// The MCP "Resource Server" half of this project: verifies bearer tokens
// this same process issued (via oidc-provider), then proxies the actual
// tool traffic to a per-session `@masonator/coolify-mcp` child process
// running with *that session's* Coolify credentials.
//
// Deliberately does not reimplement any Coolify tool logic — it spawns the
// real published package over stdio (exactly like a local Claude Desktop
// config would) and forwards MCP requests to it, the same pattern
// supergateway/mcp-proxy use, just parameterized per authenticated user
// instead of fixed at process startup. That parameterization is the whole
// reason this isn't just "supergateway with a login page": a static
// stdio-wrapping bridge can only ever hold one set of credentials for its
// entire lifetime, which is incompatible with "anyone can bring their own
// Coolify instance" to one shared deployment.

import { jwtVerify } from 'jose';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport, getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

const PROXY_SERVER_INFO = { name: 'coolify-mcp-oauth', version: '0.1.0' };

export function buildWwwAuthenticateHeader(protectedResourceMetadataUrl) {
  return [
    'Bearer error="unauthorized"',
    'error_description="Authorization needed"',
    `resource_metadata="${protectedResourceMetadataUrl}"`,
  ].join(', ');
}

/**
 * @param {object} opts
 * @param {string} opts.issuer - expected `iss` claim (our own public URL)
 * @param {string} opts.audience - expected `aud` claim (our /mcp resource URL)
 * @param {import('jose').JWTVerifyGetKey} opts.jwks - a jose remote or local JWKSet
 */
export function createBearerVerifier({ issuer, audience, jwks }) {
  return async function verifyBearerToken(authorizationHeader) {
    const match = typeof authorizationHeader === 'string' && authorizationHeader.match(/^Bearer (.+)$/);
    if (!match) {
      throw Object.assign(new Error('No bearer token provided.'), { code: 'missing_token' });
    }
    try {
      const { payload } = await jwtVerify(match[1], jwks, { issuer, audience });
      return payload;
    } catch (cause) {
      throw Object.assign(new Error('Invalid or expired bearer token.'), { code: 'invalid_token', cause });
    }
  };
}

/**
 * Native overrides for upstream coolify-mcp tools whose HTTP verbs are
 * stale against current Coolify API (deploy / restart / stop / start
 * endpoints moved to POST). We already hold the session's Coolify base
 * URL + API token, so implement them directly instead of waiting on an
 * upstream release.
 */
async function callCoolify(baseUrl, accessToken, method, path) {
  const url = `${String(baseUrl).replace(/\/+$/, '')}${path}`;
  let res;
  try {
    res = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
      },
    });
  } catch (cause) {
    throw new Error(`Coolify API ${method} ${path} unreachable: ${cause.message}`);
  }
  const text = await res.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!res.ok) {
    throw new Error(`Coolify API ${method} ${path} -> ${res.status}: ${String(text).slice(0, 300)}`);
  }
  return body;
}

function pluralize(resource) {
  if (resource === 'application') return 'applications';
  if (resource === 'database') return 'databases';
  return `${resource}s`;
}

async function nativeDeploy(baseUrl, accessToken, args) {
  // Coolify's /api/v1/deploy takes `uuid` (resource uuid); `tag` only
  // matches user-assigned custom tags, so uuid is the correct param for
  // tag_or_uuid semantics.
  const tagOrUuid = args?.tag_or_uuid;
  if (!tagOrUuid) throw new Error('deploy: tag_or_uuid is required');
  return callCoolify(baseUrl, accessToken, 'POST', `/api/v1/deploy?uuid=${encodeURIComponent(tagOrUuid)}`);
}

async function nativeControl(baseUrl, accessToken, args) {
  const { resource, uuid, action } = args || {};
  if (!resource || !uuid || !action) {
    throw new Error('control: resource (application|service|database), uuid and action are required');
  }
  return callCoolify(baseUrl, accessToken, 'POST', `/api/v1/${pluralize(resource)}/${encodeURIComponent(uuid)}/${encodeURIComponent(action)}`);
}

const NATIVE_TOOLS = {
  deploy: nativeDeploy,
  control: nativeControl,
};

/**
 * Spawns one `coolify-mcp` child process for a single authenticated
 * session and wires up an MCP Server that forwards requests to it.
 *
 * @param {object} opts
 * @param {string} opts.baseUrl - this session's user's Coolify base URL
 * @param {string} opts.accessToken - this session's user's Coolify API token
 * @param {string} [opts.command] - override for tests (defaults to the real package via npx)
 * @param {string[]} [opts.args]
 */
export async function createCoolifySessionProxy({
  baseUrl,
  accessToken,
  command = 'npx',
  args = ['-y', '@masonator/coolify-mcp@latest'],
}) {
  const clientTransport = new StdioClientTransport({
    command,
    args,
    env: {
      ...getDefaultEnvironment(),
      COOLIFY_ACCESS_TOKEN: accessToken,
      COOLIFY_BASE_URL: baseUrl,
    },
  });

  const client = new Client({ name: 'coolify-mcp-oauth-proxy', version: '0.1.0' });
  await client.connect(clientTransport);

  const capabilities = client.getServerCapabilities() ?? {};
  const server = new Server(PROXY_SERVER_INFO, { capabilities: { tools: capabilities.tools ?? {} } });

  // Tools are the whole point and always forwarded.
  server.setRequestHandler(ListToolsRequestSchema, (request) => client.listTools(request.params));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const native = NATIVE_TOOLS[name];
    if (native) {
      try {
        const result = await native(baseUrl, accessToken, args);
        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return { isError: true, content: [{ type: 'text', text: `Error: ${err.message}` }] };
      }
    }
    return client.callTool(request.params);
  });

  // Forwarded too, but only if the underlying coolify-mcp version actually
  // supports them — otherwise we'd advertise a capability we can't serve.
  if (capabilities.resources) {
    server.registerCapabilities({ resources: capabilities.resources });
    server.setRequestHandler(ListResourcesRequestSchema, (request) => client.listResources(request.params));
    server.setRequestHandler(ReadResourceRequestSchema, (request) => client.readResource(request.params));
  }
  if (capabilities.prompts) {
    server.registerCapabilities({ prompts: capabilities.prompts });
    server.setRequestHandler(ListPromptsRequestSchema, (request) => client.listPrompts(request.params));
    server.setRequestHandler(GetPromptRequestSchema, (request) => client.getPrompt(request.params));
  }

  return {
    client,
    server,
    async close() {
      await Promise.allSettled([client.close(), server.close()]);
    },
  };
}
