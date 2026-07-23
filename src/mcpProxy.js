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
  server.setRequestHandler(CallToolRequestSchema, (request) => client.callTool(request.params));

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
