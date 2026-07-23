import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { openDb } from '../../src/db.js';
import { createApp } from '../../src/app.js';
import { createGoogleAuth } from '../../src/google.js';
import { testJwks } from '../helpers/testJwks.js';
import { startMockGoogle } from '../helpers/mockGoogle.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FAKE_COOLIFY_MCP = join(__dirname, '../helpers/fakeCoolifyMcp.js');

const PUBLIC_URL = 'http://localhost:3000';
const MCP_RESOURCE_URL = `${PUBLIC_URL}/mcp`;

function pkcePair() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

function makeRedirectWalker(ownOrigin) {
  const isOwnAppPath = (location) => location.startsWith('/') || location.startsWith(ownOrigin);
  const toRequestable = (location) => (location.startsWith('/') ? location : new URL(location).pathname + new URL(location).search);
  return async function walkRedirects(agent, startLocation, maxHops = 15) {
    let location = startLocation;
    for (let i = 0; i < maxHops; i += 1) {
      if (!isOwnAppPath(location)) return { res: null, location };
      const res = await agent.get(toRequestable(location));
      if (res.status >= 300 && res.status < 400 && res.headers.location) {
        location = res.headers.location;
        continue;
      }
      return { res, location };
    }
    throw new Error(`Too many redirects, stuck at ${location}`);
  };
}

/**
 * This is the capstone test: it drives the *entire* system exactly the
 * way a real deployment would be used, with only two things swapped for
 * determinism/hermeticity — Google's endpoints point at a local mock
 * instead of accounts.google.com, and the "coolify-mcp" child process is a
 * small fixture instead of downloading the real npm package. Everything
 * else (oidc-provider, the SQLite adapter, the interaction/consent flow,
 * JWT issuance and verification, the per-session child-process MCP proxy)
 * is the real production code path.
 */
describe('Full stack: Dynamic Client Registration through a real MCP tool call', () => {
  let db;
  let mockGoogle;
  let httpServer;
  let walkRedirects;
  let client;
  let realListenUrl; // the *actual* socket address — MCP_RESOURCE_URL stays
  // the logical `aud`/issuer value baked into config and tokens, same as
  // in real deployments where a public hostname and the literal listening
  // address aren't the same string.

  beforeAll(async () => {
    mockGoogle = await startMockGoogle();
    db = openDb(':memory:');

    const env = {
      publicUrl: PUBLIC_URL,
      mcpResourceUrl: MCP_RESOURCE_URL,
      cookieSecret: 'test-cookie-secret-test-cookie-secret',
      credentialEncryptionKey: 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=',
      allowedGoogleEmails: [],
    };

    const googleAuth = createGoogleAuth({
      clientId: 'test-google-client-id',
      clientSecret: 'test-google-client-secret',
      redirectUri: `${PUBLIC_URL}/callback/google`,
      discoveryUrl: mockGoogle.discoveryUrl,
    });

    const { app } = createApp({
      env,
      db,
      jwks: await testJwks(),
      googleAuth,
      spawnOptions: { command: 'node', args: [FAKE_COOLIFY_MCP] },
    });

    httpServer = app.listen(0);
    const { port } = httpServer.address();
    realListenUrl = `http://127.0.0.1:${port}`;
    walkRedirects = makeRedirectWalker(realListenUrl);

    const discovery = await request(httpServer).get('/.well-known/openid-configuration');
    const registrationPath = new URL(discovery.body.registration_endpoint).pathname;
    const reg = await request(httpServer)
      .post(registrationPath)
      .send({
        client_name: 'Claude',
        redirect_uris: ['https://claude.example/api/mcp/auth_callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      })
      .set('Content-Type', 'application/json');
    client = reg.body;
  });

  afterAll(async () => {
    await mockGoogle.close();
    await new Promise((resolve) => httpServer.close(resolve));
  });

  it('discovers the MCP resource metadata and points at this issuer', async () => {
    const res = await request(httpServer).get('/.well-known/oauth-protected-resource');
    expect(res.status).toBe(200);
    expect(res.body.resource).toBe(MCP_RESOURCE_URL);
    expect(res.body.authorization_servers).toEqual([PUBLIC_URL]);
  });

  it('an unauthenticated /mcp request gets a 401 pointing at that metadata', async () => {
    const res = await request(httpServer)
      .post('/mcp')
      .set('Content-Type', 'application/json')
      .set('Accept', 'application/json, text/event-stream')
      .send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'x', version: '1' } } });
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toContain(`resource_metadata="${PUBLIC_URL}/.well-known/oauth-protected-resource"`);
  });

  it('goes from Google sign-in through Coolify setup and consent to a working MCP session', async () => {
    const agent = request.agent(httpServer);
    const { verifier, challenge } = pkcePair();
    mockGoogle.setNextIdTokenClaims({ sub: 'full-stack-google-sub', email: 'full-stack@example.com', name: 'Full Stack', email_verified: true });

    // 1. Kick off /authorize.
    const authorizeQuery = new URLSearchParams({
      client_id: client.client_id,
      redirect_uri: client.redirect_uris[0],
      response_type: 'code',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      resource: MCP_RESOURCE_URL,
      scope: 'coolify',
      state: 'xyz',
    });
    const authorizeRes = await agent.get(`/auth?${authorizeQuery.toString()}`);
    expect(authorizeRes.status).toBe(303);

    // 2. -> Google.
    const loginRedirect = await agent.get(authorizeRes.headers.location);
    expect(loginRedirect.headers.location.startsWith(mockGoogle.origin)).toBe(true);
    const googleState = new URL(loginRedirect.headers.location).searchParams.get('state');

    // 3. Google -> us. First-time user -> Coolify setup form.
    const callbackRes = await agent.get(`/callback/google?code=valid-code&state=${encodeURIComponent(googleState)}`);
    expect(callbackRes.status).toBe(200);
    const setupActionUrl = callbackRes.text.match(/action="([^"]+)"/)[1];

    // 4. Submit Coolify credentials.
    const setupRes = await agent.post(setupActionUrl).type('form').send({
      baseUrl: 'https://full-stack-coolify.example.com',
      accessToken: 'full-stack-coolify-token',
    });
    expect(setupRes.status).toBe(303);

    // 5. -> consent page -> approve.
    const { res: consentPage } = await walkRedirects(agent, setupRes.headers.location);
    expect(consentPage.text).toContain('Authorize access');
    const confirmActionUrl = consentPage.text.match(/action="([^"]+)"/)[1];
    const confirmRes = await agent.post(confirmActionUrl).type('form').send({});

    // 6. -> back to the client's redirect_uri with a code.
    const { location } = await walkRedirects(agent, confirmRes.headers.location);
    const code = new URL(location).searchParams.get('code');
    expect(code).toBeTruthy();

    // 7. Exchange for tokens (a real, JWT-format, resource-bound access token).
    const discovery = await request(httpServer).get('/.well-known/openid-configuration');
    const tokenPath = new URL(discovery.body.token_endpoint).pathname;
    const tokenRes = await request(httpServer)
      .post(tokenPath)
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: client.redirect_uris[0],
        client_id: client.client_id,
        code_verifier: verifier,
        resource: MCP_RESOURCE_URL,
      });
    expect(tokenRes.status).toBe(200);
    const { access_token: accessToken } = tokenRes.body;
    expect(accessToken).toBeTruthy();

    // 8. THE POINT: use that real, freshly-issued token to open an actual
    // MCP session — real bearer verification against our real JWKS, real
    // per-session child process spawn, real tool call. Connect to the
    // test server's *actual* socket address; the token's `aud` is still
    // the logical MCP_RESOURCE_URL, exactly as it would be in production
    // behind a reverse proxy where the public hostname and the literal
    // listen address differ too.
    const mcpTransport = new StreamableHTTPClientTransport(new URL(`${realListenUrl}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${accessToken}` } },
    });
    const mcpClient = new Client({ name: 'claude-e2e-test', version: '0.0.0' });
    await mcpClient.connect(mcpTransport);

    const tools = await mcpClient.listTools();
    expect(tools.tools.map((t) => t.name)).toContain('whoami');

    const result = await mcpClient.callTool({ name: 'whoami', arguments: {} });
    const reported = JSON.parse(result.content[0].text);
    expect(reported.baseUrl).toBe('https://full-stack-coolify.example.com');
    expect(reported.accessToken).toBe('full-stack-coolify-token');

    await mcpClient.close();
  });
});
