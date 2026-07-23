import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { openDb } from '../../src/db.js';
import { upsertUserFromGoogle, saveCoolifyCredentials } from '../../src/users.js';
import { createMcpRouter } from '../../src/mcpRoute.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FAKE_COOLIFY_MCP = join(__dirname, '../helpers/fakeCoolifyMcp.js');

const MCP_RESOURCE_URL = 'http://localhost:3000/mcp';
const ISSUER = 'http://localhost:3000';
const ENCRYPTION_KEY = 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=';

// Stub token verifier: tokens of the form "token-for:<userId>" are "valid"
// for that user, everything else is rejected. Real JWT verification is
// already covered by mcpProxy.test.js — this test is about the HTTP route
// and session wiring, not JWT mechanics.
function stubVerifier(prefix = 'token-for:') {
  return async (authorizationHeader) => {
    const token = authorizationHeader?.match(/^Bearer (.+)$/)?.[1];
    if (!token || !token.startsWith(prefix)) {
      throw Object.assign(new Error('invalid'), { code: 'invalid_token' });
    }
    return { sub: token.slice(prefix.length) };
  };
}

describe('createMcpRouter (the /mcp HTTP route + session wiring)', () => {
  let db;
  let httpServer;
  let baseUrl;
  let alice;
  let bob;
  const clients = [];

  beforeAll(async () => {
    db = openDb(':memory:');
    alice = upsertUserFromGoogle(db, { googleSub: 'g-alice', email: 'alice@example.com', name: 'Alice' });
    bob = upsertUserFromGoogle(db, { googleSub: 'g-bob', email: 'bob@example.com', name: 'Bob' });
    saveCoolifyCredentials(db, alice.id, { baseUrl: 'https://alice-coolify.example.com', accessToken: 'alice-token' }, ENCRYPTION_KEY);
    // bob deliberately has no Coolify credentials saved yet.

    const app = express();
    app.use(createMcpRouter({
      verifyBearerToken: stubVerifier(),
      db,
      encryptionKey: ENCRYPTION_KEY,
      mcpResourceUrl: MCP_RESOURCE_URL,
      issuer: ISSUER,
      spawnOptions: { command: 'node', args: [FAKE_COOLIFY_MCP] },
    }));

    httpServer = app.listen(0);
    const { port } = httpServer.address();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterEach(async () => {
    await Promise.all(clients.splice(0).map((c) => c.close().catch(() => {})));
  });

  afterAll(async () => {
    await new Promise((resolve) => httpServer.close(resolve));
  });

  async function connectAs(userId) {
    const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer token-for:${userId}` } },
    });
    const client = new Client({ name: 'test-client', version: '0.0.0' });
    await client.connect(transport);
    clients.push(client);
    return client;
  }

  it('rejects requests with no bearer token, with a resource_metadata challenge', async () => {
    const res = await request(httpServer)
      .post('/mcp')
      .set('Content-Type', 'application/json')
      .set('Accept', 'application/json, text/event-stream')
      .send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'x', version: '1' } } });

    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toContain('resource_metadata=');
  });

  it('rejects an invalid bearer token', async () => {
    const res = await request(httpServer)
      .post('/mcp')
      .set('Content-Type', 'application/json')
      .set('Accept', 'application/json, text/event-stream')
      .set('Authorization', 'Bearer garbage')
      .send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'x', version: '1' } } });

    expect(res.status).toBe(401);
  });

  it('rejects a valid token for a user who has not configured Coolify credentials yet', async () => {
    const res = await request(httpServer)
      .post('/mcp')
      .set('Content-Type', 'application/json')
      .set('Accept', 'application/json, text/event-stream')
      .set('Authorization', `Bearer token-for:${bob.id}`)
      .send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'x', version: '1' } } });

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('coolify_not_configured');
  });

  it('serves the protected-resource metadata', async () => {
    const res = await request(httpServer).get('/.well-known/oauth-protected-resource');
    expect(res.status).toBe(200);
    expect(res.body.resource).toBe(MCP_RESOURCE_URL);
    expect(res.body.authorization_servers).toEqual([ISSUER]);
    expect(res.body.scopes_supported).toContain('coolify');
  });

  it('a fully authenticated client can list and call tools, reaching the real spawned child', async () => {
    const client = await connectAs(alice.id);
    const tools = await client.listTools();
    expect(tools.tools.map((t) => t.name)).toContain('whoami');

    const result = await client.callTool({ name: 'whoami', arguments: {} });
    const reported = JSON.parse(result.content[0].text);
    expect(reported.baseUrl).toBe('https://alice-coolify.example.com');
    expect(reported.accessToken).toBe('alice-token');
  });

  it('does not let a different valid token take over someone else\'s session id', async () => {
    // Give bob credentials too, now that we've proven the 403 case above.
    saveCoolifyCredentials(db, bob.id, { baseUrl: 'https://bob-coolify.example.com', accessToken: 'bob-token' }, ENCRYPTION_KEY);

    const aliceClient = await connectAs(alice.id);
    const sessionId = aliceClient.transport.sessionId;
    expect(sessionId).toBeTruthy();

    // Reuse alice's session id, but authenticate as bob.
    const res = await request(httpServer)
      .post('/mcp')
      .set('Content-Type', 'application/json')
      .set('Accept', 'application/json, text/event-stream')
      .set('Authorization', `Bearer token-for:${bob.id}`)
      .set('Mcp-Session-Id', sessionId)
      .send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });

    expect(res.status).toBe(403);
  });
});
