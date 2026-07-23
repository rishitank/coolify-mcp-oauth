import { describe, it, expect, afterEach } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { SignJWT, generateKeyPair, exportJWK, createLocalJWKSet } from 'jose';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createCoolifySessionProxy, createBearerVerifier } from '../../src/mcpProxy.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FAKE_COOLIFY_MCP = join(__dirname, '../helpers/fakeCoolifyMcp.js');

function fakeCoolifyArgs() {
  return { command: 'node', args: [FAKE_COOLIFY_MCP] };
}

describe('createCoolifySessionProxy (spawns a coolify-mcp child per session)', () => {
  const proxies = [];

  afterEach(async () => {
    await Promise.all(proxies.splice(0).map((p) => p.close()));
  });

  it('lists tools from the spawned child', async () => {
    const proxy = await createCoolifySessionProxy({
      baseUrl: 'https://coolify.example.com',
      accessToken: 'token-a',
      ...fakeCoolifyArgs(),
    });
    proxies.push(proxy);

    const result = await proxy.client.listTools();
    expect(result.tools.map((t) => t.name)).toContain('whoami');
  });

  it("passes this session's credentials to the spawned child via env vars", async () => {
    const proxy = await createCoolifySessionProxy({
      baseUrl: 'https://alice-coolify.example.com',
      accessToken: 'alice-token',
      ...fakeCoolifyArgs(),
    });
    proxies.push(proxy);

    const result = await proxy.client.callTool({ name: 'whoami', arguments: {} });
    const reported = JSON.parse(result.content[0].text);
    expect(reported.baseUrl).toBe('https://alice-coolify.example.com');
    expect(reported.accessToken).toBe('alice-token');
  });

  it('isolates credentials between concurrent sessions', async () => {
    const [alice, bob] = await Promise.all([
      createCoolifySessionProxy({ baseUrl: 'https://alice.example.com', accessToken: 'alice-token', ...fakeCoolifyArgs() }),
      createCoolifySessionProxy({ baseUrl: 'https://bob.example.com', accessToken: 'bob-token', ...fakeCoolifyArgs() }),
    ]);
    proxies.push(alice, bob);

    const [aliceResult, bobResult] = await Promise.all([
      alice.client.callTool({ name: 'whoami', arguments: {} }),
      bob.client.callTool({ name: 'whoami', arguments: {} }),
    ]);

    expect(JSON.parse(aliceResult.content[0].text).accessToken).toBe('alice-token');
    expect(JSON.parse(bobResult.content[0].text).accessToken).toBe('bob-token');
  });

  it('the external server forwards tools/list and tools/call to the internal client (proxying, not reimplementation)', async () => {
    const proxy = await createCoolifySessionProxy({
      baseUrl: 'https://coolify.example.com',
      accessToken: 'token-a',
      ...fakeCoolifyArgs(),
    });
    proxies.push(proxy);

    // Drive proxy.server the same way a real MCP client would talk to it
    // over the wire — a second, throwaway Client connected via an
    // in-memory transport pair — rather than reaching into its internals.
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    const testClient = new Client({ name: 'test-client', version: '0.0.0' });
    await Promise.all([
      testClient.connect(clientSide),
      proxy.server.connect(serverSide),
    ]);

    const list = await testClient.listTools();
    expect(list.tools.map((t) => t.name)).toContain('whoami');

    const called = await testClient.callTool({ name: 'whoami', arguments: {} });
    expect(JSON.parse(called.content[0].text).accessToken).toBe('token-a');

    await testClient.close();
  });

  it('close() terminates the child process cleanly', async () => {
    const proxy = await createCoolifySessionProxy({
      baseUrl: 'https://coolify.example.com',
      accessToken: 'token-a',
      ...fakeCoolifyArgs(),
    });
    await expect(proxy.close()).resolves.not.toThrow();
  });
});

describe('createBearerVerifier', () => {
  const ISSUER = 'https://mcp.example.com';
  const AUDIENCE = 'https://mcp.example.com/mcp';

  async function setup() {
    const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
    const jwk = await exportJWK(publicKey);
    jwk.kid = 'test';
    jwk.alg = 'RS256';
    const jwks = createLocalJWKSet({ keys: [jwk] });
    const verify = createBearerVerifier({ issuer: ISSUER, audience: AUDIENCE, jwks });

    async function issueToken(overrides = {}) {
      let jwt = new SignJWT({ ...overrides.claims })
        .setProtectedHeader({ alg: 'RS256', kid: 'test' })
        .setSubject(overrides.sub ?? 'user-123')
        .setIssuer(overrides.issuer ?? ISSUER)
        .setAudience(overrides.audience ?? AUDIENCE)
        .setIssuedAt();
      jwt = overrides.expired ? jwt.setExpirationTime(Math.floor(Date.now() / 1000) - 60) : jwt.setExpirationTime('1h');
      return jwt.sign(privateKey);
    }

    return { verify, issueToken };
  }

  it('accepts a validly signed, correctly scoped token', async () => {
    const { verify, issueToken } = await setup();
    const token = await issueToken({ sub: 'user-123' });
    const payload = await verify(`Bearer ${token}`);
    expect(payload.sub).toBe('user-123');
  });

  it('rejects a missing Authorization header', async () => {
    const { verify } = await setup();
    await expect(verify(undefined)).rejects.toThrow();
  });

  it('rejects a non-Bearer Authorization header', async () => {
    const { verify } = await setup();
    await expect(verify('Basic dXNlcjpwYXNz')).rejects.toThrow();
  });

  it('rejects a token with the wrong audience', async () => {
    const { verify, issueToken } = await setup();
    const token = await issueToken({ audience: 'https://someone-elses-mcp.example.com/mcp' });
    await expect(verify(`Bearer ${token}`)).rejects.toThrow();
  });

  it('rejects a token from the wrong issuer', async () => {
    const { verify, issueToken } = await setup();
    const token = await issueToken({ issuer: 'https://not-us.example.com' });
    await expect(verify(`Bearer ${token}`)).rejects.toThrow();
  });

  it('rejects an expired token', async () => {
    const { verify, issueToken } = await setup();
    const token = await issueToken({ expired: true });
    await expect(verify(`Bearer ${token}`)).rejects.toThrow();
  });

  it('rejects a garbage token', async () => {
    const { verify } = await setup();
    await expect(verify('Bearer not-a-real-jwt')).rejects.toThrow();
  });
});
