import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { openDb } from '../../src/db.js';
import { createOidcProvider } from '../../src/oidcProvider.js';
import { testJwks } from '../helpers/testJwks.js';

const PUBLIC_URL = 'http://localhost:3000';
const MCP_RESOURCE_URL = `${PUBLIC_URL}/mcp`;

describe('oidc-provider wiring: discovery + JWKS', () => {
  let provider;

  beforeAll(async () => {
    const db = openDb(':memory:');
    provider = createOidcProvider({
      publicUrl: PUBLIC_URL,
      mcpResourceUrl: MCP_RESOURCE_URL,
      db,
      jwks: await testJwks(),
      cookieSecret: 'test-cookie-secret-test-cookie-secret',
    });
  });

  it('serves OAuth authorization server metadata at the issuer root', async () => {
    const res = await request(provider.callback()).get('/.well-known/oauth-authorization-server');
    expect(res.status).toBe(200);
    expect(res.body.issuer).toBe(PUBLIC_URL);
    expect(res.body.authorization_endpoint).toBeTruthy();
    expect(res.body.token_endpoint).toBeTruthy();
    expect(res.body.registration_endpoint).toBeTruthy();
    expect(res.body.jwks_uri).toBeTruthy();
    expect(res.body.code_challenge_methods_supported).toContain('S256');
  });

  it('also serves OIDC discovery metadata (some clients only check this one)', async () => {
    const res = await request(provider.callback()).get('/.well-known/openid-configuration');
    expect(res.status).toBe(200);
    expect(res.body.issuer).toBe(PUBLIC_URL);
  });

  it('publishes a JWKS with the public key only — no private key material', async () => {
    const discovery = await request(provider.callback()).get('/.well-known/openid-configuration');
    // Use only the path: oidc-provider builds absolute endpoint URLs from
    // the *actual* request origin (respecting X-Forwarded-* when
    // provider.proxy = true), which in this test is supertest's own
    // ephemeral local server address, not PUBLIC_URL — that's fine, it's
    // exactly how it'll pick up the real hostname in production behind
    // Coolify's proxy.
    const jwksPath = new URL(discovery.body.jwks_uri).pathname;

    const res = await request(provider.callback()).get(jwksPath);
    expect(res.status).toBe(200);
    expect(res.body.keys).toHaveLength(1);
    const [key] = res.body.keys;
    expect(key.kty).toBe('RSA');
    expect(key.n).toBeTruthy(); // public modulus present
    expect(key.d).toBeUndefined(); // private exponent must NOT be exposed
    expect(key.p).toBeUndefined();
    expect(key.q).toBeUndefined();
  });
});
