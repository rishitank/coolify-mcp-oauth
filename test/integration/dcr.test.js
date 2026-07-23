import { describe, it, expect, beforeAll } from 'vitest';
import express from 'express';
import request from 'supertest';
import { openDb } from '../../src/db.js';
import { createOidcProvider } from '../../src/oidcProvider.js';
import { createMcpRouter } from '../../src/mcpRoute.js';
import { testJwks } from '../helpers/testJwks.js';

const PUBLIC_URL = 'http://localhost:3000';
const MCP_RESOURCE_URL = `${PUBLIC_URL}/mcp`;

describe('Dynamic Client Registration (RFC 7591)', () => {
  let provider;
  let callback;
  let registrationPath;

  beforeAll(async () => {
    const db = openDb(':memory:');
    provider = createOidcProvider({
      publicUrl: PUBLIC_URL,
      mcpResourceUrl: MCP_RESOURCE_URL,
      db,
      jwks: await testJwks(),
      cookieSecret: 'test-cookie-secret-test-cookie-secret',
    });

    // Mount the real MCP router in front of the provider, the same order
    // app.js uses, so /.well-known/oauth-protected-resource (RFC 9728,
    // defined in mcpRoute.js — not part of oidc-provider itself) is
    // reachable. verifyBearerToken is never exercised by these tests (no
    // request here ever hits /mcp), so a stub is fine.
    const app = express();
    app.use(createMcpRouter({
      verifyBearerToken: async () => { throw new Error('not used in this test'); },
      db,
      encryptionKey: 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=',
      mcpResourceUrl: MCP_RESOURCE_URL,
      issuer: PUBLIC_URL,
    }));
    app.use(provider.callback());

    callback = app;
    const discovery = await request(callback).get('/.well-known/openid-configuration');
    registrationPath = new URL(discovery.body.registration_endpoint).pathname;
  });

  it('registers a new public client (like Claude/Cowork would) with no auth required', async () => {
    const res = await request(callback)
      .post(registrationPath)
      .send({
        client_name: 'Claude',
        redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      })
      .set('Content-Type', 'application/json');

    expect(res.status).toBe(201);
    expect(res.body.client_id).toBeTruthy();
    expect(res.body.redirect_uris).toEqual(['https://claude.ai/api/mcp/auth_callback']);
    expect(res.body.token_endpoint_auth_method).toBe('none');
  });

  it('rejects registration missing required fields', async () => {
    const res = await request(callback)
      .post(registrationPath)
      .send({})
      .set('Content-Type', 'application/json');

    expect(res.status).toBe(400);
  });

  it('each registration gets a distinct client_id', async () => {
    const body = {
      client_name: 'Some MCP client',
      redirect_uris: ['https://example.com/callback'],
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    };
    const a = await request(callback).post(registrationPath).send(body).set('Content-Type', 'application/json');
    const b = await request(callback).post(registrationPath).send(body).set('Content-Type', 'application/json');
    expect(a.body.client_id).not.toBe(b.body.client_id);
  });

  // Regression test for a real production failure: Claude/Cowork's connector
  // setup reads `scopes_supported` off /.well-known/oauth-protected-resource
  // (which advertises ["coolify"], via resourceIndicators.getResourceServerInfo
  // in oidcProvider.js) and dutifully echoes that scope back in its DCR
  // request. oidc-provider's registration_endpoint validates the requested
  // `scope` against the Authorization Server's own top-level `scopes`
  // config — a *separate* list from resource-indicator scopes — so without
  // 'coolify' also present there, every spec-compliant client that follows
  // our own resource metadata gets rejected with invalid_client_metadata.
  // This isn't Claude-specific: any RFC 7591 + RFC 9728 compliant client
  // would hit the same wall, since it's just doing what our metadata says.
  it('accepts registration requesting exactly the scope(s) our own protected-resource metadata advertises', async () => {
    const resourceMeta = await request(callback).get('/.well-known/oauth-protected-resource');
    expect(resourceMeta.body.scopes_supported.length).toBeGreaterThan(0);

    const res = await request(callback)
      .post(registrationPath)
      .send({
        client_name: 'Claude',
        redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
        scope: resourceMeta.body.scopes_supported.join(' '),
      })
      .set('Content-Type', 'application/json');

    expect(res.status).toBe(201);
    expect(res.body.scope.split(' ')).toEqual(expect.arrayContaining(resourceMeta.body.scopes_supported));
  });
});
