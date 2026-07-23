import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { openDb } from '../../src/db.js';
import { createOidcProvider } from '../../src/oidcProvider.js';
import { testJwks } from '../helpers/testJwks.js';

const PUBLIC_URL = 'http://localhost:3000';

describe('Dynamic Client Registration (RFC 7591)', () => {
  let provider;
  let callback;
  let registrationPath;

  beforeAll(async () => {
    const db = openDb(':memory:');
    provider = createOidcProvider({
      publicUrl: PUBLIC_URL,
      mcpResourceUrl: `${PUBLIC_URL}/mcp`,
      db,
      jwks: await testJwks(),
      cookieSecret: 'test-cookie-secret-test-cookie-secret',
    });
    callback = provider.callback();
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
});
