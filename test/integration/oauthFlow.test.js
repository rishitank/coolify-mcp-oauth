import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createHash, randomBytes } from 'node:crypto';
import { decodeJwt } from 'jose';
import { openDb } from '../../src/db.js';
import { createOidcProvider } from '../../src/oidcProvider.js';
import { createInteractionsRouter } from '../../src/interactions.js';
import { createGoogleAuth } from '../../src/google.js';
import { getCoolifyCredentials } from '../../src/users.js';
import { testJwks } from '../helpers/testJwks.js';
import { startMockGoogle } from '../helpers/mockGoogle.js';

const PUBLIC_URL = 'http://localhost:3000';
const MCP_RESOURCE_URL = `${PUBLIC_URL}/mcp`;
const COOKIE_SECRET = 'test-cookie-secret-test-cookie-secret';
const ENCRYPTION_KEY = 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=';

function pkcePair() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

/**
 * Follows a chain of same-app 3xx redirects using the given supertest
 * agent. Stops *without fetching* as soon as the next hop points off-app
 * (Google, or the OAuth client's own redirect_uri) — those aren't real
 * servers in this test, so we only want to inspect where we were being
 * sent, not actually request it. Returns whichever comes first: a
 * non-redirect response reached via on-app hops, or the first off-app
 * location encountered.
 *
 * `ownOrigin` must be the *actual* address of the listening test server
 * (see beforeAll) — oidc-provider builds absolute self-redirect URLs from
 * the real request origin, not from the configured `issuer` string.
 */
function makeRedirectWalker(ownOrigin) {
  const isOwnAppPath = (location) => location.startsWith('/') || location.startsWith(ownOrigin);
  // supertest agents bound to a live Server (see beforeAll) choke on being
  // given a full absolute URL to `.get()` ("Invalid URL" inside its own
  // cookie handling) — pass just the path+query once we've established
  // the URL is our own server anyway.
  const toRequestable = (location) => (location.startsWith('/') ? location : new URL(location).pathname + new URL(location).search);

  return async function walkRedirects(agent, startLocation, maxHops = 15) {
    let location = startLocation;
    for (let i = 0; i < maxHops; i += 1) {
      if (!isOwnAppPath(location)) {
        return { res: null, location };
      }
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

describe('End-to-end OAuth flow: DCR -> Google login -> Coolify setup -> consent -> token', () => {
  let db;
  let mockGoogle;
  let client;
  let httpServer;
  let walkRedirects;

  beforeAll(async () => {
    mockGoogle = await startMockGoogle();
    db = openDb(':memory:');

    const provider = createOidcProvider({
      publicUrl: PUBLIC_URL,
      mcpResourceUrl: MCP_RESOURCE_URL,
      db,
      jwks: await testJwks(),
      cookieSecret: COOKIE_SECRET,
    });

    const googleAuth = createGoogleAuth({
      clientId: 'test-google-client-id',
      clientSecret: 'test-google-client-secret',
      redirectUri: `${PUBLIC_URL}/callback/google`,
      discoveryUrl: mockGoogle.discoveryUrl,
    });

    const app = express();
    app.set('trust proxy', true);
    app.use(createInteractionsRouter({
      provider,
      googleAuth,
      db,
      encryptionKey: ENCRYPTION_KEY,
      cookieSecret: COOKIE_SECRET,
      allowedGoogleEmails: [],
      mcpResourceUrl: MCP_RESOURCE_URL,
    }));
    app.use(provider.callback());

    // A single persistent listening server for the whole test, so that
    // oidc-provider's self-referential absolute redirect URLs (which are
    // built from the real request origin) stay stable across every hop —
    // supertest spins up a *new* ephemeral port per call when you pass it
    // a bare app instead of a listening server.
    httpServer = app.listen(0);
    const { port } = httpServer.address();
    walkRedirects = makeRedirectWalker(`http://127.0.0.1:${port}`);

    // Register the OAuth client the way Claude/Cowork's DCR would.
    const discovery = await request(httpServer).get('/.well-known/openid-configuration');
    const registrationPath = new URL(discovery.body.registration_endpoint).pathname;
    const reg = await request(httpServer)
      .post(registrationPath)
      .send({
        client_name: 'Test MCP Client',
        redirect_uris: ['https://claude.example/api/mcp/auth_callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      })
      .set('Content-Type', 'application/json');
    expect(reg.status).toBe(201);
    client = reg.body;
  });

  afterAll(async () => {
    await mockGoogle.close();
    await new Promise((resolve) => httpServer.close(resolve));
  });

  it('completes the full loop and issues a resource-bound access token', async () => {
    const agent = request.agent(httpServer);
    const { verifier, challenge } = pkcePair();
    mockGoogle.setNextIdTokenClaims({ sub: 'e2e-google-sub', email: 'e2e@example.com', name: 'E2E User', email_verified: true });

    // 1. Kick off /authorize like an MCP client would.
    const authorizeQuery = new URLSearchParams({
      client_id: client.client_id,
      redirect_uri: client.redirect_uris[0],
      response_type: 'code',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      resource: MCP_RESOURCE_URL,
      scope: 'coolify',
      state: 'client-state-xyz',
    });
    const authorizeRes = await agent.get(`/auth?${authorizeQuery.toString()}`);
    expect(authorizeRes.status).toBe(303);
    expect(authorizeRes.headers.location).toMatch(/^\/interaction\//);

    // 2. Interaction page for a brand-new session should be a 'login'
    // prompt, which we redirect straight to (mock) Google.
    const loginRedirect = await agent.get(authorizeRes.headers.location);
    expect(loginRedirect.status).toBe(302);
    expect(loginRedirect.headers.location.startsWith(mockGoogle.origin)).toBe(true);
    const googleState = new URL(loginRedirect.headers.location).searchParams.get('state');

    // 3. Simulate Google's redirect back to us. First-time user -> Coolify
    // setup form (not finished yet).
    const callbackRes = await agent.get(`/callback/google?code=valid-code&state=${encodeURIComponent(googleState)}`);
    expect(callbackRes.status).toBe(200);
    const actionMatch = callbackRes.text.match(/action="([^"]+)"/);
    expect(actionMatch).toBeTruthy();
    const setupActionUrl = actionMatch[1];
    expect(setupActionUrl).toMatch(/^\/interaction\/.+\/coolify-setup\?t=/);

    // 4. Submit Coolify credentials.
    const setupRes = await agent
      .post(setupActionUrl)
      .type('form')
      .send({ baseUrl: 'https://coolify.example.com', accessToken: 'e2e-coolify-token' });
    expect(setupRes.status).toBe(303);

    // 5. Follow redirects until we land on the consent interaction page
    // (a fresh grant, so consent should still be required).
    const { res: consentPage } = await walkRedirects(agent, setupRes.headers.location);
    expect(consentPage).toBeTruthy();
    expect(consentPage.status).toBe(200);
    expect(consentPage.text).toContain('Authorize access');
    expect(consentPage.text).toContain('Test MCP Client');
    const confirmActionMatch = consentPage.text.match(/action="([^"]+)"/);
    const confirmActionUrl = confirmActionMatch[1];
    expect(confirmActionUrl).toMatch(/\/confirm$/);

    // 6. Approve consent, then follow the redirect chain out to the
    // client's own redirect_uri, which carries the authorization code.
    const confirmRes = await agent.post(confirmActionUrl).type('form').send({});
    expect(confirmRes.status).toBe(303);

    const { location } = await walkRedirects(agent, confirmRes.headers.location);
    expect(location.startsWith(client.redirect_uris[0])).toBe(true);
    const finalUrl = new URL(location);
    const code = finalUrl.searchParams.get('code');
    expect(code).toBeTruthy();
    expect(finalUrl.searchParams.get('state')).toBe('client-state-xyz');

    // 7. Exchange the code for tokens, like the MCP client would.
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
    expect(tokenRes.body.access_token).toBeTruthy();
    expect(tokenRes.body.refresh_token).toBeTruthy();

    const claims = decodeJwt(tokenRes.body.access_token);
    expect(claims.aud).toBe(MCP_RESOURCE_URL);
    expect(claims.iss).toBe(PUBLIC_URL);

    // 8. And the whole point: that access token's `sub` maps to a local
    // user who now has the Coolify credentials we entered mid-flow.
    const creds = getCoolifyCredentials(db, claims.sub, ENCRYPTION_KEY);
    expect(creds).toBeTruthy();
    expect(creds.baseUrl).toBe('https://coolify.example.com');
    expect(creds.accessToken).toBe('e2e-coolify-token');
  });
});
