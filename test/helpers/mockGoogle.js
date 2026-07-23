// A local stand-in for accounts.google.com's OIDC endpoints, so tests can
// exercise the real HTTP + JWT-verification code paths in src/google.js
// without any network access to Google (the sandbox this was built in
// can't reach external hosts anyway, and hitting the real Google in a
// unit test would be flaky/undesirable regardless).

import { createServer } from 'node:http';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';

export async function startMockGoogle() {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = 'mock-google-key';
  publicJwk.alg = 'RS256';
  publicJwk.use = 'sig';

  let issuedTokenOverrides = null; // test hook: force the next id_token's claims
  const requestCounts = { discovery: 0, jwks: 0, token: 0 };

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');

    if (req.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
      requestCounts.discovery += 1;
      const origin = `http://127.0.0.1:${server.address().port}`;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        issuer: origin,
        authorization_endpoint: `${origin}/o/oauth2/v2/auth`,
        token_endpoint: `${origin}/token`,
        jwks_uri: `${origin}/jwks`,
      }));
      return;
    }

    if (req.method === 'GET' && url.pathname === '/jwks') {
      requestCounts.jwks += 1;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys: [publicJwk] }));
      return;
    }

    if (req.method === 'POST' && url.pathname === '/token') {
      requestCounts.token += 1;
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = new URLSearchParams(Buffer.concat(chunks).toString('utf8'));

      if (!body.get('code') || body.get('code') === 'invalid-code') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_grant' }));
        return;
      }

      const origin = `http://127.0.0.1:${server.address().port}`;
      const claims = {
        email: 'rishi@example.com',
        email_verified: true,
        name: 'Rishi Tank',
        ...issuedTokenOverrides,
      };
      const sub = claims.sub ?? 'google-user-123';
      delete claims.sub;

      let jwt = new SignJWT(claims)
        .setProtectedHeader({ alg: 'RS256', kid: 'mock-google-key' })
        .setSubject(sub)
        .setIssuer(origin)
        .setAudience(body.get('client_id'))
        .setIssuedAt();

      jwt = issuedTokenOverrides?.expired
        ? jwt.setExpirationTime(Math.floor(Date.now() / 1000) - 60)
        : jwt.setExpirationTime('5m');

      const idToken = await jwt.sign(privateKey);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        access_token: 'mock-google-access-token',
        id_token: idToken,
        token_type: 'Bearer',
        expires_in: 3600,
      }));
      return;
    }

    res.writeHead(404);
    res.end('not found');
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const origin = `http://127.0.0.1:${port}`;

  return {
    origin,
    discoveryUrl: `${origin}/.well-known/openid-configuration`,
    requestCounts,
    setNextIdTokenClaims(overrides) {
      issuedTokenOverrides = overrides;
    },
    async close() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
