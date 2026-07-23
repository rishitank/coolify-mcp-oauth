// Wires the three pieces into one Express app:
//   1. oidc-provider (the OAuth/OIDC Authorization Server)
//   2. interactions.js (Google federation + Coolify credential onboarding —
//      the custom logic oidc-provider delegates *to*)
//   3. mcpRoute.js (the MCP Resource Server — verifies tokens *issued by*
//      #1, proxies to a per-user coolify-mcp child)
//
// Order matters: interactions and MCP routes are matched first (specific
// paths only), and only requests that don't match either fall through to
// provider.callback() — which owns everything else (/auth, /token, /reg,
// /jwks, /.well-known/openid-configuration, ...).

import express from 'express';
import { createLocalJWKSet } from 'jose';
import { createOidcProvider } from './oidcProvider.js';
import { createInteractionsRouter } from './interactions.js';
import { createMcpRouter } from './mcpRoute.js';
import { createGoogleAuth } from './google.js';
import { createBearerVerifier } from './mcpProxy.js';

function toPublicJwk({ d, p, q, dp, dq, qi, ...publicOnly }) {
  return publicOnly;
}

export function createApp({ env, db, jwks, spawnOptions = {}, googleAuth } = {}) {
  const provider = createOidcProvider({
    publicUrl: env.publicUrl,
    mcpResourceUrl: env.mcpResourceUrl,
    db,
    jwks,
    cookieSecret: env.cookieSecret,
  });

  const google = googleAuth ?? createGoogleAuth({
    clientId: env.googleClientId,
    clientSecret: env.googleClientSecret,
    redirectUri: `${env.publicUrl}/callback/google`,
  });

  // Verify our own issued access tokens the way an external resource
  // server would (via the public JWKS), just without the extra network
  // hop, since we minted the keys in this same process.
  const publicJwks = { keys: jwks.keys.map(toPublicJwk) };
  const verifyBearerToken = createBearerVerifier({
    issuer: env.publicUrl,
    audience: env.mcpResourceUrl,
    jwks: createLocalJWKSet(publicJwks),
  });

  const app = express();
  app.set('trust proxy', true);
  app.disable('x-powered-by');

  // Minimal access log — mounted before everything else so it captures
  // literally every inbound request, including ones oidc-provider itself
  // rejects before its own error events would fire (bad routing, method
  // not allowed, etc). Skips /healthz to avoid drowning real traffic in
  // uptime-check noise. This is what makes a remote caller's "it failed"
  // report debuggable after the fact instead of needing to catch it live.
  app.use((req, res, next) => {
    if (req.path === '/healthz') return next();
    const start = Date.now();
    res.on('finish', () => {
      console.log('[http]', JSON.stringify({
        method: req.method,
        path: req.originalUrl,
        status: res.statusCode,
        ms: Date.now() - start,
        origin: req.get('origin') || null,
        ua: req.get('user-agent') || null,
        len: req.get('content-length') || null,
      }));
    });
    next();
  });

  app.get('/healthz', (req, res) => res.status(200).send('ok'));

  app.use(createInteractionsRouter({
    provider,
    googleAuth: google,
    db,
    encryptionKey: env.credentialEncryptionKey,
    cookieSecret: env.cookieSecret,
    allowedGoogleEmails: env.allowedGoogleEmails,
    mcpResourceUrl: env.mcpResourceUrl,
  }));

  app.use(createMcpRouter({
    verifyBearerToken,
    db,
    encryptionKey: env.credentialEncryptionKey,
    mcpResourceUrl: env.mcpResourceUrl,
    issuer: env.publicUrl,
    spawnOptions,
  }));

  app.use(provider.callback());

  return { app, provider };
}
