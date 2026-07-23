// Express wiring for the MCP resource server: session bookkeeping on top
// of mcpProxy.js's per-session child-process proxy, plus the protected
// resource metadata endpoint MCP clients use for OAuth discovery (RFC
// 9728 / MCP Authorization spec).

import { randomUUID } from 'node:crypto';
import express from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createCoolifySessionProxy, buildWwwAuthenticateHeader } from './mcpProxy.js';
import { getCoolifyCredentials } from './users.js';
import { MCP_SCOPE } from './mcpScope.js';

export function createMcpRouter({
  verifyBearerToken,
  db,
  encryptionKey,
  mcpResourceUrl,
  issuer,
  spawnOptions = {},
}) {
  const router = express.Router();
  const protectedResourceMetadataUrl = `${new URL(mcpResourceUrl).origin}/.well-known/oauth-protected-resource`;
  // sessionId -> { transport, proxy, userId }
  const sessions = new Map();

  router.get('/.well-known/oauth-protected-resource', (req, res) => {
    res.json({
      resource: mcpResourceUrl,
      authorization_servers: [issuer],
      scopes_supported: [MCP_SCOPE],
      bearer_methods_supported: ['header'],
    });
  });

  function unauthorized(res, err) {
    res.set('WWW-Authenticate', buildWwwAuthenticateHeader(protectedResourceMetadataUrl));
    return res.status(401).json({
      error: err.code === 'missing_token' ? 'unauthorized' : 'invalid_token',
      error_description: err.message,
    });
  }

  router.all('/mcp', express.json(), async (req, res, next) => {
    try {
      // Always verify — the session id (once established) is only a
      // routing/continuity handle, not a substitute for auth on every
      // request. This also lets us catch a stolen/reused session id being
      // paired with a *different* user's otherwise-valid token.
      let auth;
      try {
        auth = await verifyBearerToken(req.headers.authorization);
      } catch (err) {
        return unauthorized(res, err);
      }

      const sessionIdHeader = req.header('mcp-session-id');
      let session = sessionIdHeader ? sessions.get(sessionIdHeader) : undefined;

      if (session && session.userId !== auth.sub) {
        return res.status(403).json({ error: 'session_user_mismatch', error_description: 'This session belongs to a different account.' });
      }

      if (!session) {
        const credentials = getCoolifyCredentials(db, auth.sub, encryptionKey);
        if (!credentials) {
          return res.status(403).json({
            error: 'coolify_not_configured',
            error_description: 'No Coolify credentials are configured for this account yet. Visit /account on this server to set them up.',
          });
        }

        const proxy = await createCoolifySessionProxy({
          baseUrl: credentials.baseUrl,
          accessToken: credentials.accessToken,
          ...spawnOptions,
        });

        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (sessionId) => {
            session.sessionId = sessionId;
            sessions.set(sessionId, session);
          },
          onsessionclosed: (sessionId) => {
            sessions.delete(sessionId);
            proxy.close().catch(() => {});
          },
        });
        transport.onclose = () => {
          if (transport.sessionId) sessions.delete(transport.sessionId);
          proxy.close().catch(() => {});
        };

        session = { transport, proxy, userId: auth.sub };
        await proxy.server.connect(transport);
      }

      await session.transport.handleRequest(req, res, req.body);
    } catch (err) {
      next(err);
    }
  });

  return router;
}
