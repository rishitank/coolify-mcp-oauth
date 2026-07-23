// Configures the oidc-provider Authorization Server instance. This is the
// part that gives us, for free, spec-compliant: PKCE enforcement, Dynamic
// Client Registration, RFC 8707 Resource Indicator / audience binding,
// JWKS, and RFC 8414 metadata. The only genuinely custom pieces plugged in
// here are: SQLite storage (oidcAdapter.js), how an account is loaded
// (findAccount, backed by users.js), and where unauthenticated requests get
// sent to establish who the user is (interactions.url — handled by
// interactions.js, which drives the Google federation).

import { Provider, errors } from 'oidc-provider';
import { createAdapter } from './oidcAdapter.js';
import { getUserById } from './users.js';
import { MCP_SCOPE } from './mcpScope.js';

const { InvalidTarget } = errors;

export function createOidcProvider({ publicUrl, mcpResourceUrl, db, jwks, cookieSecret }) {
  const Adapter = createAdapter(db);

  const provider = new Provider(publicUrl, {
    adapter: Adapter,
    clients: [],
    jwks,
    cookies: {
      keys: [cookieSecret],
    },
    claims: {
      openid: ['sub'],
      profile: ['name'],
      email: ['email'],
    },
    // Extends the default ['openid', 'offline_access'] with our own
    // resource's scope so it lands in scopes_supported and Dynamic Client
    // Registration will actually accept a client requesting it — see
    // mcpScope.js for why this has to be listed both here *and* in
    // resourceIndicators.getResourceServerInfo below.
    scopes: ['openid', 'offline_access', MCP_SCOPE],
    features: {
      // Anyone can self-register an MCP client (Claude/Cowork does this
      // automatically) — no pre-shared initial access token.
      registration: {
        enabled: true,
        initialAccessToken: false,
      },
      revocation: { enabled: true },
      devInteractions: { enabled: false },
      // RFC 8707 — binds issued access tokens to a specific resource
      // (our /mcp URL) via the `aud` claim, and is what makes JWT-format
      // access tokens possible without a confidential client secret.
      resourceIndicators: {
        enabled: true,
        defaultResource: async () => mcpResourceUrl,
        getResourceServerInfo: async (ctx, resourceIndicator) => {
          if (resourceIndicator !== mcpResourceUrl) {
            throw new InvalidTarget('unknown resource indicator');
          }
          return {
            scope: MCP_SCOPE,
            accessTokenFormat: 'jwt',
            jwt: { sign: { alg: 'RS256' } },
          };
        },
      },
    },
    interactions: {
      url(ctx, interaction) {
        return `/interaction/${interaction.uid}`;
      },
    },
    findAccount: async (ctx, sub) => {
      const user = getUserById(db, sub);
      if (!user) return undefined;
      return {
        accountId: sub,
        async claims() {
          return { sub, email: user.email, name: user.name ?? undefined };
        },
      };
    },
    // oidc-provider's default only issues a refresh token when the client
    // also requested the OIDC-ism 'offline_access' scope. MCP clients are
    // plain OAuth2 (no 'openid'/'offline_access' concept) but still need
    // long-lived access without re-prompting Google every hour — so any
    // client that declared it supports the refresh_token grant gets one.
    issueRefreshToken: async (ctx, client) => client.grantTypeAllowed('refresh_token'),
    ttl: {
      AccessToken: 3600,
      AuthorizationCode: 300,
      RefreshToken: 30 * 24 * 3600,
      Interaction: 3600,
      Session: 30 * 24 * 3600,
      Grant: 30 * 24 * 3600,
    },
  });

  // We sit behind Coolify's Caddy proxy (TLS offload) — trust
  // X-Forwarded-* so issuer/redirect URLs come out as https, not http.
  provider.proxy = true;

  // oidc-provider only surfaces action failures through its own `debug`
  // namespaces (silent unless DEBUG=oidc-provider:* is set) or as a JSON
  // body sent back to the *client* — nothing reaches our own stdout/logs
  // by default. That makes remote-client failures (e.g. Claude/Cowork's
  // connector setup failing to register) invisible to us: the caller sees
  // an error, we see nothing. Log every action error server-side so a
  // failure like that shows up in `docker logs` / Coolify's log viewer
  // instead of only in the caller's UI.
  for (const eventName of [
    'server_error',
    'registration_create.error',
    'registration_read.error',
    'registration_update.error',
    'registration_delete.error',
    'discovery.error',
    'grant.error',
    'authorization.error',
    'userinfo.error',
  ]) {
    provider.on(eventName, (ctx, err) => {
      console.error(`[oidc:${eventName}]`, JSON.stringify({
        path: ctx.path,
        method: ctx.method,
        origin: ctx.get('origin') || null,
        error: err.error,
        error_description: err.error_description,
        message: err.message,
        statusCode: err.statusCode,
      }));
    });
  }

  return provider;
}
