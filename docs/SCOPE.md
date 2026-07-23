# Scope: self-hosted OAuth + Coolify MCP gateway

## Goal

A single open-source, self-hostable service that:

1. Is a spec-compliant OAuth 2.1 / OIDC **Authorization Server** — no
   third-party auth vendor (replaces the earlier WorkOS-based build).
2. Lets end users authenticate with **Google Sign-In** rather than a
   password.
3. Lets *any* user bring *their own* Coolify instance URL + API token and
   use it through this one deployment — multi-tenant, not hardcoded to a
   single Coolify instance.
4. Exposes the real `@masonator/coolify-mcp` tool surface (42 tools) over
   MCP Streamable HTTP, gated behind the bearer tokens this server issues.
5. Is addable as a Claude/Cowork custom connector via Dynamic Client
   Registration — no manual client ID/secret entry.

This is a materially different shape than the previous WorkOS-based build,
which was single-tenant (one Coolify instance baked in at deploy time via
env vars) and delegated all OAuth logic to WorkOS. Here, both the identity
and the OAuth protocol implementation are ours.

## Why build the AS instead of hand-rolling it fully from scratch

OAuth/OIDC authorization-server logic (PKCE validation, authorization code
handling, token issuance, DCR, resource-indicator/audience binding) is
security-critical and easy to get subtly wrong. Rather than hand-roll it,
this uses [`oidc-provider`](https://github.com/panva/node-oidc-provider) —
a mature, spec-compliant, actively maintained OIDC/OAuth2 AS implementation
(same author as the `jose` JWT library already used in the earlier build).
It natively supports everything the MCP OAuth spec needs:

- RFC 7591 Dynamic Client Registration (`features.registration`)
- RFC 7636 PKCE (on by default for public clients — OAuth 2.1 requirement)
- RFC 8707 Resource Indicators (`features.resourceIndicators` —
  binds issued tokens to the MCP server's URL as `aud`, exactly what
  Claude's MCP client sends as the `resource` parameter)
- RFC 8414 Authorization Server Metadata (auto-served)
- JWKS + JWT-format access tokens (`accessTokenFormat: 'jwt'`)
- A pluggable `interactions` hook, which is where custom code plugs in:
  our own logic decides *how* a user authenticates (Google, in this case)
  and oidc-provider handles everything downstream of that decision.

The genuinely custom code is: the SQLite storage adapter, the Google
federation logic, the Coolify-credential onboarding step, and the MCP
resource-server proxy. That's the surface this project's tests target.

## Components (one Node process, one Express app)

```
                          ┌─────────────────────────────────────────┐
                          │            coolify-mcp-oauth              │
                          │                                           │
 Claude / Cowork  ───────▶│  oidc-provider  (DCR, /auth, /token,      │
  (OAuth client,          │  JWKS, resource-indicator-bound JWTs)     │
  DCR + PKCE)              │        │                                 │
                          │        │ interactions.url                │
                          │        ▼                                 │
                          │  /interaction/:uid  ──▶ redirect ──────┐ │
                          │        ▲                    Google     │ │
                          │        │ /callback/google  OAuth       │ │
                          │        └────────────────────────────────┘ │
                          │        │                                 │
                          │        ▼ (first login only)              │
                          │  /interaction/:uid/coolify-setup         │
                          │  "enter your Coolify URL + API token"    │
                          │        │                                 │
                          │        ▼                                 │
                          │  SQLite (users, encrypted coolify         │
                          │  credentials, oidc-provider's own state) │
                          │                                           │
 Claude / Cowork  ───────▶│  /mcp  (bearer-checked against the       │
  (MCP client,             │  provider's own JWKS) ──▶ spawns          │
  Streamable HTTP)         │  `npx @masonator/coolify-mcp` per         │
                          │  session, using *that user's* stored      │
                          │  Coolify URL + token as env vars          │
                          └─────────────────────────────────────────┘
                                          │
                                          ▼
                              user's own Coolify instance
```

Everything lives in one deployable service (one container, one SQLite
file) rather than the multi-service docker-compose split used in the
WorkOS build — the previous split existed to separate "trusted resource
server" from "third-party AS." Now there's no third party, and the AS and
resource server share the same JWKS and the same user/credential store, so
one process is simpler and there's nothing gained by splitting it.

## Data model (SQLite)

- `users` — `id` (uuid, = OIDC `sub`), `google_sub` (unique), `email`,
  `name`, `created_at`.
- `coolify_credentials` — `user_id` (FK, PK), `base_url`,
  `encrypted_token`, `iv`, `auth_tag`, `updated_at`. Token encrypted with
  AES-256-GCM using a server-held `CREDENTIAL_ENCRYPTION_KEY` (32 random
  bytes, generated once, set as an env var — never written to disk in
  plaintext alongside the ciphertext).
- `oidc_model_instances` — generic table backing the `oidc-provider`
  Adapter contract: `(model, id) PK`, `payload` (JSON), plus indexed
  `grant_id`, `user_code`, `uid` columns for the adapter's `findByUid` /
  `findByUserCode` / `revokeByGrantId` lookups, and `expires_at` for
  cleanup.

## Security notes (this matters more than usual — it's public and holds
other people's infra credentials)

- Coolify API tokens are encrypted at rest (AES-256-GCM), never logged,
  never embedded in issued JWT claims (tokens only carry the local
  `sub`/user id; the MCP proxy layer looks up credentials server-side).
- Access tokens are short-lived JWTs bound to the MCP resource URL via
  `aud` (resource indicators) — a token minted for one deployment's `/mcp`
  cannot be replayed against a different resource.
- Each authenticated MCP session gets its own `coolify-mcp` child process
  with only *that* user's credentials in its environment — no shared
  global Coolify credential in process memory.
- Self-hosters who want the instance restricted to themselves (the
  expected setup for a personal Coolify box) can set `ALLOWED_GOOGLE_EMAILS`
  to reject Google logins from anyone else — otherwise any Google account
  can create a local account and link *their own* Coolify credentials
  (isolated per-user; not a data-exposure risk to other users, but still
  worth gating on shared compute).
- `oidc-provider`'s own request validation (PKCE required for public
  clients, redirect URI exact-match, etc.) is trusted rather than
  reimplemented.

## Out of scope for this pass

- Multi-Coolify-instance-per-user (one Coolify config per user for now).
- An account-settings UI beyond the one onboarding form (updating stored
  credentials later can reuse the same form, reachable by re-running the
  OAuth flow).
- Horizontal scaling / non-SQLite storage backends (documented as a
  future swap — the Adapter interface is the seam).

## Test strategy (TDD)

Each module gets tests written first:

1. `crypto` — encrypt/decrypt roundtrip, tamper detection.
2. `oidcAdapter` — exercised directly against the documented `oidc-provider`
   Adapter contract (upsert/find/findByUid/consume/destroy/revokeByGrantId).
3. Google federation — HTTP calls to Google are made through an injectable
   client so tests point it at a local mock server instead of the real
   `accounts.google.com`.
4. MCP proxy — bearer verification tested against real JWTs signed with a
   test JWKS; the `coolify-mcp` child process is a tiny fixture script
   speaking just enough MCP stdio protocol to prove the proxying works,
   instead of spawning the real npm package in unit tests.
5. One end-to-end integration test drives the full loop in-process:
   DCR → `/authorize` → interaction → mocked Google → token exchange →
   authenticated `/mcp` call → tool result.

Real Google credentials and a real Coolify instance are only needed for
the final live deployment check, not for the test suite.
