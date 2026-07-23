# coolify-mcp-oauth

A self-hosted OAuth 2.1 authorization server (sign in with Google) that
turns [`@masonator/coolify-mcp`](https://github.com/StuMason/coolify-mcp)
into a remote, multi-tenant MCP server — so you (or anyone you let in) can
add **your own Coolify instance** to Claude/Cowork as a custom connector
from any device, with no shared credentials and no third-party auth
vendor in the loop.

Bring your own Coolify instance and your own Google account; this project
supplies the OAuth server and the MCP proxying in between. One deployment
can serve multiple people, each with their own Coolify credentials —
nobody shares anybody else's.

See [`docs/SCOPE.md`](docs/SCOPE.md) for the full architecture writeup.

```
Claude / Cowork ──OAuth (DCR + PKCE)──▶  this service  ──sign in──▶  Google
                                              │
                                              │ (first login only)
                                              ▼
                                   "enter your Coolify URL + API token"
                                              │
Claude / Cowork ──MCP, bearer token──▶  this service  ──spawns per session──▶ coolify-mcp
                                                                                    │
                                                                                    ▼
                                                                      your Coolify instance
```

## Why this exists

`@masonator/coolify-mcp` is a great local MCP server, but it's stdio-only
and single-tenant — it only knows about one Coolify instance, configured
via env vars at process startup. That's fine for `claude_desktop_config.json`
on your own machine, but doesn't work for Cowork on mobile, or for
sharing one deployment across people who each manage different Coolify
instances.

This project is the Authorization Server *and* the Resource Server:
Dynamic Client Registration, PKCE, JWT-format resource-bound access
tokens, and a `/mcp` endpoint that spawns a fresh `coolify-mcp` process
per authenticated session using *that session's* stored credentials —
built on [`oidc-provider`](https://github.com/panva/node-oidc-provider)
rather than hand-rolled, since OAuth protocol correctness matters and
that library is a mature, spec-compliant implementation.

## Self-hosting

### 1. Create a Google OAuth client

In [Google Cloud Console](https://console.cloud.google.com/apis/credentials):

1. Create (or reuse) a project.
2. **APIs & Services → OAuth consent screen** — set it up (External is
   fine; you can leave it in "Testing" mode and explicitly add allowed
   testers, or publish it — either works for this use case).
3. **APIs & Services → Credentials → Create Credentials → OAuth client ID**
   → Application type **Web application**.
4. Authorized redirect URI: `https://<your-domain>/callback/google`
5. Note the **Client ID** and **Client Secret**.

### 2. Generate secrets

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"  # run twice
```
Use one output for `CREDENTIAL_ENCRYPTION_KEY`, the other for `COOKIE_SECRET`.

### 3. Configure environment

Copy `.env.example` to `.env` and fill in `PUBLIC_URL`, the Google client
ID/secret, and the two generated secrets. See the comments in
`.env.example` for what each variable does. If this is a personal
deployment (your own Coolify box), also set `ALLOWED_GOOGLE_EMAILS` to
your own email — otherwise anyone with a Google account can create a
local account on your deployment and link their own (not your) Coolify
instance to it.

### 4. Deploy

**Docker Compose** (works on Coolify, or anywhere else that runs compose):

```bash
docker compose up -d --build
```

Point a domain at the container's port 3000 (on Coolify: assign the
domain in the app's settings; if it 502s, double check the domain is
mapped to port **3000** specifically, e.g. `https://your-domain:3000`
in the Domains field, since Coolify doesn't always infer the port
correctly for a single-service compose app).

**Bare Node** (no Docker):

```bash
npm install
npm start
```

Either way, the SQLite database and generated JWKS signing key persist
under `DATA_DIR` (`/data` in the Docker image — make sure it's a real
volume, not ephemeral storage) — losing that directory invalidates every
session and orphans everyone's stored (encrypted) Coolify credentials.

### 5. Add it to Claude / Cowork

Settings → Connectors → Add custom connector → paste
`https://<your-domain>/mcp`. Claude registers itself automatically (no
manual client ID/secret), redirects you to Google, and — the first time —
asks for the Coolify base URL and API token to use. Get an API token from
your Coolify instance under **Keys & Tokens → API tokens**.

You can also visit `https://<your-domain>/account` directly any time to
set up or rotate your stored Coolify credentials without going through an
MCP client.

## Development

```bash
npm install
npm test        # runs the full suite once
npm run test:watch
```

The test suite (82 tests as of this writing) never touches the real
Google or npm registry: `test/helpers/mockGoogle.js` stands in for
Google's OIDC endpoints, and `test/helpers/fakeCoolifyMcp.js` stands in
for the real `coolify-mcp` package, both speaking the real protocols so
the tests exercise genuine request/response handling rather than mocks of
your own code. `test/integration/fullStack.test.js` is the capstone: it
drives Dynamic Client Registration, the full Google-login-then-Coolify-setup
interaction, consent, token issuance, and an actual MCP tool call, all
in one test.

## Security notes

- Coolify API tokens are encrypted at rest (AES-256-GCM) and never appear
  in logs, issued tokens, or JWT claims — the MCP proxy layer looks them
  up server-side by the authenticated user id.
- Each MCP session gets its own `coolify-mcp` child process, holding only
  that session's user's credentials — never a shared global credential.
- Access tokens are short-lived JWTs bound to this deployment's `/mcp`
  URL via the `aud` claim (RFC 8707 Resource Indicators); a token can't
  be replayed against a different resource.
- The bearer token is re-verified on *every* `/mcp` request, not just
  when a session is established — an `Mcp-Session-Id` alone is never
  sufficient, so a leaked session id can't be paired with someone else's
  valid token to hijack a session.
- This is a single-instance deployment (SQLite, in-process session state)
  by design for now — see `docs/SCOPE.md` for what's explicitly out of
  scope.

## License

MIT — see [`LICENSE`](LICENSE).
