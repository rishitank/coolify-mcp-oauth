// oidc-provider wires CORS support (open, or client-based via the
// clientBasedCORS helper) onto every endpoint it owns *except* the
// registration endpoint — verified directly in
// node_modules/oidc-provider/lib/helpers/initialize_app.js: every other
// route (token, userinfo, jwks, discovery, revocation, introspection, PAR,
// ...) gets both a matching `CORS.*` middleware on its handler and a
// registered OPTIONS preflight route, while `post('registration', ...)`
// and `get('client', ...)` get neither.
//
// A same-origin caller (our own pages, curl, server-to-server calls like
// Claude/Cowork's connector setup actually makes) never notices this,
// since CORS is a browser-only restriction. But a browser-based DCR
// client calling us cross-origin would get an opaque blocked-preflight
// network error with no detail surfaced to the caller, not a JSON error —
// confirmed with a live cross-origin fetch() from a third-party origin.
//
// Dynamic Client Registration is meant to be publicly callable (that's
// the entire point of DCR — no pre-shared credential needed), so this
// allows any origin, matching the "open" treatment oidc-provider itself
// gives to discovery/jwks.
export function registrationCors(req, res, next) {
  res.set('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') {
    res.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.set('Access-Control-Max-Age', '86400');
    res.status(204).end();
    return;
  }
  next();
}
