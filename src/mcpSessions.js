// Durable record of which user an established MCP session id belongs to.
//
// mcpRoute.js's `sessions` Map holds the *live* objects for an established
// session — the StreamableHTTPServerTransport and the spawned coolify-mcp
// child process — and none of that can be persisted: a subprocess and an
// open HTTP transport aren't data. A restart of this service always loses
// them, same as restarting any stateful server would.
//
// What can be persisted, cheaply, is the one fact that lets a fresh process
// respond usefully instead of ambiguously: "this session id was, at some
// point, legitimately issued to this user." Recording just that means an
// unrecognized `Mcp-Session-Id` after a restart can be told apart from an
// unrecognized id that was never valid at all (see mcpRoute.js) — a real
// session that died with the old process ("410 session_expired: please
// reinitialize") versus a bogus or stale-beyond-cleanup one ("404
// session_not_found"). Either way the *conversation* the client had is
// still gone — this doesn't and can't resume it — but the client now gets
// an unambiguous, spec-shaped signal to reinitialize instead of a silently
// fabricated session or a confusing protocol-level failure.

/**
 * Record that `sessionId` was issued to `userId`. Idempotent — recording
 * the same session id twice (e.g. a duplicate `onsessioninitialized` call)
 * keeps the original row rather than erroring or resetting `createdAt`.
 *
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {string} sessionId
 * @param {string} userId
 */
export function recordMcpSession(db, sessionId, userId) {
  db.prepare(
    'INSERT INTO mcp_sessions (session_id, user_id, created_at) VALUES (?, ?, ?) ON CONFLICT(session_id) DO NOTHING',
  ).run(sessionId, userId, Date.now());
}

/**
 * Look up who a session id was issued to.
 *
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {string} sessionId
 * @returns {{sessionId: string, userId: string, createdAt: number} | undefined}
 *   `undefined` when the id was never recorded (or was already deleted).
 */
export function getMcpSession(db, sessionId) {
  return db
    .prepare('SELECT session_id AS sessionId, user_id AS userId, created_at AS createdAt FROM mcp_sessions WHERE session_id = ?')
    .get(sessionId);
}

/**
 * Remove the ownership record for a session id. A no-op, not an error, if
 * the id was never recorded or was already removed.
 *
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {string} sessionId
 */
export function deleteMcpSession(db, sessionId) {
  db.prepare('DELETE FROM mcp_sessions WHERE session_id = ?').run(sessionId);
}
