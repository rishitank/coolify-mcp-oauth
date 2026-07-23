// Storage Adapter for oidc-provider, per the interface documented at
// https://github.com/panva/node-oidc-provider/blob/main/example/my_adapter.js
//
// oidc-provider instantiates one adapter *per model name* (AccessToken,
// Client, Grant, Session, Interaction, ...); `createAdapter(db)` is a
// factory that returns a class closed over the shared db connection, which
// is the pattern oidc-provider expects for the `adapter` config option
// (a class, not an instance — oidc-provider does `new Adapter(name)`).
//
// All models share one physical table (oidc_model_instances) distinguished
// by the `model` column, with a few payload fields promoted to real
// columns (grant_id, user_code, uid, expiry) so they're indexable — the
// rest of the payload is opaque JSON we don't need to understand.

function rowToPayload(row) {
  if (!row) return undefined;
  if (row.expires_at !== null && row.expires_at < Date.now()) return undefined;
  const payload = JSON.parse(row.payload);
  if (row.consumed_at !== null) {
    payload.consumed = Math.floor(row.consumed_at / 1000);
  }
  return payload;
}

export function createAdapter(db) {
  const upsertStmt = db.prepare(`
    INSERT INTO oidc_model_instances (model, id, payload, grant_id, user_code, uid, expires_at, consumed_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
    ON CONFLICT(model, id) DO UPDATE SET
      payload = excluded.payload,
      grant_id = excluded.grant_id,
      user_code = excluded.user_code,
      uid = excluded.uid,
      expires_at = excluded.expires_at,
      consumed_at = NULL
  `);
  const findStmt = db.prepare('SELECT * FROM oidc_model_instances WHERE model = ? AND id = ?');
  const findByUserCodeStmt = db.prepare('SELECT * FROM oidc_model_instances WHERE model = ? AND user_code = ?');
  const findByUidStmt = db.prepare('SELECT * FROM oidc_model_instances WHERE model = ? AND uid = ?');
  const consumeStmt = db.prepare('UPDATE oidc_model_instances SET consumed_at = ? WHERE model = ? AND id = ?');
  const destroyStmt = db.prepare('DELETE FROM oidc_model_instances WHERE model = ? AND id = ?');
  // Deliberately NOT scoped to `this.model` — a grantId can be shared by
  // AccessToken/RefreshToken/Grant records, and the interface contract
  // requires *all* of them to be revoked, regardless of which model's
  // adapter instance received the call.
  const revokeByGrantIdStmt = db.prepare('DELETE FROM oidc_model_instances WHERE grant_id = ?');

  return class SqliteAdapter {
    constructor(name) {
      this.model = name;
    }

    async upsert(id, payload, expiresIn) {
      const expiresAt = expiresIn ? Date.now() + expiresIn * 1000 : null;
      upsertStmt.run(
        this.model,
        id,
        JSON.stringify(payload),
        payload.grantId ?? null,
        payload.userCode ?? null,
        payload.uid ?? null,
        expiresAt,
      );
    }

    async find(id) {
      return rowToPayload(findStmt.get(this.model, id));
    }

    async findByUserCode(userCode) {
      return rowToPayload(findByUserCodeStmt.get(this.model, userCode));
    }

    async findByUid(uid) {
      return rowToPayload(findByUidStmt.get(this.model, uid));
    }

    async consume(id) {
      consumeStmt.run(Date.now(), this.model, id);
    }

    async destroy(id) {
      destroyStmt.run(this.model, id);
    }

    async revokeByGrantId(grantId) {
      revokeByGrantIdStmt.run(grantId);
    }
  };
}
