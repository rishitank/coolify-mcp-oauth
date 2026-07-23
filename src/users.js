// Local user accounts (keyed by Google `sub`) and their per-user Coolify
// credentials. This is the multi-tenancy seam: every MCP request is
// resolved down to a userId, and that userId's stored credentials are what
// get handed to the spawned coolify-mcp process (see mcpProxy.js).

import { randomUUID } from 'node:crypto';
import { encryptSecret, decryptSecret } from './crypto.js';

export function upsertUserFromGoogle(db, { googleSub, email, name }) {
  const existing = getUserByGoogleSub(db, googleSub);
  if (existing) {
    db.prepare('UPDATE users SET email = ?, name = ? WHERE id = ?').run(email, name ?? null, existing.id);
    return getUserById(db, existing.id);
  }

  const id = randomUUID();
  db.prepare(
    'INSERT INTO users (id, google_sub, email, name, created_at) VALUES (?, ?, ?, ?, ?)',
  ).run(id, googleSub, email, name ?? null, Date.now());
  return getUserById(db, id);
}

export function getUserById(db, id) {
  return db.prepare('SELECT id, google_sub AS googleSub, email, name, created_at AS createdAt FROM users WHERE id = ?').get(id);
}

export function getUserByGoogleSub(db, googleSub) {
  return db.prepare('SELECT id, google_sub AS googleSub, email, name, created_at AS createdAt FROM users WHERE google_sub = ?').get(googleSub);
}

export function saveCoolifyCredentials(db, userId, { baseUrl, accessToken }, encryptionKey) {
  const encryptedToken = encryptSecret(accessToken, encryptionKey);
  db.prepare(`
    INSERT INTO coolify_credentials (user_id, base_url, encrypted_token, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET base_url = excluded.base_url, encrypted_token = excluded.encrypted_token, updated_at = excluded.updated_at
  `).run(userId, baseUrl, encryptedToken, Date.now());
}

export function getCoolifyCredentials(db, userId, encryptionKey) {
  const row = db.prepare('SELECT base_url AS baseUrl, encrypted_token AS encryptedToken FROM coolify_credentials WHERE user_id = ?').get(userId);
  if (!row) return undefined;
  return {
    baseUrl: row.baseUrl,
    accessToken: decryptSecret(row.encryptedToken, encryptionKey),
  };
}
