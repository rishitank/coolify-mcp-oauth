// SQLite storage, via Node's built-in node:sqlite (no native module build
// step — important both for this sandbox's restricted network and for
// keeping the Docker image simple: no node-gyp / prebuilt-binary download
// needed). Node marks this API experimental; it's stable enough for a
// single-file, single-process deployment like this one.
//
// Holds two kinds of state:
//   1. Our own app tables: users, coolify_credentials.
//   2. oidc-provider's state, via the generic oidc_model_instances table
//      (see oidcAdapter.js for the Adapter that reads/writes it).

import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  google_sub TEXT UNIQUE NOT NULL,
  email TEXT NOT NULL,
  name TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS coolify_credentials (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  base_url TEXT NOT NULL,
  encrypted_token TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_model_instances (
  model TEXT NOT NULL,
  id TEXT NOT NULL,
  payload TEXT NOT NULL,
  grant_id TEXT,
  user_code TEXT,
  uid TEXT,
  expires_at INTEGER,
  consumed_at INTEGER,
  PRIMARY KEY (model, id)
);

CREATE INDEX IF NOT EXISTS idx_oidc_grant_id ON oidc_model_instances(grant_id);
CREATE INDEX IF NOT EXISTS idx_oidc_user_code ON oidc_model_instances(model, user_code);
CREATE INDEX IF NOT EXISTS idx_oidc_uid ON oidc_model_instances(model, uid);
`;

export function openDb(path) {
  if (path !== ':memory:') {
    mkdirSync(dirname(path), { recursive: true });
  }
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  return db;
}
