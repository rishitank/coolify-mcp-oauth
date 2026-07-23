import { describe, it, expect, beforeEach } from 'vitest';
import { openDb } from '../../src/db.js';
import {
  upsertUserFromGoogle,
  getUserById,
  getUserByGoogleSub,
  saveCoolifyCredentials,
  getCoolifyCredentials,
} from '../../src/users.js';
import { generateEncryptionKey } from '../../src/crypto.js';

const KEY = generateEncryptionKey();

describe('users + coolify credentials store', () => {
  let db;

  beforeEach(() => {
    db = openDb(':memory:');
  });

  it('creates a new local user on first Google login', () => {
    const user = upsertUserFromGoogle(db, { googleSub: 'g-123', email: 'rishi@example.com', name: 'Rishi' });
    expect(user.id).toBeTruthy();
    expect(user.email).toBe('rishi@example.com');
    expect(user.name).toBe('Rishi');
  });

  it('is idempotent: the same google_sub maps to the same local user id', () => {
    const first = upsertUserFromGoogle(db, { googleSub: 'g-123', email: 'rishi@example.com', name: 'Rishi' });
    const second = upsertUserFromGoogle(db, { googleSub: 'g-123', email: 'rishi@example.com', name: 'Rishi' });
    expect(second.id).toBe(first.id);
  });

  it('refreshes email/name on repeat login if they changed upstream', () => {
    const first = upsertUserFromGoogle(db, { googleSub: 'g-123', email: 'old@example.com', name: 'Old Name' });
    const second = upsertUserFromGoogle(db, { googleSub: 'g-123', email: 'new@example.com', name: 'New Name' });
    expect(second.id).toBe(first.id);
    expect(second.email).toBe('new@example.com');
    expect(second.name).toBe('New Name');
  });

  it('different google_sub values get different local users', () => {
    const a = upsertUserFromGoogle(db, { googleSub: 'g-a', email: 'a@example.com', name: 'A' });
    const b = upsertUserFromGoogle(db, { googleSub: 'g-b', email: 'b@example.com', name: 'B' });
    expect(a.id).not.toBe(b.id);
  });

  it('getUserById returns undefined for an unknown id', () => {
    expect(getUserById(db, 'does-not-exist')).toBeUndefined();
  });

  it('getUserByGoogleSub finds a previously created user', () => {
    const created = upsertUserFromGoogle(db, { googleSub: 'g-123', email: 'rishi@example.com', name: 'Rishi' });
    const found = getUserByGoogleSub(db, 'g-123');
    expect(found.id).toBe(created.id);
  });

  it('getCoolifyCredentials returns undefined when nothing has been saved', () => {
    const user = upsertUserFromGoogle(db, { googleSub: 'g-123', email: 'rishi@example.com', name: 'Rishi' });
    expect(getCoolifyCredentials(db, user.id, KEY)).toBeUndefined();
  });

  it('round-trips saved Coolify credentials, transparently decrypted', () => {
    const user = upsertUserFromGoogle(db, { googleSub: 'g-123', email: 'rishi@example.com', name: 'Rishi' });
    saveCoolifyCredentials(db, user.id, {
      baseUrl: 'https://coolify.tanksterai.com',
      accessToken: '3|9QsiYPJSYAibmdtraceN3SL7FWa2N3VB2r8kjHBof43e5e2d',
    }, KEY);

    const creds = getCoolifyCredentials(db, user.id, KEY);
    expect(creds.baseUrl).toBe('https://coolify.tanksterai.com');
    expect(creds.accessToken).toBe('3|9QsiYPJSYAibmdtraceN3SL7FWa2N3VB2r8kjHBof43e5e2d');
  });

  it('never stores the access token in plaintext', () => {
    const user = upsertUserFromGoogle(db, { googleSub: 'g-123', email: 'rishi@example.com', name: 'Rishi' });
    const token = 'super-secret-coolify-token';
    saveCoolifyCredentials(db, user.id, { baseUrl: 'https://coolify.example.com', accessToken: token }, KEY);

    const row = db.prepare('SELECT encrypted_token FROM coolify_credentials WHERE user_id = ?').get(user.id);
    expect(row.encrypted_token).not.toContain(token);
  });

  it('saveCoolifyCredentials overwrites a previous value for the same user', () => {
    const user = upsertUserFromGoogle(db, { googleSub: 'g-123', email: 'rishi@example.com', name: 'Rishi' });
    saveCoolifyCredentials(db, user.id, { baseUrl: 'https://old.example.com', accessToken: 'old-token' }, KEY);
    saveCoolifyCredentials(db, user.id, { baseUrl: 'https://new.example.com', accessToken: 'new-token' }, KEY);

    const creds = getCoolifyCredentials(db, user.id, KEY);
    expect(creds.baseUrl).toBe('https://new.example.com');
    expect(creds.accessToken).toBe('new-token');
  });

  it('credentials are isolated per user', () => {
    const alice = upsertUserFromGoogle(db, { googleSub: 'g-alice', email: 'alice@example.com', name: 'Alice' });
    const bob = upsertUserFromGoogle(db, { googleSub: 'g-bob', email: 'bob@example.com', name: 'Bob' });
    saveCoolifyCredentials(db, alice.id, { baseUrl: 'https://alice-coolify.example.com', accessToken: 'alice-token' }, KEY);

    expect(getCoolifyCredentials(db, bob.id, KEY)).toBeUndefined();
  });
});
