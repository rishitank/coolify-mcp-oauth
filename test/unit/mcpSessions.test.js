import { describe, it, expect, beforeEach } from 'vitest';
import { openDb } from '../../src/db.js';
import { upsertUserFromGoogle } from '../../src/users.js';
import { recordMcpSession, getMcpSession, deleteMcpSession } from '../../src/mcpSessions.js';

describe('mcpSessions (durable record of which user an MCP session id belongs to)', () => {
  let db;
  let user;

  beforeEach(() => {
    db = openDb(':memory:');
    user = upsertUserFromGoogle(db, { googleSub: 'g-1', email: 'a@example.com', name: 'A' });
  });

  it('getMcpSession returns undefined for an id that was never recorded', () => {
    expect(getMcpSession(db, 'nope')).toBeUndefined();
  });

  it('recordMcpSession then getMcpSession round-trips the owning user', () => {
    recordMcpSession(db, 'sess-1', user.id);
    const found = getMcpSession(db, 'sess-1');
    expect(found.sessionId).toBe('sess-1');
    expect(found.userId).toBe(user.id);
    expect(typeof found.createdAt).toBe('number');
  });

  it('recording the same session id twice does not throw and keeps the original row', () => {
    recordMcpSession(db, 'sess-1', user.id);
    const first = getMcpSession(db, 'sess-1');
    recordMcpSession(db, 'sess-1', user.id);
    const second = getMcpSession(db, 'sess-1');
    expect(second.createdAt).toBe(first.createdAt);
  });

  it('deleteMcpSession removes the record', () => {
    recordMcpSession(db, 'sess-1', user.id);
    deleteMcpSession(db, 'sess-1');
    expect(getMcpSession(db, 'sess-1')).toBeUndefined();
  });

  it('deleteMcpSession on an id that does not exist is a no-op, not an error', () => {
    expect(() => deleteMcpSession(db, 'does-not-exist')).not.toThrow();
  });
});
