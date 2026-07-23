import { describe, it, expect } from 'vitest';
import { signState, verifyState } from '../../src/signedState.js';

const SECRET = 'test-cookie-secret-test-cookie-secret';

describe('signedState (CSRF-protected state param for the Google OAuth leg)', () => {
  it('round-trips a payload', () => {
    const token = signState({ purpose: 'interaction', uid: 'abc123' }, SECRET);
    expect(verifyState(token, SECRET)).toMatchObject({ purpose: 'interaction', uid: 'abc123' });
  });

  it('produces a URL-safe token (no characters that need percent-encoding)', () => {
    const token = signState({ purpose: 'account' }, SECRET);
    // payload.signature — both segments base64url, joined by a literal dot
    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  it('rejects a tampered payload', () => {
    const token = signState({ purpose: 'interaction', uid: 'abc123' }, SECRET);
    const [payload, sig] = token.split('.');
    const tamperedPayload = Buffer.from(JSON.stringify({ purpose: 'interaction', uid: 'someone-elses-uid' })).toString('base64url');
    expect(() => verifyState(`${tamperedPayload}.${sig}`, SECRET)).toThrow();
  });

  it('rejects a token signed with a different secret', () => {
    const token = signState({ purpose: 'interaction', uid: 'abc123' }, SECRET);
    expect(() => verifyState(token, 'a-completely-different-secret-value')).toThrow();
  });

  it('rejects an expired token', () => {
    const token = signState({ purpose: 'interaction', uid: 'abc123' }, SECRET, { ttlSeconds: -1 });
    expect(() => verifyState(token, SECRET)).toThrow(/expired/i);
  });

  it('rejects a malformed token', () => {
    expect(() => verifyState('not-a-valid-token', SECRET)).toThrow();
    expect(() => verifyState('', SECRET)).toThrow();
  });
});
