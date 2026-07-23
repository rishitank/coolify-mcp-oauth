import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { startMockGoogle } from '../helpers/mockGoogle.js';
import { createGoogleAuth } from '../../src/google.js';

describe('Google federation (src/google.js)', () => {
  let mockGoogle;
  let googleAuth;

  beforeAll(async () => {
    mockGoogle = await startMockGoogle();
    googleAuth = createGoogleAuth({
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      redirectUri: 'http://localhost:3000/callback/google',
      discoveryUrl: mockGoogle.discoveryUrl,
    });
  });

  afterAll(async () => {
    await mockGoogle.close();
  });

  beforeEach(() => {
    mockGoogle.setNextIdTokenClaims(null);
  });

  it('builds an authorization URL pointing at the (mock) Google authorization endpoint', async () => {
    const url = await googleAuth.getAuthorizationUrl({ state: 'abc123' });
    const parsed = new URL(url);

    expect(parsed.origin + parsed.pathname).toBe(`${mockGoogle.origin}/o/oauth2/v2/auth`);
    expect(parsed.searchParams.get('client_id')).toBe('test-client-id');
    expect(parsed.searchParams.get('redirect_uri')).toBe('http://localhost:3000/callback/google');
    expect(parsed.searchParams.get('response_type')).toBe('code');
    expect(parsed.searchParams.get('state')).toBe('abc123');
    expect(parsed.searchParams.get('scope')).toContain('email');
  });

  it('exchanges a valid code for tokens', async () => {
    const tokens = await googleAuth.exchangeCode('valid-code');
    expect(tokens.idToken).toBeTruthy();
    expect(tokens.accessToken).toBe('mock-google-access-token');
  });

  it('rejects an invalid code', async () => {
    await expect(googleAuth.exchangeCode('invalid-code')).rejects.toThrow();
  });

  it('verifies a genuine id_token and returns identity claims', async () => {
    mockGoogle.setNextIdTokenClaims({ sub: 'google-sub-42', email: 'rishi@example.com', name: 'Rishi Tank', email_verified: true });
    const { idToken } = await googleAuth.exchangeCode('valid-code');

    const identity = await googleAuth.verifyIdToken(idToken);
    expect(identity.sub).toBe('google-sub-42');
    expect(identity.email).toBe('rishi@example.com');
    expect(identity.name).toBe('Rishi Tank');
  });

  it('rejects an expired id_token', async () => {
    mockGoogle.setNextIdTokenClaims({ expired: true });
    const { idToken } = await googleAuth.exchangeCode('valid-code');
    await expect(googleAuth.verifyIdToken(idToken)).rejects.toThrow();
  });

  it('rejects an id_token issued for a different client (wrong audience)', async () => {
    const otherClientAuth = createGoogleAuth({
      clientId: 'a-completely-different-client-id',
      clientSecret: 'irrelevant',
      redirectUri: 'http://localhost:3000/callback/google',
      discoveryUrl: mockGoogle.discoveryUrl,
    });

    const { idToken } = await googleAuth.exchangeCode('valid-code'); // issued for 'test-client-id'
    await expect(otherClientAuth.verifyIdToken(idToken)).rejects.toThrow();
  });

  it('rejects an unverified email', async () => {
    mockGoogle.setNextIdTokenClaims({ email_verified: false });
    const { idToken } = await googleAuth.exchangeCode('valid-code');
    await expect(googleAuth.verifyIdToken(idToken)).rejects.toThrow(/email/i);
  });

  it('caches the discovery document instead of refetching it on every call', async () => {
    const before = mockGoogle.requestCounts.discovery;
    await googleAuth.getAuthorizationUrl({ state: 'x' });
    await googleAuth.exchangeCode('valid-code');
    const after = mockGoogle.requestCounts.discovery;
    expect(after - before).toBeLessThanOrEqual(1);
  });
});
