// Compact signed+expiring token used as the `state` param on the outbound
// Google OAuth redirect. Protects that leg against CSRF (an attacker
// can't forge a valid state pointing at someone else's interaction uid)
// without needing server-side storage for the state itself — it's
// self-contained, HMAC-signed, base64url so it's safe to drop straight
// into a query string.

import { createHmac, timingSafeEqual } from 'node:crypto';

const DEFAULT_TTL_SECONDS = 10 * 60; // Google login should take well under this

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function sign(payloadB64, secret) {
  return createHmac('sha256', secret).update(payloadB64).digest('base64url');
}

export function signState(payload, secret, { ttlSeconds = DEFAULT_TTL_SECONDS } = {}) {
  const envelope = { ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds };
  const payloadB64 = base64url(JSON.stringify(envelope));
  const signature = sign(payloadB64, secret);
  return `${payloadB64}.${signature}`;
}

export function verifyState(token, secret) {
  if (!token || typeof token !== 'string' || !token.includes('.')) {
    throw new Error('Malformed state token.');
  }
  const [payloadB64, signature] = token.split('.');
  const expectedSignature = sign(payloadB64, secret);

  const sigBuf = Buffer.from(signature ?? '');
  const expectedBuf = Buffer.from(expectedSignature);
  if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) {
    throw new Error('State token signature is invalid.');
  }

  const envelope = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  if (typeof envelope.exp !== 'number' || envelope.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('State token has expired.');
  }

  const { exp, ...payload } = envelope;
  return payload;
}
