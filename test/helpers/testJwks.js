// Ephemeral JWKS for tests — avoids touching disk (unlike jwks.js's
// loadOrCreateJwks, which is tested separately in unit/jwks.test.js).
import { generateKeyPair, exportJWK } from 'jose';

let cached;

export async function testJwks() {
  if (cached) return cached;
  const { privateKey } = await generateKeyPair('RS256', { extractable: true, modulusLength: 2048 });
  const jwk = await exportJWK(privateKey);
  jwk.kid = 'test-key';
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  cached = { keys: [jwk] };
  return cached;
}
