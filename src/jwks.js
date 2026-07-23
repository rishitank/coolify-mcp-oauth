// Generates (once) and persists the RSA signing key oidc-provider uses to
// sign access/ID tokens. Persistence matters: if this key changed on every
// restart, every previously issued token (and every client's cached
// knowledge of our JWKS) would silently break.

import { generateKeyPair, exportJWK } from 'jose';
import { randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export async function loadOrCreateJwks(path) {
  if (existsSync(path)) {
    return JSON.parse(readFileSync(path, 'utf8'));
  }

  const { privateKey } = await generateKeyPair('RS256', { extractable: true, modulusLength: 2048 });
  const jwk = await exportJWK(privateKey);
  jwk.kid = randomUUID();
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  const jwks = { keys: [jwk] };

  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(jwks, null, 2), { mode: 0o600 });

  return jwks;
}
