import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadOrCreateJwks } from '../../src/jwks.js';

describe('jwks persistence', () => {
  let dir;
  let path;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'jwks-test-'));
    path = join(dir, 'nested', 'jwks.json');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('generates a private RSA signing key on first call', async () => {
    const jwks = await loadOrCreateJwks(path);
    expect(jwks.keys).toHaveLength(1);
    const [key] = jwks.keys;
    expect(key.kty).toBe('RSA');
    expect(key.d).toBeTruthy(); // private component present
    expect(key.alg).toBe('RS256');
    expect(key.kid).toBeTruthy();
  });

  it('persists the generated key to disk', async () => {
    await loadOrCreateJwks(path);
    expect(existsSync(path)).toBe(true);
  });

  it('returns the same key on a second call instead of regenerating', async () => {
    const first = await loadOrCreateJwks(path);
    const second = await loadOrCreateJwks(path);
    expect(second.keys[0].kid).toBe(first.keys[0].kid);
    expect(second.keys[0].n).toBe(first.keys[0].n);
  });
});
