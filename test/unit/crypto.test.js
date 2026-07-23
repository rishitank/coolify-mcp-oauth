import { describe, it, expect } from 'vitest';
import { encryptSecret, decryptSecret, generateEncryptionKey } from '../../src/crypto.js';

const KEY = generateEncryptionKey(); // base64, 32 bytes

describe('crypto (AES-256-GCM secret box)', () => {
  it('round-trips plaintext through encrypt/decrypt', () => {
    const plaintext = '3|9QsiYPJSYAibmdtraceN3SL7FWa2N3VB2r8kjHBof43e5e2d';
    const packed = encryptSecret(plaintext, KEY);
    expect(decryptSecret(packed, KEY)).toBe(plaintext);
  });

  it('produces a different ciphertext each call (random IV, no reuse)', () => {
    const plaintext = 'same-plaintext-both-times';
    const a = encryptSecret(plaintext, KEY);
    const b = encryptSecret(plaintext, KEY);
    expect(a).not.toBe(b);
    expect(decryptSecret(a, KEY)).toBe(plaintext);
    expect(decryptSecret(b, KEY)).toBe(plaintext);
  });

  it('rejects a tampered ciphertext instead of returning corrupted plaintext', () => {
    const packed = encryptSecret('sensitive-value', KEY);
    const bytes = Buffer.from(packed, 'base64');
    // flip a bit roughly in the middle (inside the ciphertext region, past iv+tag)
    bytes[Math.floor(bytes.length / 2)] ^= 0xff;
    const tampered = bytes.toString('base64');
    expect(() => decryptSecret(tampered, KEY)).toThrow();
  });

  it('fails to decrypt with the wrong key', () => {
    const packed = encryptSecret('sensitive-value', KEY);
    const wrongKey = generateEncryptionKey();
    expect(() => decryptSecret(packed, wrongKey)).toThrow();
  });

  it('generateEncryptionKey returns a 32-byte key, base64-encoded', () => {
    const key = generateEncryptionKey();
    expect(Buffer.from(key, 'base64')).toHaveLength(32);
  });

  it('rejects a key that is not 32 bytes', () => {
    const shortKey = Buffer.alloc(16).toString('base64');
    expect(() => encryptSecret('x', shortKey)).toThrow(/32 bytes/);
  });

  it('handles empty string plaintext', () => {
    const packed = encryptSecret('', KEY);
    expect(decryptSecret(packed, KEY)).toBe('');
  });

  it('handles unicode plaintext', () => {
    const plaintext = 'tökén-with-ünïcödé-🔑';
    const packed = encryptSecret(plaintext, KEY);
    expect(decryptSecret(packed, KEY)).toBe(plaintext);
  });
});
