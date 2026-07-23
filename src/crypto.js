// AES-256-GCM "secret box" for encrypting Coolify API tokens at rest.
//
// Packed format (base64 of the concatenation): iv (12 bytes) || authTag
// (16 bytes) || ciphertext. Single-column storage, and GCM's auth tag
// means any tampering with the stored value is detected on decrypt rather
// than silently producing garbage plaintext.

import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;

function loadKey(keyBase64) {
  const key = Buffer.from(keyBase64, 'base64');
  if (key.length !== KEY_LENGTH) {
    throw new Error(`Encryption key must decode to ${KEY_LENGTH} bytes (got ${key.length}). Generate one with generateEncryptionKey().`);
  }
  return key;
}

export function generateEncryptionKey() {
  return randomBytes(KEY_LENGTH).toString('base64');
}

export function encryptSecret(plaintext, keyBase64) {
  const key = loadKey(keyBase64);
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, ciphertext]).toString('base64');
}

export function decryptSecret(packedBase64, keyBase64) {
  const key = loadKey(keyBase64);
  const packed = Buffer.from(packedBase64, 'base64');
  if (packed.length < IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new Error('Ciphertext too short to contain iv + auth tag.');
  }
  const iv = packed.subarray(0, IV_LENGTH);
  const authTag = packed.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = packed.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}
