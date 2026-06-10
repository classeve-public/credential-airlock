/**
 * Authenticated encryption with AES-256-GCM.
 * Blob layout: [iv:12][tag:16][ciphertext:...]
 */
import * as crypto from 'crypto';

const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

export function aesgcmEncrypt(key: Buffer, plaintext: Buffer, aad?: Buffer): Buffer {
  if (key.length !== KEY_LEN) throw new Error(`AES key must be ${KEY_LEN} bytes`);
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]);
}

export function aesgcmDecrypt(key: Buffer, blob: Buffer, aad?: Buffer): Buffer {
  if (key.length !== KEY_LEN) throw new Error(`AES key must be ${KEY_LEN} bytes`);
  if (blob.length < IV_LEN + TAG_LEN) throw new Error('ciphertext too short');
  const iv = blob.subarray(0, IV_LEN);
  const tag = blob.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const ct = blob.subarray(IV_LEN + TAG_LEN);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  if (aad) decipher.setAAD(aad);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

export function randomKey(): Buffer {
  return crypto.randomBytes(KEY_LEN);
}
