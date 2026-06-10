import * as crypto from 'crypto';

/** HKDF-SHA256 -> Buffer of `length` bytes. */
export function hkdf(ikm: Buffer, salt: Buffer, info: string, length = 32): Buffer {
  const out = crypto.hkdfSync('sha256', ikm, salt, Buffer.from(info, 'utf8'), length);
  return Buffer.from(out);
}

/** scrypt KDF (built-in, memory-hard). Used for passphrase-protected shares. */
export function scryptKey(passphrase: string, salt: Buffer, length = 32): Buffer {
  // N=2^15, r=8, p=1 -> ~32MB, a sensible interactive cost.
  return crypto.scryptSync(passphrase, salt, length, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
}
