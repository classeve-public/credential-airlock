import * as crypto from 'crypto';

/** URL-safe random id. */
export function randomId(bytes = 9): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

/** High-entropy admin/session token. */
export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

/** Constant-time string comparison to avoid token-timing oracles. */
export function timingSafeEqualStr(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) {
    // Still do a comparison to keep timing roughly constant.
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}
