/**
 * Shamir's Secret Sharing over GF(2^8) (Rijndael field, poly 0x11b).
 *
 * Implemented in-repo (no dependency) so it can be audited line by line, per the
 * project's "review every dependency" hardening rule.
 *
 * split(secret, k, n) -> n shares; any k reconstruct the secret, k-1 reveal nothing.
 * Share wire format: [x:1][y:len] where x is the 1-based evaluation point.
 */
import * as crypto from 'crypto';

// --- GF(256) exp/log tables (generator 0x03) ---
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(function initTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    // multiply by generator 3: x = x ^ (x<<1), reduce by 0x11b
    let next = x ^ (x << 1);
    if (next & 0x100) next ^= 0x11b;
    x = next & 0xff;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

function gmul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

function gdiv(a: number, b: number): number {
  if (b === 0) throw new Error('division by zero in GF(256)');
  if (a === 0) return 0;
  return EXP[(LOG[a] - LOG[b] + 255) % 255];
}

/** Evaluate polynomial (coeffs low->high) at x in GF(256). */
function evalPoly(coeffs: Uint8Array, x: number): number {
  let result = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    result = gmul(result, x) ^ coeffs[i];
  }
  return result;
}

export function split(secret: Buffer, k: number, n: number): Buffer[] {
  if (k < 2) throw new Error('threshold k must be >= 2');
  if (n < k) throw new Error('n must be >= k');
  if (n > 255) throw new Error('n must be <= 255');

  const shares: Buffer[] = [];
  for (let i = 1; i <= n; i++) {
    shares.push(Buffer.alloc(1 + secret.length));
    shares[i - 1][0] = i; // x-coordinate
  }

  for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
    // Random polynomial: constant term = secret byte; k-1 random coefficients.
    const coeffs = new Uint8Array(k);
    coeffs[0] = secret[byteIdx];
    const rnd = crypto.randomBytes(k - 1);
    for (let c = 1; c < k; c++) coeffs[c] = rnd[c - 1];

    for (let i = 1; i <= n; i++) {
      shares[i - 1][1 + byteIdx] = evalPoly(coeffs, i);
    }
  }
  return shares;
}

export function combine(shares: Buffer[]): Buffer {
  if (shares.length < 2) throw new Error('need at least 2 shares');
  const len = shares[0].length - 1;
  for (const s of shares) {
    if (s.length - 1 !== len) throw new Error('inconsistent share lengths');
  }
  const xs = shares.map((s) => s[0]);
  // x=0 is the secret's own evaluation point; a share at x=0 would let one crafted
  // share dictate the result. Valid shares use x in 1..n (split() starts at 1).
  if (xs.some((x) => x === 0)) throw new Error('invalid share index 0');
  if (new Set(xs).size !== xs.length) throw new Error('duplicate share indices');

  const secret = Buffer.alloc(len);
  for (let byteIdx = 0; byteIdx < len; byteIdx++) {
    // Lagrange interpolation at x=0.
    let acc = 0;
    for (let i = 0; i < shares.length; i++) {
      const xi = xs[i];
      const yi = shares[i][1 + byteIdx];
      let num = 1;
      let den = 1;
      for (let j = 0; j < shares.length; j++) {
        if (j === i) continue;
        const xj = xs[j];
        num = gmul(num, xj); // (0 - xj) == xj in GF(2^8)
        den = gmul(den, xi ^ xj);
      }
      acc ^= gmul(yi, gdiv(num, den));
    }
    secret[byteIdx] = acc;
  }
  return secret;
}
