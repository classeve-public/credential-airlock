/**
 * Master Recovery Key (MRK) + Shamir share management for migration/recovery.
 *
 * SEPARATION OF POWERS (the core design requirement):
 *   - "use the key"  = daily, machine-bound, automatic. Uses VDK via vdk.seal.
 *                      The MRK is NEVER reconstructed during normal operation.
 *   - "move the key" = deliberate, human-bound. Needs K-of-N shares to rebuild
 *                      the MRK, derive VDK, and re-seal to a new machine.
 *
 * Default scheme = 2-of-3:
 *   share 1 (dpapi)      sealed to THIS machine    — enables nothing alone
 *   share 2 (passphrase) scrypt + AES-GCM          — a human factor
 *   share 3 (offline)    printed QR / text in a safe — a human factor
 * On a NEW machine the dpapi share cannot unseal, so migration requires BOTH
 * human factors. One compromised machine can never migrate silently.
 */
import * as crypto from 'crypto';
import * as path from 'path';
import { Sealer, MigrationManifest, ShareMeta } from '../types';
import { hkdf, scryptKey } from '../crypto/hkdf';
import { aesgcmEncrypt, aesgcmDecrypt } from '../crypto/aesgcm';
import * as shamir from '../crypto/shamir';
import { Paths } from '../config';
import { atomicWrite, readFileOpt, writeJson, readJson, ensureDir } from '../util/fsx';

const VDK_INFO = 'credential-airlock/vdk/v1';
const MRK_LEN = 32;

export function generateMrk(): Buffer {
  return crypto.randomBytes(MRK_LEN);
}

export function deriveVdk(mrk: Buffer, vdkSalt: Buffer): Buffer {
  return hkdf(mrk, vdkSalt, VDK_INFO, 32);
}

// --- offline share encoding (checksummed, human-transcribable) -------------
export function encodeOfflineShare(share: Buffer): string {
  const sum = crypto.createHash('sha256').update(share).digest().subarray(0, 3).toString('hex');
  return `CA1-${share.toString('base64url')}-${sum}`;
}

export function decodeOfflineShare(text: string): Buffer {
  const m = text.trim().match(/^CA1-([A-Za-z0-9_-]+)-([0-9a-f]{6})$/);
  if (!m) throw new Error('offline share is malformed (expected CA1-<data>-<checksum>)');
  const share = Buffer.from(m[1], 'base64url');
  const sum = crypto.createHash('sha256').update(share).digest().subarray(0, 3).toString('hex');
  if (sum !== m[2]) throw new Error('offline share checksum mismatch — check for transcription errors');
  return share;
}

export interface SetupResult {
  manifest: MigrationManifest;
  offlineShare: string; // CA1-... — display once, never stored
}

/**
 * Set up migration on the current machine. Generates an MRK, re-keys the vault's
 * VDK to be MRK-derived (caller must vault.rekey with the returned VDK), splits
 * the MRK, stores the dpapi + passphrase shares, and returns the offline share.
 */
export async function setupMigration(
  p: Paths,
  sealer: Sealer,
  opts: { passphrase: string; threshold?: number; total?: number }
): Promise<{ result: SetupResult; vdk: Buffer; vdkSalt: Buffer }> {
  const threshold = opts.threshold ?? 2;
  const total = opts.total ?? 3;
  if (total !== 3 || threshold !== 2) {
    // Other schemes are valid but the file layout below assumes 2-of-3 roles.
    if (threshold < 2 || total < threshold) throw new Error('invalid threshold/total');
  }
  if (!opts.passphrase || opts.passphrase.length < 12) {
    throw new Error('recovery passphrase must be at least 12 characters');
  }

  const mrk = generateMrk();
  const vdkSalt = crypto.randomBytes(16);
  const vdk = deriveVdk(mrk, vdkSalt);

  const shares = shamir.split(mrk, threshold, total); // x = 1,2,3
  mrk.fill(0);

  ensureDir(p.sharesDir);

  // Share 1 -> DPAPI (machine-bound)
  const dpapiSealed = await sealer.seal(shares[0]);
  atomicWrite(path.join(p.sharesDir, 'share-1.dpapi'), dpapiSealed);

  // Share 2 -> passphrase (scrypt + AES-GCM)
  const salt2 = crypto.randomBytes(16);
  const k2 = scryptKey(opts.passphrase, salt2);
  const blob2 = aesgcmEncrypt(k2, shares[1]);
  k2.fill(0);
  writeJson(path.join(p.sharesDir, 'share-2.pass.json'), {
    salt: salt2.toString('hex'),
    blob: blob2.toString('base64'),
  });

  // Share 3 -> offline (returned, not stored)
  const offlineShare = encodeOfflineShare(shares[2]);

  shares.forEach((s) => s.fill(0));

  const metas: ShareMeta[] = [
    { index: 1, kind: 'dpapi', createdAt: new Date().toISOString(), label: 'This machine (DPAPI)' },
    { index: 2, kind: 'passphrase', createdAt: new Date().toISOString(), label: 'Recovery passphrase' },
    { index: 3, kind: 'offline', createdAt: new Date().toISOString(), label: 'Offline share (safe)' },
  ];
  const manifest: MigrationManifest = {
    version: 1,
    threshold,
    total,
    shares: metas,
    vdkSalt: vdkSalt.toString('hex'),
    createdAt: new Date().toISOString(),
  };
  writeJson(p.manifest, manifest);

  return { result: { manifest, offlineShare }, vdk, vdkSalt };
}

export function loadManifest(p: Paths): MigrationManifest | null {
  return readJson<MigrationManifest>(p.manifest);
}

// --- share loaders (for reconstruction) ------------------------------------
export async function loadDpapiShare(p: Paths, sealer: Sealer): Promise<Buffer | null> {
  const sealed = readFileOpt(path.join(p.sharesDir, 'share-1.dpapi'));
  if (!sealed) return null;
  try {
    return await sealer.unseal(sealed); // fails on a different machine — that's intended
  } catch {
    return null;
  }
}

export function loadPassphraseShare(p: Paths, passphrase: string): Buffer | null {
  const j = readJson<{ salt: string; blob: string }>(path.join(p.sharesDir, 'share-2.pass.json'));
  if (!j) return null;
  const salt = Buffer.from(j.salt, 'hex');
  const key = scryptKey(passphrase, salt);
  try {
    return aesgcmDecrypt(key, Buffer.from(j.blob, 'base64'));
  } catch {
    throw new Error('wrong recovery passphrase, or passphrase share corrupted');
  } finally {
    key.fill(0);
  }
}

export function combineToMrk(shares: Buffer[]): Buffer {
  return shamir.combine(shares);
}
