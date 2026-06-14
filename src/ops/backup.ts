/**
 * Disaster-recovery backup/restore of the SEALED data dir.
 *
 * The bundle contains only already-sealed/non-secret files (the AES-GCM vault,
 * the sealed VDK, CA, audit, config, policy, migration manifest + shares). No
 * plaintext secret is ever read or written here. Each file is SHA-256 checksummed
 * and verified on restore; paths are constrained to the data dir.
 *
 * IMPORTANT: on Windows (DPAPI) and macOS (Keychain) the sealed VDK is bound to
 * the machine/account, so a backup restores on the SAME machine (recovery from
 * accidental deletion). To move to a NEW machine, use the migration ceremony.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as zlib from 'zlib';
import * as crypto from 'crypto';
import { Paths } from '../config';
import { atomicWrite } from '../util/fsx';

// Bound decompression so a tiny crafted bundle can't inflate to exhaust memory
// (parity with the proxy's bounded decompress). Real backups are KBs--low MBs.
const MAX_BUNDLE_BYTES = 128 * 1024 * 1024;

const MAGIC = 'credential-airlock-backup';

// Files that make up a vault, relative to the data dir. The lock (airlock.pid)
// is deliberately excluded.
const FILES = [
  'config.json',
  'vault.enc',
  'vdk.seal',
  'manifest.json',
  'policy.json',
  'audit.jsonl',
  'audit.tip.json',
  'audit.tamper.json',
  'admin-token',
  'airlock-ca.crt',
  'airlock-ca-bundle.pem',
];

interface FileRec {
  sha256: string;
  b64: string;
}
interface Bundle {
  _format: string;
  version: number;
  files: Record<string, FileRec>;
}

function sha256(b: Buffer): string {
  return crypto.createHash('sha256').update(b).digest('hex');
}

export function backup(paths: Paths, outPath: string): { files: number; bytes: number } {
  const files: Record<string, FileRec> = {};
  const add = (rel: string, abs: string): void => {
    const b = fs.readFileSync(abs);
    files[rel] = { sha256: sha256(b), b64: b.toString('base64') };
  };
  for (const name of FILES) {
    const fp = path.join(paths.root, name);
    if (fs.existsSync(fp) && fs.statSync(fp).isFile()) add(name, fp);
  }
  // Offline migration shares, if any.
  if (fs.existsSync(paths.sharesDir)) {
    for (const f of fs.readdirSync(paths.sharesDir)) {
      const fp = path.join(paths.sharesDir, f);
      if (fs.statSync(fp).isFile()) add(path.posix.join('shares', f), fp);
    }
  }
  const bundle: Bundle = { _format: MAGIC, version: 1, files };
  const gz = zlib.gzipSync(Buffer.from(JSON.stringify(bundle)));
  fs.writeFileSync(outPath, gz, { mode: 0o600 });
  return { files: Object.keys(files).length, bytes: gz.length };
}

function lstatOpt(p: string): fs.Stats | null {
  try {
    return fs.lstatSync(p);
  } catch {
    return null;
  }
}

// A backup entry name is permitted only if it is one of the known top-level
// files or a single-segment file under shares/. Anything else (nested dirs,
// traversal, absolute, or the '.'/'..' segments that collapse to the data dir or
// the shares dir itself) is refused outright.
function isAllowedName(name: string): boolean {
  if (FILES.includes(name)) return true;
  const m = /^shares\/([^/\\]+)$/.exec(name);
  if (!m) return false;
  const seg = m[1];
  // Conservative, cross-platform-writable allowlist for a share filename. Rejects
  // '.'/'..', a trailing dot, and any contained-but-UNWRITABLE name (Windows-
  // illegal chars / control chars / ADS ':' / spaces) which would otherwise
  // pass PASS 1 and then throw mid-PASS-2, breaking two-pass atomicity.
  if (!/^[A-Za-z0-9._-]+$/.test(seg)) return false;
  if (seg === '.' || seg === '..' || seg.endsWith('.')) return false;
  return true;
}

export function restore(paths: Paths, inPath: string, opts: { force?: boolean } = {}): { restored: number } {
  let bundle: Bundle;
  try {
    const json = zlib.gunzipSync(fs.readFileSync(inPath), { maxOutputLength: MAX_BUNDLE_BYTES });
    bundle = JSON.parse(json.toString('utf8')) as Bundle;
  } catch (e) {
    throw new Error(`not a valid airlock backup (gunzip/parse failed): ${String(e)}`);
  }
  if (!bundle || bundle._format !== MAGIC || typeof bundle.files !== 'object' || bundle.files === null) {
    throw new Error('not a credential-airlock backup');
  }
  const initialized = fs.existsSync(paths.config) && fs.existsSync(paths.vaultEnc);
  if (initialized && !opts.force) {
    throw new Error(`refusing to overwrite the live vault at ${paths.root} -- pass --force to replace it`);
  }
  const rootResolved = path.resolve(paths.root);
  const sharesResolved = path.resolve(paths.sharesDir);

  // PASS 1 -- validate every entry (name allowlist + path containment + integrity)
  // BEFORE writing anything, so a forged/corrupt bundle fails closed instead of
  // leaving a half-restored data dir.
  const prepared: Array<{ name: string; dest: string; buf: Buffer }> = [];
  for (const [name, rec] of Object.entries(bundle.files)) {
    if (typeof name !== 'string' || !isAllowedName(name)) throw new Error(`illegal entry in backup: ${name}`);
    if (!rec || typeof rec.b64 !== 'string' || typeof rec.sha256 !== 'string') throw new Error(`malformed entry: ${name}`);
    const buf = Buffer.from(rec.b64, 'base64');
    if (sha256(buf) !== rec.sha256) throw new Error(`integrity check failed for ${name}`);
    const dest = path.resolve(paths.root, name);
    // Must be a FILE strictly inside the data dir -- never the root or shares dir
    // itself (defense-in-depth against any '.'/'..' segment collapse).
    if (dest === rootResolved || dest === sharesResolved || !dest.startsWith(rootResolved + path.sep)) {
      throw new Error(`illegal path in backup: ${name}`);
    }
    prepared.push({ name, dest, buf });
  }

  // PASS 2 -- write. atomicWrite uses openSync(tmp,'wx')+rename, which (a) never
  // follows a pre-planted symlink at the destination (rename replaces the link
  // itself) and (b) won't clobber through a temp collision. We additionally
  // refuse to follow a symlink/junction at the destination or at shares/.
  fs.mkdirSync(paths.root, { recursive: true });
  const needShares = prepared.some((f) => f.name.startsWith('shares/'));
  if (needShares) {
    const st = lstatOpt(paths.sharesDir);
    if (st && st.isSymbolicLink()) throw new Error('refusing to restore: shares/ is a symlink/junction');
    if (st && !st.isDirectory()) throw new Error('refusing to restore: shares/ exists and is not a directory');
  }
  // Validate that NO destination is a pre-planted symlink BEFORE writing anything,
  // so a symlink at a later entry can't leave earlier entries half-written.
  for (const f of prepared) {
    const st = lstatOpt(f.dest);
    if (st && st.isSymbolicLink()) throw new Error(`refusing to overwrite a symlink at ${f.name}`);
  }
  // All entries validated -- create shares/ (now known not to be a symlink) and write.
  if (needShares && !lstatOpt(paths.sharesDir)) fs.mkdirSync(paths.sharesDir, { recursive: true });
  let restored = 0;
  for (const f of prepared) {
    atomicWrite(f.dest, f.buf, 0o600);
    restored++;
  }
  return { restored };
}
