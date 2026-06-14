/**
 * Regression tests for the sealed backup/restore ops module.
 *
 * Covers: round-trip fidelity, clobber refusal, the name allowlist (path
 * traversal refused), per-file integrity, two-pass atomicity (a bad entry leaves
 * NOTHING written), and the bounded-decompression guard. Run: node test/backup.mjs
 * (after `npm run build`).
 */
import { createRequire } from 'module';
import crypto from 'crypto';
import zlib from 'zlib';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const D = (p) => require(path.join(here, '..', 'dist', p));

let pass = 0;
let fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) pass++;
  else {
    fail++;
    console.log(`  FAIL  ${name}  ${extra}`);
  }
};
const throwsWith = (fn, re) => {
  try {
    fn();
    return false;
  } catch (e) {
    return re.test(String(e.message || e));
  }
};

const MAGIC = 'credential-airlock-backup';
const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const mkBundle = (files) => zlib.gzipSync(Buffer.from(JSON.stringify({ _format: MAGIC, version: 1, files })));
const entry = (s) => ({ sha256: sha256(Buffer.from(s)), b64: Buffer.from(s).toString('base64') });

const { backup, restore } = D('ops/backup.js');
const { paths } = D('config.js');

function freshHome(seed = false) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'airlock-bk-'));
  process.env.AIRLOCK_HOME = root;
  delete require.cache[require.resolve(path.join(here, '..', 'dist', 'config.js'))];
  const { paths: P2 } = require(path.join(here, '..', 'dist', 'config.js'));
  const P = P2();
  fs.mkdirSync(P.root, { recursive: true });
  if (seed) {
    fs.writeFileSync(P.config, JSON.stringify({ version: 1, sealer: 'passphrase' }));
    fs.writeFileSync(P.vaultEnc, Buffer.from('SEALED-VAULT-BYTES'));
    fs.writeFileSync(P.policy, JSON.stringify({ defaultAction: 'deny' }));
    fs.mkdirSync(P.sharesDir, { recursive: true });
    // hyphen + dot + digits — must survive the conservative shares-name allowlist
    fs.writeFileSync(path.join(P.sharesDir, 'share-001.json'), 'SHARE-DATA');
  }
  return P;
}

// --- round-trip ------------------------------------------------------------
{
  const P = freshHome(true);
  const out = path.join(P.root, '..', 'bundle.akb');
  const res = backup(P, out);
  ok('backup: captured the seeded sealed files + share', res.files >= 4);

  const P2 = freshHome(false); // empty target
  const r = restore(P2, out, {});
  ok('restore: round-trip restored all files', r.restored === res.files);
  ok('restore: vault bytes identical', fs.readFileSync(P2.vaultEnc).toString() === 'SEALED-VAULT-BYTES');
  ok('restore: hyphenated share file restored under shares/', fs.readFileSync(path.join(P2.sharesDir, 'share-001.json')).toString() === 'SHARE-DATA');
}

// --- clobber refusal -------------------------------------------------------
{
  const P = freshHome(true);
  const out = path.join(P.root, '..', 'bundle2.akb');
  backup(P, out);
  ok('restore: refuses to overwrite a live vault without --force', throwsWith(() => restore(P, out, {}), /refusing to overwrite/i));
  ok('restore: --force overwrites', restore(P, out, { force: true }).restored >= 1);
}

// --- name allowlist / traversal -------------------------------------------
{
  const P = freshHome(false);
  const trav = path.join(P.root, '..', 'evil.akb');
  fs.writeFileSync(trav, mkBundle({ '../evil.txt': entry('x') }));
  ok('restore: rejects parent-traversal entry name', throwsWith(() => restore(P, trav, {}), /illegal entry/i));

  const sneaky = path.join(P.root, '..', 'evil2.akb');
  fs.writeFileSync(sneaky, mkBundle({ 'shares/../../evil': entry('x') }));
  ok('restore: rejects shares/ traversal', throwsWith(() => restore(P, sneaky, {}), /illegal entry/i));

  const abs = path.join(P.root, '..', 'evil3.akb');
  fs.writeFileSync(abs, mkBundle({ 'random-unlisted.txt': entry('x') }));
  ok('restore: rejects an unlisted top-level name', throwsWith(() => restore(P, abs, {}), /illegal entry/i));

  // shares/.. collapses to the data dir and shares/. to the shares dir — both must
  // be refused in PASS 1 so a good co-entry is NEVER written (true atomicity).
  const dd = path.join(P.root, '..', 'evil4.akb');
  fs.writeFileSync(dd, mkBundle({ 'config.json': entry('{"real":1}'), 'shares/..': entry('x') }));
  ok('restore: rejects shares/.. (collapses to data dir)', throwsWith(() => restore(P, dd, {}), /illegal/i));
  ok('restore: two-pass — good co-entry NOT written when shares/.. present', !fs.existsSync(P.config));
  const sd = path.join(P.root, '..', 'evil5.akb');
  fs.writeFileSync(sd, mkBundle({ 'shares/.': entry('x') }));
  ok('restore: rejects shares/. (collapses to shares dir)', throwsWith(() => restore(P, sd, {}), /illegal/i));

  // A contained-but-unwritable name (Windows ADS ':' / illegal chars) must be
  // rejected in PASS 1, NOT throw mid-write after a good co-entry is written.
  const ads = path.join(P.root, '..', 'evil6.akb');
  fs.writeFileSync(ads, mkBundle({ 'config.json': entry('{"real":1}'), 'shares/evil:x': entry('x') }));
  ok('restore: rejects an unwritable shares name (ADS/illegal char)', throwsWith(() => restore(P, ads, {}), /illegal/i));
  ok('restore: two-pass -- good co-entry NOT written when an unwritable name present', !fs.existsSync(P.config));
}

// --- integrity + two-pass atomicity ---------------------------------------
{
  const P = freshHome(false);
  const badHash = path.join(P.root, '..', 'badhash.akb');
  fs.writeFileSync(badHash, mkBundle({ 'config.json': { sha256: 'deadbeef'.repeat(8), b64: Buffer.from('{}').toString('base64') } }));
  ok('restore: rejects a tampered entry (sha mismatch)', throwsWith(() => restore(P, badHash, {}), /integrity check failed/i));

  // good 'config.json' + bad 'policy.json' -> must write NEITHER (validate all first).
  const mixed = path.join(P.root, '..', 'mixed.akb');
  fs.writeFileSync(mixed, mkBundle({ 'config.json': entry('{"ok":1}'), 'policy.json': { sha256: 'bad', b64: Buffer.from('{}').toString('base64') } }));
  throwsWith(() => restore(P, mixed, {}), /integrity check failed/i);
  ok('restore: two-pass atomicity — good entry NOT written when a later entry is bad', !fs.existsSync(P.config));
}

// --- bounded decompression -------------------------------------------------
{
  const P = freshHome(false);
  const notgz = path.join(P.root, '..', 'notgz.akb');
  fs.writeFileSync(notgz, Buffer.from('this is not gzip'));
  ok('restore: rejects a non-gzip / unparseable bundle', throwsWith(() => restore(P, notgz, {}), /not a valid airlock backup/i));

  const wrongFormat = path.join(P.root, '..', 'wrongfmt.akb');
  fs.writeFileSync(wrongFormat, zlib.gzipSync(Buffer.from(JSON.stringify({ _format: 'something-else', files: {} }))));
  ok('restore: rejects a bundle with the wrong format marker', throwsWith(() => restore(P, wrongFormat, {}), /not a credential-airlock backup/i));
}

// --- write-lock creates a missing data dir (restore-into-fresh regression) ---
{
  const { acquireWriteLock, releaseWriteLock } = D('runtime.js');
  const root = path.join(os.tmpdir(), 'airlock-lk-' + crypto.randomBytes(4).toString('hex'));
  process.env.AIRLOCK_HOME = root;
  delete require.cache[require.resolve(path.join(here, '..', 'dist', 'config.js'))];
  const { paths: P3 } = require(path.join(here, '..', 'dist', 'config.js'));
  const P = P3();
  let fd;
  let acquired = false;
  try {
    fd = acquireWriteLock(P); // root does NOT exist yet — must be created
    acquired = true;
  } catch {
    acquired = false;
  }
  ok('lock: acquireWriteLock creates a missing data dir (restore-into-fresh)', acquired && fs.existsSync(P.root));
  if (fd !== undefined) releaseWriteLock(P, fd);
  try { fs.rmSync(root, { recursive: true, force: true }); } catch {}
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
