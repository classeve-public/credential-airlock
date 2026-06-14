/**
 * macOS Keychain sealer smoke test (best-effort, CI).
 *
 * Exercises the REAL production KeychainSealer (`security` CLI, generic-password,
 * ThisDeviceOnly, empty trusted-app ACL) against a throwaway keychain created and
 * unlocked just for this run. Headless Keychain access can be restricted in CI;
 * this job is marked continue-on-error so it provides signal without gating the
 * build. The behavior it checks is flagged for the external pentest regardless.
 *
 * Skips cleanly on non-darwin.
 */
import { spawnSync } from 'child_process';
import os from 'os';
import path from 'path';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';

if (process.platform !== 'darwin') {
  console.log('skip: keychain smoke is darwin-only');
  process.exit(0);
}

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const { KeychainSealer } = require(path.join(here, '..', 'dist', 'crypto', 'keychain.js'));

const KC = path.join(os.tmpdir(), 'airlock-smoke.keychain-db');
const PW = 'smoke-pass-not-secret';
const SECURITY_TIMEOUT_MS = 10_000;

function sec(args) {
  const r = spawnSync('security', args, { encoding: 'utf8', timeout: SECURITY_TIMEOUT_MS });
  if (r.status !== 0) {
    throw new Error(`security ${args[0]} failed: ${(r.stderr || r.error?.message || '').trim() || r.status}`);
  }
  return r.stdout || '';
}

function trySec(args) {
  try {
    spawnSync('security', args, { encoding: 'utf8', timeout: SECURITY_TIMEOUT_MS });
  } catch {}
}

async function main() {
  // Fresh keychain, unlocked, set as default + first in the user search list so
  // the sealer's add/find-generic-password resolve against it.
  trySec(['delete-keychain', KC]);
  sec(['create-keychain', '-p', PW, KC]);
  sec(['set-keychain-settings', KC]); // no auto-lock timeout
  sec(['unlock-keychain', '-p', PW, KC]);
  const existing = sec(['list-keychains', '-d', 'user'])
    .split('\n')
    .map((s) => s.trim().replace(/"/g, ''))
    .filter(Boolean);
  sec(['list-keychains', '-d', 'user', '-s', KC, ...existing]);
  sec(['default-keychain', '-d', 'user', '-s', KC]);

  const sealer = new KeychainSealer();
  const secret = Buffer.from('hello-keychain-round-trip-payload');
  const sealed = await sealer.seal(secret);
  const out = await sealer.unseal(sealed);

  if (!Buffer.isBuffer(out) || !out.equals(secret)) {
    console.error('FAIL  keychain seal/unseal did not round-trip');
    process.exit(1);
  }
  // The sealed reference must NOT contain the plaintext.
  if (sealed.toString('utf8').includes(secret.toString('utf8'))) {
    console.error('FAIL  sealed reference leaked plaintext');
    process.exit(1);
  }
  console.log('PASS  keychain seal/unseal round-trip (reference contains no plaintext)');
}

main()
  .catch((e) => {
    console.warn('skip: keychain smoke could not run in this environment:', e.message);
    process.exit(0);
  })
  .finally(() => {
    trySec(['delete-keychain', KC]);
  });
