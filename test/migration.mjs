/**
 * End-to-end migration / recovery ceremony test.
 *
 * Simulates moving the vault to a NEW machine:
 *   - "Old machine" (home A): passphrase sealer, sets up the 2-of-3 ceremony.
 *   - Back up the data dir to home B.
 *   - "New machine": the machine-bound (old) share cannot be unsealed by the new
 *     machine's sealer, so recovery must use BOTH human factors (recovery
 *     passphrase + offline share). We reconstruct, re-seal to the new machine,
 *     and confirm the ACTUAL secret value survived.
 *   - Negative: one human factor alone (or a wrong passphrase) must fail.
 *
 * Run: node test/migration.mjs  (after `npm run build`).
 */
import { createRequire } from 'module';
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

const SECRET = 'sk-MIGRATION-SECRET-9f3a2b';
const RECOVERY = 'correct horse battery staple recovery';
const OLD_DAILY = 'old-machine-daily-pass-AAAA';
const NEW_DAILY = 'new-machine-daily-pass-BBBB';

async function main() {
  const { Runtime } = D('runtime.js');
  const { paths } = D('config.js');
  const { migrateImport } = D('migrate/ceremony.js');

  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'airlock-mig-'));
  const homeA = path.join(base, 'A');
  const homeB = path.join(base, 'B'); // good recovery
  const homeC = path.join(base, 'C'); // negative: missing offline share
  const homeDdir = path.join(base, 'Dd'); // negative: wrong passphrase

  // --- Old machine: passphrase sealer, set up migration ---
  process.env.AIRLOCK_SEALER = 'passphrase';
  process.env.AIRLOCK_PASSPHRASE = OLD_DAILY;
  const PA = paths(homeA);
  const a = await Runtime.initNew(PA);
  a.addOrUpdateSecret({
    name: 'svc',
    placeholder: '__SVC__',
    allowedHosts: ['api.example.com'],
    injection: { mode: 'header', header: 'authorization', valueTemplate: 'Bearer {{secret}}' },
    value: SECRET,
  });
  const setup = await a.setupMigration(RECOVERY);
  a.close();
  ok('setup: produced an offline share', typeof setup.offlineShare === 'string' && setup.offlineShare.startsWith('CA1-'), setup.offlineShare);

  // --- Back up the data dir to the "new machine" (and two negative copies) ---
  fs.cpSync(homeA, homeB, { recursive: true });
  fs.cpSync(homeA, homeC, { recursive: true });
  fs.cpSync(homeA, homeDdir, { recursive: true });

  // --- New machine: use a different passphrase sealer to simulate a different
  //     machine/account. The old passphrase-sealed share cannot unseal with this
  //     new sealer -> migration must use both human factors. This keeps CI
  //     deterministic on Linux/macOS instead of invoking a real Keychain prompt.
  process.env.AIRLOCK_SEALER = 'passphrase';
  process.env.AIRLOCK_PASSPHRASE = NEW_DAILY;

  // Negative 1: only the recovery passphrase, no offline share -> below threshold.
  const PC = paths(homeC);
  const onlyPass = await migrateImport(PC, { passphrase: RECOVERY });
  ok('negative: passphrase alone cannot migrate (need 2-of-3)', onlyPass.ok === false, JSON.stringify(onlyPass));

  // Negative 2: wrong recovery passphrase + correct offline share -> still 1 share.
  const PD = paths(homeDdir);
  const wrongPass = await migrateImport(PD, { passphrase: 'totally-wrong-passphrase', offlineShare: setup.offlineShare });
  ok('negative: wrong passphrase cannot migrate', wrongPass.ok === false, JSON.stringify(wrongPass));

  // Positive: recovery passphrase + offline share -> reconstructs and re-seals.
  const PB = paths(homeB);
  const res = await migrateImport(PB, { passphrase: RECOVERY, offlineShare: setup.offlineShare });
  ok('migrate: succeeds with passphrase + offline share', res.ok === true, JSON.stringify(res));
  ok('migrate: did NOT rely on the old machine share', res.ok && !res.sharesUsed.includes('dpapi(local)'), JSON.stringify(res.sharesUsed));

  // --- Confirm the ACTUAL secret value survived on the new machine ---
  if (res.ok) {
    const b = await Runtime.open(PB, { passphrase: NEW_DAILY });
    const inj = b.vault.getInjectors().find((x) => x.name === 'svc');
    ok('migrate: secret value recovered intact on the new machine', !!inj && inj.value === SECRET, inj ? '(value mismatch)' : '(secret missing)');
    ok('migrate: secret metadata intact (allowed host)', !!inj && inj.allowedHosts.includes('api.example.com'));
    // The new machine can now open the vault automatically (re-sealed to its sealer).
    ok('migrate: config.sealer updated to the new machine sealer', b.config.sealer === b.sealer.info.kind);
    b.close();
  }

  try {
    fs.rmSync(base, { recursive: true, force: true });
  } catch {}

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => {
  console.error('migration test crashed:', e);
  process.exit(1);
});
