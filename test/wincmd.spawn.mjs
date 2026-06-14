/**
 * Windows-only proof: winCommandLine + spawn(shell:true) passes arguments
 * containing cmd metacharacters (& | < > ( ), WITHOUT an embedded double-quote)
 * to the child process LITERALLY — no cmd.exe command-splitting/injection.
 *
 * Skips on non-win32. The embedded-quote+metacharacter and literal %VAR% cases
 * are documented limitations in src/util/wincmd.ts and are intentionally not
 * asserted here (arguments are operator-configured, not adversary-controlled).
 */
import { spawnSync } from 'child_process';
import path from 'path';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';

if (process.platform !== 'win32') {
  console.log('skip: wincmd spawn proof is win32-only');
  process.exit(0);
}

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const { winCommandLine } = require(path.join(here, '..', 'dist', 'util', 'wincmd.js'));

let pass = 0;
let fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) pass++;
  else {
    fail++;
    console.log(`  FAIL  ${name}  ${extra}`);
  }
};

const printer = 'console.log("ARGV=" + JSON.stringify(process.argv.slice(1)))';
const cases = [
  ['plain'],
  ['two words'],
  ['a&b'],
  ['https://h/p?a=1&b=2'],
  ['x|y'],
  ['a<b'],
  ['c>d'],
  ['p(1)'],
  ['amp&end', 'second arg'],
];
for (const args of cases) {
  const line = winCommandLine(process.execPath, ['-e', printer, ...args]);
  const r = spawnSync(line, { shell: true, encoding: 'utf8' });
  const out = (r.stdout || '').trim().replace(/\r/g, '');
  ok(
    `spawn: ${JSON.stringify(args)} reaches child literally (no cmd splitting)`,
    out === 'ARGV=' + JSON.stringify(args),
    out || (r.stderr || '').trim().slice(0, 120)
  );
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
