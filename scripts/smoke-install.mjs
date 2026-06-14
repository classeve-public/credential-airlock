import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const npmExecPath = process.env.npm_execpath;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'credential-airlock-smoke-'));

function run(command, args, options = {}) {
  let file = command;
  let spawnArgs = args;

  if (process.platform === 'win32' && /\.(cmd|bat)$/i.test(command)) {
    file = process.env.ComSpec || 'cmd.exe';
    spawnArgs = ['/d', '/c', 'call', command, ...args];
  }

  const result = spawnSync(file, spawnArgs, {
    cwd: options.cwd || root,
    env: { ...process.env, ...options.env },
    stdio: 'inherit',
    shell: false,
  });

  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} exited with ${result.status}`);
  }
}

function runNpm(args, options = {}) {
  if (npmExecPath && fs.existsSync(npmExecPath)) {
    run(process.execPath, [npmExecPath, ...args], options);
    return;
  }
  run(npm, args, options);
}

try {
  runNpm(['pack', '--pack-destination', tmp]);

  const tarballs = fs.readdirSync(tmp).filter((name) => name.endsWith('.tgz'));
  if (tarballs.length !== 1) {
    throw new Error(`expected exactly one tarball, found ${tarballs.length}`);
  }

  const prefix = path.join(tmp, 'prefix');
  fs.mkdirSync(prefix);

  const tarball = path.join(tmp, tarballs[0]);
  runNpm(['install', '--prefix', prefix, tarball]);

  const bin = process.platform === 'win32'
    ? path.join(prefix, 'node_modules', '.bin', 'airlock.cmd')
    : path.join(prefix, 'node_modules', '.bin', 'airlock');
  const index = path.join(prefix, 'node_modules', 'credential-airlock', 'dist', 'index.js');

  if (!fs.existsSync(bin)) throw new Error(`installed bin is missing: ${bin}`);
  if (!fs.existsSync(index)) throw new Error(`installed CLI entry is missing: ${index}`);

  run(bin, ['help'], { cwd: prefix });
  run(process.execPath, [index, 'help'], { cwd: prefix });

  console.log(`install smoke ok: ${tarballs[0]}`);
} finally {
  if (process.env.AIRLOCK_KEEP_SMOKE === '1') {
    console.log(`kept smoke directory: ${tmp}`);
  } else {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}
