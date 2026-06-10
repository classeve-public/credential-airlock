#!/usr/bin/env node
/**
 * Credential Airlock CLI + daemon.
 *
 *   airlock init                 initialize the vault (sealed to this machine)
 *   airlock start                run the airlock (proxy + local UI) and open it
 *   airlock run -- <cmd...>      run any command through the airlock
 *   airlock secret set <name> ... / list / rm / rotate
 *   airlock policy show
 *   airlock audit [--verify] [--limit N]
 *   airlock agent add/list/rm
 *   airlock migrate setup|import ...
 *   airlock ca | status | doctor | env
 */
import { spawn } from 'child_process';
import * as net from 'net';
import { paths as makePaths, isInitialized, loadConfig } from './config';
import { Runtime } from './runtime';
import { AdminServer } from './admin/server';
import { migrateImport } from './migrate/ceremony';
import { createSealer, autoSealerKind } from './crypto/sealer';
import { dpapiSelfTest } from './crypto/dpapi';
import { InjectionSpec, InjectionMode } from './types';
import { log } from './util/logger';

const P = makePaths();

interface Parsed {
  _: string[];
  flags: Record<string, string | string[] | boolean>;
}

function parseArgs(argv: string[]): Parsed {
  const _: string[] = [];
  const flags: Record<string, string | string[] | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') {
      flags['--rest'] = argv.slice(i + 1);
      break;
    }
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        flags[key] = true;
      } else {
        const cur = flags[key];
        if (cur === undefined) flags[key] = next;
        else if (Array.isArray(cur)) cur.push(next);
        else flags[key] = [cur as string, next];
        i++;
      }
    } else {
      _.push(a);
    }
  }
  return { _, flags };
}

const asArray = (v: string | string[] | boolean | undefined): string[] =>
  v === undefined || typeof v === 'boolean' ? [] : Array.isArray(v) ? v : [v];
const asStr = (v: string | string[] | boolean | undefined): string | undefined =>
  typeof v === 'string' ? v : Array.isArray(v) ? v[0] : undefined;

function die(msg: string): never {
  process.stderr.write(`error: ${msg}\n`);
  process.exit(1);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString('utf8').trim();
}

function portFree(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.once('listening', () => s.close(() => resolve(true)));
    s.listen(port, host);
  });
}

function openBrowser(url: string): void {
  try {
    let child;
    if (process.platform === 'win32') child = spawn('cmd', ['/c', 'start', '""', url], { detached: true, windowsHide: true });
    else if (process.platform === 'darwin') child = spawn('open', [url], { detached: true });
    else child = spawn('xdg-open', [url], { detached: true });
    child.on('error', () => {}); // a missing launcher must not crash the daemon
    child.unref?.();
  } catch {
    /* non-fatal */
  }
}

const USAGE = `Credential Airlock — a self-hosted credential firewall for AI agents

USAGE
  airlock init [--passphrase <p>]
  airlock start                         start proxy + local UI (opens browser)
  airlock run -- <command...>           run a command routed through the airlock
  airlock status
  airlock doctor                        environment self-test
  airlock ca                            show CA cert path + trust instructions
  airlock env                           print env vars to route a shell's traffic

  airlock secret set <name> (--value <v> | --stdin) --host <h> [--host <h2> ...]
        [--mode header|placeholder|query] [--header <H>] [--template "Bearer {{secret}}"]
        [--placeholder __NAME__] [--in-body] [--query-param <p>] [--desc <text>]
  airlock secret list
  airlock secret rm <name>
  airlock secret rotate <name> (--value <v> | --stdin)

  airlock policy show
  airlock audit [--limit <n>] [--verify]

  airlock agent add --name <n> --command <c> [--arg <a> ...] [--cwd <d>]
  airlock agent list | rm <id>

  airlock migrate setup --passphrase <p>
  airlock migrate import --passphrase <p> --offline-share <s> [--delay <sec>]

Data dir: ${P.root}
`;

async function ensureRuntime(): Promise<Runtime> {
  if (!isInitialized(P)) log.info('not initialized — running first-time init');
  // openOrInit takes the single-writer lock BEFORE deciding init-vs-open.
  return Runtime.openOrInit(P);
}

async function cmdStart(): Promise<void> {
  if (!(await portFree('127.0.0.1', Number(process.env.AIRLOCK_PROXY_PORT) || 7788))) {
    log.warn('proxy port appears busy — another airlock may be running');
  }
  const rt = await ensureRuntime(); // openOrInit already holds the single-writer lock
  await rt.startProxy();
  const admin = new AdminServer(rt);
  await admin.start();

  const banner = [
    '',
    '  ==================================================================',
    '   CREDENTIAL AIRLOCK is running',
    '  ==================================================================',
    '',
    `   Proxy (point agents here): http://${rt.config.proxyHost}:${rt.config.proxyPort}`,
    `   Control panel:             ${admin.url}`,
    `   Sealer:                    ${rt.sealer.info.description}`,
    `   CA cert (trust this):      ${rt.paths.caCertExport}`,
    '',
    '   Press Ctrl+C to stop.',
    '',
  ].join('\n');
  process.stdout.write(banner + '\n');
  if (!process.env.AIRLOCK_NO_OPEN) openBrowser(admin.url);

  const shutdown = async () => {
    log.info('shutting down…');
    try {
      await admin.stop();
      await rt.stopProxy();
      rt.close();
    } finally {
      process.exit(0);
    }
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  // Keep the credential firewall up even if a stray async error fires.
  process.on('uncaughtException', (e) => log.error('uncaught exception (daemon kept alive)', { err: String(e) }));
  process.on('unhandledRejection', (e) => log.error('unhandled rejection (daemon kept alive)', { err: String(e) }));
}

async function cmdRun(rest: string[]): Promise<void> {
  if (!rest.length) die('usage: airlock run -- <command> [args...]');
  const rt = await ensureRuntime(); // openOrInit already holds the single-writer lock
  await rt.startProxy();
  process.on('uncaughtException', (e) => log.error('uncaught exception (kept alive)', { err: String(e) }));
  process.on('unhandledRejection', (e) => log.error('unhandled rejection (kept alive)', { err: String(e) }));
  const [cmd, ...cmdArgs] = rest;
  log.info(`running through airlock: ${cmd} ${cmdArgs.join(' ')}`);
  const child = spawn(cmd, cmdArgs, { stdio: 'inherit', env: { ...process.env, ...rt.wiredEnv() }, shell: process.platform === 'win32' });
  child.on('error', (e) => die(`failed to launch: ${e.message}`));
  child.on('exit', async (code) => {
    await rt.stopProxy();
    rt.close();
    process.exit(code ?? 0);
  });
}

function buildInjection(name: string, f: Parsed['flags']): InjectionSpec {
  const explicitMode = asStr(f.mode) as InjectionMode | undefined;
  const mode: InjectionMode = explicitMode || (f.placeholder ? 'placeholder' : 'header');
  if (mode === 'placeholder') {
    return {
      mode,
      placeholder: asStr(f.placeholder) || `__${name.toUpperCase()}__`,
      injectInBody: !!f['in-body'],
      valueTemplate: asStr(f.template),
    };
  }
  if (mode === 'query') {
    return { mode, queryParam: asStr(f['query-param']) || 'api_key' };
  }
  return { mode: 'header', header: asStr(f.header) || 'Authorization', valueTemplate: asStr(f.template) || 'Bearer {{secret}}' };
}

async function cmdSecret(parsed: Parsed): Promise<void> {
  const sub = parsed._[1];
  if (sub === 'list') {
    const rt = await Runtime.open(P);
    const list = rt.vault.listSecrets();
    rt.close();
    if (!list.length) {
      process.stdout.write('no secrets yet.\n');
      return;
    }
    for (const s of list) {
      process.stdout.write(`• ${s.name}  [${s.injection.mode}]  -> ${s.allowedHosts.join(', ')}  (placeholder ${s.placeholder})\n`);
    }
    return;
  }
  if (sub === 'set') {
    const name = parsed._[2];
    if (!name) die('usage: airlock secret set <name> ...');
    const hosts = asArray(parsed.flags.host);
    if (!hosts.length) die('--host is required (one or more). A secret is only ever injected toward these hosts.');
    let value = asStr(parsed.flags.value);
    if (parsed.flags.stdin) value = await readStdin();
    if (!value) die('provide --value <v> or --stdin');
    // openOrInit locks before deciding init-vs-open and NEVER wipes an existing vault
    // (Vault.create refuses if one exists), so a transient open failure can't clobber it.
    const rt = await Runtime.openOrInit(P);
    try {
      rt.addOrUpdateSecret({
        name,
        placeholder: asStr(parsed.flags.placeholder) || `__${name.toUpperCase()}__`,
        allowedHosts: hosts,
        injection: buildInjection(name, parsed.flags),
        description: asStr(parsed.flags.desc),
        value,
      });
    } finally {
      rt.close();
    }
    process.stdout.write(`secret '${name}' stored (sealed) and policy updated for ${hosts.join(', ')}\n`);
    return;
  }
  if (sub === 'rotate') {
    const name = parsed._[2];
    if (!name) die('usage: airlock secret rotate <name> --value <v>');
    let value = asStr(parsed.flags.value);
    if (parsed.flags.stdin) value = await readStdin();
    if (!value) die('provide --value <v> or --stdin');
    const rt = await Runtime.open(P);
    try {
      rt.acquireLock();
      rt.rotateSecret(name, value);
    } finally {
      rt.close();
    }
    process.stdout.write(`secret '${name}' rotated (agents unaffected — they use the dummy)\n`);
    return;
  }
  if (sub === 'rm') {
    const name = parsed._[2];
    if (!name) die('usage: airlock secret rm <name>');
    const rt = await Runtime.open(P);
    try {
      rt.acquireLock();
      rt.deleteSecret(name);
    } finally {
      rt.close();
    }
    process.stdout.write(`secret '${name}' deleted\n`);
    return;
  }
  die('unknown secret subcommand. try: set | list | rm | rotate');
}

async function cmdAgent(parsed: Parsed): Promise<void> {
  const sub = parsed._[1];
  const rt = await Runtime.open(P);
  try {
    if (sub === 'add' || sub === 'rm') rt.acquireLock();
    if (sub === 'list') {
      if (!rt.config.agents.length) process.stdout.write('no agents registered.\n');
      for (const a of rt.config.agents) process.stdout.write(`• ${a.id}  ${a.name}: ${a.command} ${a.args.join(' ')}\n`);
      return;
    }
    if (sub === 'add') {
      const name = asStr(parsed.flags.name);
      const command = asStr(parsed.flags.command);
      if (!name || !command) die('usage: airlock agent add --name <n> --command <c> [--arg <a> ...]');
      const a = rt.upsertAgent({ name, command, args: asArray(parsed.flags.arg), cwd: asStr(parsed.flags.cwd) });
      process.stdout.write(`agent '${a.name}' added (id ${a.id}). Launch it from the UI or: airlock run -- ${command} ...\n`);
      return;
    }
    if (sub === 'rm') {
      const id = parsed._[2];
      if (!id) die('usage: airlock agent rm <id>');
      rt.removeAgent(id);
      process.stdout.write('agent removed\n');
      return;
    }
    die('unknown agent subcommand. try: add | list | rm');
  } finally {
    rt.close();
  }
}

async function cmdMigrate(parsed: Parsed): Promise<void> {
  const sub = parsed._[1];
  if (sub === 'setup') {
    const pass = asStr(parsed.flags.passphrase);
    if (!pass) die('usage: airlock migrate setup --passphrase <p>  (min 12 chars)');
    const rt = await Runtime.open(P);
    let out!: { offlineShare: string };
    try {
      rt.acquireLock();
      out = await rt.setupMigration(pass);
    } finally {
      rt.close();
    }
    process.stdout.write(
      [
        '',
        'Migration is now configured (2-of-3).',
        ' • share 1: sealed to THIS machine (DPAPI)',
        ' • share 2: your recovery passphrase',
        ' • share 3: the OFFLINE share below — PRINT IT and store it in a safe.',
        '',
        'OFFLINE RECOVERY SHARE (shown once, never stored):',
        '',
        '   ' + out.offlineShare,
        '',
        'Back up the data dir to migrate later. On a new machine you will need the',
        'passphrase AND this offline share. Keep them apart.',
        '',
      ].join('\n')
    );
    return;
  }
  if (sub === 'import') {
    const res = await migrateImport(P, {
      passphrase: asStr(parsed.flags.passphrase),
      offlineShare: asStr(parsed.flags['offline-share']),
      delaySec: Number(asStr(parsed.flags.delay)) || 0,
    });
    if (!res.ok) die(res.reason || 'migration failed');
    process.stdout.write(
      `vault migrated to this machine (shares: ${res.sharesUsed.join(', ')}).\n` +
        'STRONGLY recommended: rotate the upstream provider keys now (belt and suspenders).\n'
    );
    return;
  }
  die('usage: airlock migrate setup|import ...');
}

async function cmdDoctor(): Promise<void> {
  const out: string[] = ['Credential Airlock — doctor', ''];
  out.push(`platform: ${process.platform} ${process.arch}, node ${process.version}`);
  out.push(`data dir: ${P.root}`);
  out.push(`initialized: ${isInitialized(P)}`);
  let cfg = null;
  try {
    cfg = loadConfig(P);
  } catch (e) {
    out.push(`config.json: CORRUPT — ${String(e)} (restore from backup or re-init)`);
  }
  const kind = cfg?.sealer || autoSealerKind();
  out.push(`sealer: ${kind}${cfg ? ' (recorded in config)' : ' (auto; not yet initialized)'}`);
  if (process.env.AIRLOCK_SEALER) {
    out.push(`note: AIRLOCK_SEALER=${process.env.AIRLOCK_SEALER} is set — honored ONLY at first init, never silently on open`);
  }
  if (kind === 'dpapi') out.push(`DPAPI round-trip self-test: ${dpapiSelfTest() ? 'OK' : 'FAILED'}`);
  if (kind === 'passphrase') {
    out.push('sealer create: passphrase sealer (requires AIRLOCK_PASSPHRASE at runtime)');
  } else {
    try {
      createSealer(kind);
      out.push('sealer create: OK');
    } catch (e) {
      out.push(`sealer create: FAILED — ${String(e)}`);
    }
  }
  out.push(`proxy port 7788 free: ${await portFree('127.0.0.1', 7788)}`);
  out.push(`admin port 7800 free: ${await portFree('127.0.0.1', 7800)}`);
  process.stdout.write(out.join('\n') + '\n');
}

async function cmdEnv(): Promise<void> {
  const rt = await Runtime.open(P);
  const env = rt.wiredEnv();
  rt.close();
  const isPwsh = process.platform === 'win32';
  for (const [k, v] of Object.entries(env)) {
    process.stdout.write(isPwsh ? `$env:${k}="${v}"\n` : `export ${k}="${v}"\n`);
  }
}

async function main(): Promise<void> {
  const parsed = parseArgs(process.argv.slice(2));
  const cmd = parsed._[0];
  switch (cmd) {
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      process.stdout.write(USAGE);
      return;
    case 'init': {
      if (isInitialized(P)) {
        process.stdout.write(`already initialized at ${P.root}\n`);
        return;
      }
      const rt = await Runtime.initNew(P, { passphrase: asStr(parsed.flags.passphrase) });
      process.stdout.write(`initialized at ${P.root}\nsealer: ${rt.sealer.info.description}\nnext: airlock secret set ... then airlock start\n`);
      rt.close();
      return;
    }
    case 'start':
    case 'up':
      return cmdStart();
    case 'run':
      return cmdRun((parsed.flags['--rest'] as string[]) || []);
    case 'status': {
      const rt = await Runtime.open(P);
      process.stdout.write(JSON.stringify(rt.status(), null, 2) + '\n');
      rt.close();
      return;
    }
    case 'secret':
      return cmdSecret(parsed);
    case 'policy': {
      const rt = await Runtime.open(P);
      process.stdout.write(JSON.stringify(rt.getPolicy(), null, 2) + '\n');
      rt.close();
      return;
    }
    case 'audit': {
      const rt = await Runtime.open(P);
      if (parsed.flags.verify) {
        process.stdout.write(JSON.stringify(rt.audit.verify(), null, 2) + '\n');
      } else {
        const limit = Number(asStr(parsed.flags.limit)) || 50;
        for (const e of rt.audit.read(limit)) {
          process.stdout.write(
            `#${e.seq} ${e.ts} ${e.event} ${e.method || ''} ${e.host || ''}${e.path || ''} -> ${e.decision || ''} ${e.reason || ''}\n`
          );
        }
      }
      rt.close();
      return;
    }
    case 'agent':
      return cmdAgent(parsed);
    case 'migrate':
      return cmdMigrate(parsed);
    case 'ca': {
      process.stdout.write(
        `CA cert: ${P.caCertExport}\n\n` +
          'Trust it so your agents accept intercepted TLS:\n' +
          '  • Node:   set NODE_EXTRA_CA_CERTS to the path above\n' +
          '  • Python: set REQUESTS_CA_BUNDLE / SSL_CERT_FILE to the bundle in the data dir\n' +
          '  • Or import airlock-ca.crt into your OS trust store.\n' +
          '  (airlock run / the launcher wire these automatically.)\n'
      );
      return;
    }
    case 'doctor':
      return cmdDoctor();
    case 'env':
      return cmdEnv();
    default:
      die(`unknown command '${cmd}'. run 'airlock help'.`);
  }
}

main().catch((e) => die(e instanceof Error ? e.message : String(e)));
