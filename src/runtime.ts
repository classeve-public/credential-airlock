/**
 * Runtime facade — the single coordinator the CLI and admin API both call.
 *
 * Owns the live objects (vault, policy engine, audit, approvals, proxy,
 * launcher) and the high-level operations that must stay consistent, e.g.
 * "add a secret" also opens egress for and adds an allow rule covering that
 * secret's hosts, so the product is turnkey while remaining deny-by-default.
 */
import * as path from 'path';
import * as tls from 'tls';
import * as fs from 'fs';
import { Paths, loadConfig, saveConfig, defaultConfig, isInitialized } from './config';
import { AirlockConfig, Policy, InjectionSpec, AgentProfile, Sealer, SealerKind } from './types';
import { createSealer, autoSealerKind } from './crypto/sealer';
import { Vault } from './vault/vault';
import { PolicyEngine } from './policy/policy';
import { Approvals } from './policy/approvals';
import { AuditLog } from './audit/audit';
import { AirlockProxy } from './proxy/proxy';
import { AgentLauncher } from './agents/launcher';
import { setupMigration, loadManifest } from './vault/mrk';
import { readJson, writeJson, atomicWrite, readFileOpt, ensureDir } from './util/fsx';
import { randomId } from './util/ids';
import { log } from './util/logger';

export function defaultPolicy(): Policy {
  return { defaultAction: 'deny', egressAllowlist: [], rules: [] };
}

const LOOPBACK = new Set(['127.0.0.1', '::1', '[::1]', 'localhost']);
function coerceLoopbackHost(host: string, label: string): string {
  if (LOOPBACK.has(host)) return host;
  log.warn(`${label} '${host}' is not a loopback address; coercing to 127.0.0.1 (control/data plane is loopback only)`);
  return '127.0.0.1';
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/**
 * Acquire the single-writer lock. 'wx' create is atomic; for a stale lock we
 * reclaim and then RE-READ to confirm we own it, so a concurrent reclaimer that
 * recreated the file makes us back off instead of both proceeding. The pid is
 * fsync'd before we expose the lock, so a reader never sees an empty pid file.
 */
function lockAcquire(lockPath: string): number {
  const claim = (): number => {
    const fd = fs.openSync(lockPath, 'wx');
    try {
      fs.writeSync(fd, String(process.pid));
      fs.fsyncSync(fd);
    } catch (e) {
      try {
        fs.closeSync(fd); // don't leak the descriptor if write/fsync fails
      } catch {
        /* ignore */
      }
      throw e;
    }
    return fd;
  };
  let fd: number;
  try {
    fd = claim();
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
    const raw = readFileOpt(lockPath);
    const pid = raw ? Number(raw.toString().trim()) : NaN;
    // If the lock names ANY live process, refuse (single-writer). Only a dead/empty
    // pid is reclaimable — a restart is a new process whose old pid is now dead.
    if (Number.isFinite(pid) && pid > 0 && isAlive(pid)) {
      throw new Error(
        `another airlock process (pid ${pid}) is running — manage secrets via its control panel, or stop it first`
      );
    }
    try {
      fs.unlinkSync(lockPath); // stale lock from a dead process / empty file
    } catch {
      /* ignore */
    }
    try {
      fd = claim();
    } catch {
      throw new Error('another airlock process is starting concurrently — retry in a moment');
    }
  }
  const back = readFileOpt(lockPath);
  if (!back || back.toString().trim() !== String(process.pid)) {
    try {
      fs.closeSync(fd);
    } catch {
      /* ignore */
    }
    throw new Error('lost a race for the airlock lock — another process won; retry');
  }
  return fd;
}

/** Release the lock, deleting the file only if it still names THIS process. */
function lockRelease(lockPath: string, fd: number): void {
  const back = readFileOpt(lockPath);
  try {
    fs.closeSync(fd);
  } catch {
    /* ignore */
  }
  if (back && back.toString().trim() === String(process.pid)) {
    try {
      fs.unlinkSync(lockPath);
    } catch {
      /* ignore */
    }
  }
}

export interface SecretInput {
  name: string;
  placeholder: string;
  allowedHosts: string[];
  injection: InjectionSpec;
  description?: string;
  value: string;
}

export class Runtime {
  proxy: AirlockProxy | null = null;
  readonly launcher = new AgentLauncher();
  private caBundlePath: string;
  private lockFd: number | null = null;

  private constructor(
    readonly paths: Paths,
    public config: AirlockConfig,
    readonly sealer: Sealer,
    readonly vault: Vault,
    readonly policy: PolicyEngine,
    readonly audit: AuditLog,
    readonly approvals: Approvals
  ) {
    this.caBundlePath = path.join(paths.root, 'airlock-ca-bundle.pem');
  }

  // --- lifecycle ----------------------------------------------------------
  static async initNew(paths: Paths, opts?: { passphrase?: string }): Promise<Runtime> {
    const cfg = defaultConfig();
    // AIRLOCK_SEALER is honored ONLY here (first init). Record the ACTUAL kind so
    // open() always rebuilds the exact sealer that protects the vault.
    const kind = (process.env.AIRLOCK_SEALER as SealerKind) || autoSealerKind();
    cfg.sealer = kind;
    const sealer = createSealer(kind, opts);
    const vault = await Vault.create(paths, sealer);
    saveConfig(paths, cfg);
    writeJson(paths.policy, defaultPolicy());
    const rt = await Runtime.attach(paths, cfg, sealer, vault);
    rt.audit.append({ event: 'system', reason: 'airlock initialized', detail: { sealer: sealer.info.kind } });
    return rt;
  }

  static async open(paths: Paths, opts?: { passphrase?: string }): Promise<Runtime> {
    const cfg = loadConfig(paths);
    if (!cfg) throw new Error('not initialized — run `airlock init`');
    const sealer = createSealer(cfg.sealer, opts);
    const vault = await Vault.open(paths, sealer);
    return Runtime.attach(paths, cfg, sealer, vault);
  }

  /**
   * Acquire the single-writer lock BEFORE deciding init-vs-open, then re-check
   * initialization under the lock. Closes the race where two concurrent first-run
   * processes both init a fresh vault. Used by the daemon and `secret set`.
   */
  static async openOrInit(paths: Paths, opts?: { passphrase?: string }): Promise<Runtime> {
    ensureDir(paths.root);
    const fd = lockAcquire(paths.lock);
    let rt: Runtime;
    try {
      rt = isInitialized(paths) ? await Runtime.open(paths, opts) : await Runtime.initNew(paths, opts);
    } catch (e) {
      lockRelease(paths.lock, fd);
      throw e;
    }
    rt.lockFd = fd; // transfer lock ownership to the runtime; close() releases it
    return rt;
  }

  private static async attach(paths: Paths, cfg: AirlockConfig, sealer: Sealer, vault: Vault): Promise<Runtime> {
    // Enforce loopback as an invariant regardless of config.json edits.
    cfg.adminHost = coerceLoopbackHost(cfg.adminHost, 'adminHost');
    cfg.proxyHost = coerceLoopbackHost(cfg.proxyHost, 'proxyHost');
    let policyData: Policy;
    try {
      policyData = readJson<Policy>(paths.policy) || defaultPolicy();
    } catch (e) {
      // Corrupt policy.json -> fail SAFE (deny-all) rather than bricking or failing open.
      log.error('policy.json is corrupt — failing safe to deny-all until it is fixed', { err: String(e) });
      policyData = defaultPolicy();
    }
    policyData.defaultAction = 'deny'; // enforce invariant regardless of file edits
    const engine = new PolicyEngine(policyData);
    const audit = new AuditLog(paths);
    const approvals = new Approvals();
    const rt = new Runtime(paths, cfg, sealer, vault, engine, audit, approvals);
    rt.writeCaFiles();
    return rt;
  }

  /** Write the CA cert (additive trust) and a full bundle (system roots + our CA), only if changed. */
  private writeCaFiles(): void {
    const caPem = this.vault.caCertPem;
    const bundle = tls.rootCertificates.join('\n') + '\n' + caPem + '\n';
    this.writeIfChanged(this.paths.caCertExport, caPem);
    this.writeIfChanged(this.caBundlePath, bundle);
  }

  private writeIfChanged(file: string, data: string): void {
    const cur = readFileOpt(file);
    if (cur && cur.toString('utf8') === data) return; // avoid clobbering on read-only commands
    atomicWrite(file, data, 0o644);
  }

  /**
   * Single-writer lock. The daemon (start/run) and mutating CLI commands acquire
   * it so two processes can never interleave writes to vault/policy/config and
   * silently lose updates. Held for the process lifetime by the daemon.
   */
  acquireLock(): void {
    if (this.lockFd !== null) return;
    this.lockFd = lockAcquire(this.paths.lock);
  }

  private releaseLock(): void {
    if (this.lockFd === null) return;
    lockRelease(this.paths.lock, this.lockFd);
    this.lockFd = null;
  }

  async startProxy(): Promise<void> {
    if (this.proxy) return;
    const proxy = new AirlockProxy({
      vault: this.vault,
      policy: this.policy,
      approvals: this.approvals,
      audit: this.audit,
      config: this.config,
    });
    await proxy.start();
    this.proxy = proxy;
    this.audit.append({ event: 'system', reason: 'proxy started' });
  }

  async stopProxy(): Promise<void> {
    if (!this.proxy) return;
    await this.proxy.stop();
    this.proxy = null;
    this.audit.append({ event: 'system', reason: 'proxy stopped' });
  }

  get proxyRunning(): boolean {
    return this.proxy !== null;
  }

  close(): void {
    try {
      this.launcher.stopAll();
      this.vault.close();
    } finally {
      this.releaseLock(); // always release the lock, even if teardown throws
    }
  }

  // --- env wiring for launched agents ------------------------------------
  wiredEnv(): Record<string, string> {
    const proxyUrl = `http://${this.config.proxyHost}:${this.config.proxyPort}`;
    return {
      HTTP_PROXY: proxyUrl,
      HTTPS_PROXY: proxyUrl,
      http_proxy: proxyUrl,
      https_proxy: proxyUrl,
      ALL_PROXY: proxyUrl,
      NO_PROXY: 'localhost,127.0.0.1,::1',
      no_proxy: 'localhost,127.0.0.1,::1',
      NODE_EXTRA_CA_CERTS: this.paths.caCertExport,
      REQUESTS_CA_BUNDLE: this.caBundlePath,
      SSL_CERT_FILE: this.caBundlePath,
      CURL_CA_BUNDLE: this.caBundlePath,
      AIRLOCK_ACTIVE: '1',
    };
  }

  // --- secrets (with policy maintenance) ---------------------------------
  addOrUpdateSecret(input: SecretInput): void {
    this.vault.setSecret(
      {
        name: input.name,
        placeholder: input.placeholder,
        allowedHosts: input.allowedHosts,
        injection: input.injection,
        description: input.description,
      },
      input.value
    );
    this.maintainPolicyForSecret(input.name, input.allowedHosts);
    this.refreshProxyCreds();
  }

  rotateSecret(name: string, value: string): void {
    this.vault.rotateSecret(name, value);
    this.refreshProxyCreds();
  }

  deleteSecret(name: string): void {
    this.vault.deleteSecret(name);
    // Remove the auto-generated allow rule for this secret.
    const p = this.policy.getPolicy();
    p.rules = p.rules.filter((r) => r.id !== `allow-secret-${name}`);
    this.savePolicy(p);
  }

  private maintainPolicyForSecret(name: string, hosts: string[]): void {
    const p = this.policy.getPolicy();
    for (const h of hosts) {
      if (!p.egressAllowlist.includes(h)) p.egressAllowlist.push(h);
    }
    const ruleId = `allow-secret-${name}`;
    p.rules = p.rules.filter((r) => r.id !== ruleId);
    p.rules.push({
      id: ruleId,
      description: `auto: allow traffic that uses secret '${name}'`,
      match: { hosts },
      action: 'allow',
    });
    this.savePolicy(p);
  }

  private refreshProxyCreds(): void {
    // Injectors are read live from the vault on each request, so no action is
    // strictly required, but keep this hook for future caching.
  }

  // --- policy -------------------------------------------------------------
  getPolicy(): Policy {
    return this.policy.getPolicy();
  }

  savePolicy(p: Policy): void {
    p.defaultAction = 'deny';
    this.policy.setPolicy(p);
    writeJson(this.paths.policy, p);
  }

  // --- agents -------------------------------------------------------------
  upsertAgent(profile: Omit<AgentProfile, 'id'> & { id?: string }): AgentProfile {
    const id = profile.id || randomId();
    const full: AgentProfile = { ...profile, id };
    const idx = this.config.agents.findIndex((a) => a.id === id);
    if (idx >= 0) this.config.agents[idx] = full;
    else this.config.agents.push(full);
    saveConfig(this.paths, this.config);
    return full;
  }

  removeAgent(id: string): void {
    this.launcher.stop(id);
    this.config.agents = this.config.agents.filter((a) => a.id !== id);
    saveConfig(this.paths, this.config);
  }

  launchAgent(id: string): { ok: boolean; reason?: string } {
    const profile = this.config.agents.find((a) => a.id === id);
    if (!profile) return { ok: false, reason: 'no such agent' };
    if (!this.proxyRunning) return { ok: false, reason: 'proxy is not running — start the airlock first' };
    this.launcher.launch(profile, this.wiredEnv());
    this.audit.append({ event: 'admin', reason: `launched agent ${profile.name}`, detail: { id } });
    return { ok: true };
  }

  stopAgent(id: string): boolean {
    const ok = this.launcher.stop(id);
    if (ok) this.audit.append({ event: 'admin', reason: 'stopped agent', detail: { id } });
    return ok;
  }

  // --- migration ----------------------------------------------------------
  async setupMigration(passphrase: string): Promise<{ offlineShare: string }> {
    const { result, vdk } = await setupMigration(this.paths, this.sealer, { passphrase });
    await this.vault.rekey(vdk, this.sealer);
    this.audit.append({ event: 'migration', reason: 'migration shares created (2-of-3)', detail: { threshold: 2, total: 3 } });
    return { offlineShare: result.offlineShare };
  }

  migrationConfigured(): boolean {
    return loadManifest(this.paths) !== null;
  }

  // --- status -------------------------------------------------------------
  status(): Record<string, unknown> {
    const secrets = this.vault.listSecrets();
    const agents = this.config.agents.map((a) => ({ ...a, runtime: this.launcher.status(a.id) }));
    return {
      initialized: true,
      proxyRunning: this.proxyRunning,
      proxy: { host: this.config.proxyHost, port: this.config.proxyPort },
      admin: { host: this.config.adminHost, port: this.config.adminPort },
      sealer: this.sealer.info,
      secretsCount: secrets.length,
      secrets,
      agents,
      policy: this.getPolicy(),
      audit: this.audit.verify(),
      migrationConfigured: this.migrationConfigured(),
      caCertPath: this.paths.caCertExport,
    };
  }
}
