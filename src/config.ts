/**
 * Paths and non-secret configuration.
 *
 * AT-REST MODEL
 *   vault.enc   = AES-256-GCM(VDK, vaultJSON)     -- portable; safe to back up; gibberish alone
 *   vdk.seal    = Sealer.seal(VDK)                -- machine-bound (DPAPI/TPM); daily auto-use
 *   manifest    = Shamir(MRK) metadata            -- migration only; VDK = HKDF(MRK, salt)
 *   policy.json, config.json, audit.jsonl, manifest.json -- non-secret
 *
 * Daily use unseals VDK (no human, no MRK). MRK is reconstructed ONLY during the
 * deliberate migration ceremony, from K-of-N shares.
 */
import * as os from 'os';
import * as path from 'path';
import { AirlockConfig } from './types';
import { readJson, writeJson, exists } from './util/fsx';

export function dataDir(): string {
  const override = process.env.AIRLOCK_HOME;
  if (override) return path.resolve(override);
  const platform = process.platform;
  if (platform === 'win32') {
    const base = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    return path.join(base, 'CredentialAirlock');
  }
  if (platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Application Support', 'CredentialAirlock');
  }
  const xdg = process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share');
  return path.join(xdg, 'credential-airlock');
}

export interface Paths {
  root: string;
  config: string;
  vaultEnc: string;
  vdkSeal: string;
  manifest: string;
  policy: string;
  audit: string;
  auditTip: string;
  auditTamper: string;
  adminToken: string;
  caCertExport: string;
  sharesDir: string;
  lock: string;
}

export function paths(root = dataDir()): Paths {
  return {
    root,
    config: path.join(root, 'config.json'),
    vaultEnc: path.join(root, 'vault.enc'),
    vdkSeal: path.join(root, 'vdk.seal'),
    manifest: path.join(root, 'manifest.json'),
    policy: path.join(root, 'policy.json'),
    audit: path.join(root, 'audit.jsonl'),
    auditTip: path.join(root, 'audit.tip.json'),
    auditTamper: path.join(root, 'audit.tamper.json'),
    adminToken: path.join(root, 'admin-token'),
    caCertExport: path.join(root, 'airlock-ca.crt'),
    sharesDir: path.join(root, 'shares'),
    lock: path.join(root, 'airlock.pid'),
  };
}

export const DEFAULT_PROXY_PORT = 7788;
export const DEFAULT_ADMIN_PORT = 7800;

export function defaultConfig(): AirlockConfig {
  return {
    version: 1,
    proxyHost: '127.0.0.1',
    proxyPort: Number(process.env.AIRLOCK_PROXY_PORT) || DEFAULT_PROXY_PORT,
    adminHost: '127.0.0.1',
    adminPort: Number(process.env.AIRLOCK_ADMIN_PORT) || DEFAULT_ADMIN_PORT,
    sealer: process.platform === 'win32' ? 'dpapi' : process.platform === 'darwin' ? 'keychain' : 'passphrase',
    agents: [],
    createdAt: new Date().toISOString(),
  };
}

export function loadConfig(p: Paths): AirlockConfig | null {
  return readJson<AirlockConfig>(p.config);
}

export function saveConfig(p: Paths, cfg: AirlockConfig): void {
  writeJson(p.config, cfg);
}

export function isInitialized(p: Paths): boolean {
  return exists(p.config) && exists(p.vaultEnc);
}
