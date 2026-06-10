/**
 * Migration / recovery ceremony — deliberately HARD, never automatic.
 *
 * To move the vault to a new machine the operator must present K-of-N shares.
 * The old machine's DPAPI share is bound to the old machine and cannot unseal
 * here, so on a new machine migration requires BOTH human factors (recovery
 * passphrase + offline share). One compromised machine can never migrate alone.
 *
 * The honest tension (documented in THREAT-MODEL.md): anyone who fully obtains
 * the human factors can also migrate. We make that astronomically hard (multi-
 * factor, offline share, optional delay/confirmation) but not impossible.
 */
import { Paths, loadConfig, saveConfig } from '../config';
import { createSealer, autoSealerKind } from '../crypto/sealer';
import { aesgcmDecrypt } from '../crypto/aesgcm';
import { VAULT_AAD } from '../vault/vault';
import {
  loadManifest,
  loadPassphraseShare,
  loadDpapiShare,
  decodeOfflineShare,
  combineToMrk,
  deriveVdk,
} from '../vault/mrk';
import { readFileOpt, atomicWrite } from '../util/fsx';
import { AuditLog } from '../audit/audit';
import { log } from '../util/logger';

export interface MigrateOptions {
  passphrase?: string;
  offlineShare?: string;
  delaySec?: number;
  /** Optional out-of-band confirmation gate; return false to abort. */
  confirm?: () => Promise<boolean>;
  sealerPassphrase?: string; // for passphrase-sealer target machines
}

export interface MigrateResult {
  ok: boolean;
  sharesUsed: string[];
  reason?: string;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export async function migrateImport(paths: Paths, opts: MigrateOptions): Promise<MigrateResult> {
  const manifest = loadManifest(paths);
  if (!manifest) {
    return {
      ok: false,
      sharesUsed: [],
      reason: 'no migration manifest found — run `airlock migrate setup` on the source machine and copy the data dir here',
    };
  }

  const targetSealer = createSealer(autoSealerKind(), { passphrase: opts.sealerPassphrase });

  // Gather shares from the human factors first, then the machine share if present.
  const shares: Buffer[] = [];
  const used: string[] = [];
  let mrk: Buffer | undefined;
  let vdk: Buffer | undefined;
  try {
    if (opts.passphrase) {
      try {
        const s = loadPassphraseShare(paths, opts.passphrase);
        if (s) {
          shares.push(s);
          used.push('passphrase');
        }
      } catch {
        // wrong/corrupt passphrase -> treat as a share we couldn't supply; the
        // threshold check below returns a structured {ok:false} per the contract.
      }
    }
    if (opts.offlineShare) {
      const s = decodeOfflineShare(opts.offlineShare);
      shares.push(s);
      used.push('offline');
    }
    if (shares.length < manifest.threshold) {
      const s = await loadDpapiShare(paths, targetSealer);
      if (s) {
        shares.push(s);
        used.push('dpapi(local)');
      }
    }

    if (shares.length < manifest.threshold) {
      return {
        ok: false,
        sharesUsed: used,
        reason: `need ${manifest.threshold} shares to reconstruct, only have ${shares.length} (${used.join(', ') || 'none'})`,
      };
    }

    if (opts.delaySec && opts.delaySec > 0) {
      log.warn(`migration delay: waiting ${opts.delaySec}s before reconstructing (deliberate friction)`);
      await sleep(opts.delaySec * 1000);
    }
    if (opts.confirm) {
      const okc = await opts.confirm();
      if (!okc) return { ok: false, sharesUsed: used, reason: 'migration not confirmed' };
    }

    mrk = combineToMrk(shares.slice(0, manifest.threshold));
    vdk = deriveVdk(mrk, Buffer.from(manifest.vdkSalt, 'hex'));

    // Integrity check: the reconstructed VDK must decrypt the portable vault.
    const enc = readFileOpt(paths.vaultEnc);
    if (!enc) {
      return { ok: false, sharesUsed: used, reason: 'vault.enc not found in this data dir' };
    }
    try {
      const plain = aesgcmDecrypt(vdk, enc, VAULT_AAD);
      JSON.parse(plain.toString('utf8')); // throws if shares were wrong
      plain.fill(0);
    } catch {
      return { ok: false, sharesUsed: used, reason: 'reconstructed key did not decrypt the vault — wrong shares' };
    }

    // Re-seal the working key to THIS machine so daily use is automatic here.
    const sealed = await targetSealer.seal(vdk);
    atomicWrite(paths.vdkSeal, sealed);

    // Keep config.sealer in lockstep with the sealer that now protects vdk.seal —
    // a cross-platform migration (e.g. Windows DPAPI -> macOS keychain) changes the
    // sealer kind, and a stale config.sealer would brick the next open.
    try {
      const cfg = loadConfig(paths);
      if (cfg && cfg.sealer !== targetSealer.info.kind) {
        cfg.sealer = targetSealer.info.kind;
        saveConfig(paths, cfg);
      }
    } catch {
      /* non-fatal */
    }

    const audit = new AuditLog(paths);
    audit.append({
      event: 'migration',
      decision: 'approved',
      reason: 'vault migrated to this machine',
      detail: { sharesUsed: used, sealer: targetSealer.info.kind },
    });

    return { ok: true, sharesUsed: used };
  } finally {
    // Zeroize all reconstructed key material on EVERY path (success, early return, throw).
    shares.forEach((s) => s.fill(0));
    if (mrk) mrk.fill(0);
    if (vdk) vdk.fill(0);
  }
}
