/**
 * Sealer factory. Chooses a hardware/OS-bound sealer by platform and NEVER
 * silently downgrades to weaker crypto — an unavailable sealer is a hard error.
 */
import { Sealer, SealerKind } from '../types';
import { DpapiSealer, dpapiSelfTest } from './dpapi';
import { KeychainSealer } from './keychain';
import { PassphraseSealer } from './passphrase';

export function autoSealerKind(): SealerKind {
  if (process.platform === 'win32') return 'dpapi';
  if (process.platform === 'darwin') return 'keychain';
  return 'passphrase';
}

/**
 * Build a sealer of EXACTLY the requested kind. This function does NOT consult
 * AIRLOCK_SEALER — that env var is honored only at first-time init (by the
 * runtime), and the resolved kind is persisted to config, so a vault is always
 * opened with the sealer that actually protects it. No silent downgrades.
 */
export function createSealer(kind: SealerKind, opts?: { passphrase?: string }): Sealer {
  switch (kind) {
    case 'dpapi':
      if (process.platform !== 'win32') throw new Error('DPAPI sealer is only available on Windows');
      if (!dpapiSelfTest()) {
        throw new Error('DPAPI self-test failed: PowerShell / System.Security.ProtectedData unavailable');
      }
      return new DpapiSealer();
    case 'keychain':
      if (process.platform !== 'darwin') throw new Error('Keychain sealer is only available on macOS');
      return new KeychainSealer();
    case 'passphrase': {
      const pass = opts?.passphrase || process.env.AIRLOCK_PASSPHRASE;
      if (!pass) {
        throw new Error(
          'passphrase sealer requires a passphrase (set AIRLOCK_PASSPHRASE or pass --passphrase)'
        );
      }
      return new PassphraseSealer(pass);
    }
    case 'tpm':
      throw new Error('TPM sealer is a documented upgrade path; use the dpapi sealer on Windows');
    default:
      throw new Error(`unknown sealer kind: ${String(kind)}`);
  }
}
