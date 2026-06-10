/**
 * Cross-platform passphrase sealer (scrypt + AES-256-GCM).
 *
 * This is SOFTWARE sealing, not hardware sealing — we say so honestly. It is the
 * fallback when no TPM/DPAPI/Enclave is available, and it backs the
 * passphrase-protected migration share. For unattended daily use the passphrase
 * is taken from AIRLOCK_PASSPHRASE; document that this is weaker than a hardware
 * root of trust.
 *
 * Sealed blob layout: [salt:16][aesgcm blob]
 */
import * as crypto from 'crypto';
import { Sealer, SealerInfo } from '../types';
import { aesgcmEncrypt, aesgcmDecrypt } from './aesgcm';
import { scryptKey } from './hkdf';

const SALT_LEN = 16;

export class PassphraseSealer implements Sealer {
  readonly info: SealerInfo = {
    kind: 'passphrase',
    hardware: false,
    bound: 'passphrase',
    description: 'scrypt(N=2^15) + AES-256-GCM (software sealing; no hardware root of trust)',
  };

  constructor(private readonly passphrase: string) {
    if (!passphrase || passphrase.length < 12) {
      throw new Error('passphrase sealer requires a passphrase of at least 12 characters (it is the sole protection for the vault key)');
    }
  }

  async seal(plaintext: Buffer): Promise<Buffer> {
    const salt = crypto.randomBytes(SALT_LEN);
    const key = scryptKey(this.passphrase, salt);
    const blob = aesgcmEncrypt(key, plaintext);
    key.fill(0);
    return Buffer.concat([salt, blob]);
  }

  async unseal(sealed: Buffer): Promise<Buffer> {
    if (sealed.length < SALT_LEN + 28) throw new Error('passphrase blob too short');
    const salt = sealed.subarray(0, SALT_LEN);
    const blob = sealed.subarray(SALT_LEN);
    const key = scryptKey(this.passphrase, salt);
    try {
      return aesgcmDecrypt(key, blob);
    } finally {
      key.fill(0);
    }
  }
}
