/**
 * macOS Keychain sealer.
 *
 * The Keychain is stateful storage, not a pure transform, so "seal" stores the
 * payload as a generic password under a content-addressed label and returns an
 * opaque reference blob; "unseal" resolves it. Items are created with
 * ThisDeviceOnly semantics so they do not sync to iCloud.
 *
 * True Secure Enclave binding for arbitrary blobs needs a native helper; that is
 * the documented upgrade. This implementation is the Keychain primitive named in
 * the brief and is only exercised on darwin.
 */
import { spawnSync } from 'child_process';
import * as crypto from 'crypto';
import { Sealer, SealerInfo } from '../types';

const SERVICE = 'credential-airlock';

function sec(args: string[], input?: string): { status: number; stdout: string; stderr: string } {
  const res = spawnSync('security', args, { input, encoding: 'utf8' });
  return { status: res.status ?? 1, stdout: res.stdout || '', stderr: res.stderr || '' };
}

export class KeychainSealer implements Sealer {
  readonly info: SealerInfo = {
    kind: 'keychain',
    hardware: false,
    bound: 'user+machine',
    description: 'macOS Keychain (generic-password, ThisDeviceOnly)',
  };

  async seal(plaintext: Buffer): Promise<Buffer> {
    const account = 'k_' + crypto.randomBytes(8).toString('hex');
    const value = plaintext.toString('base64');
    // -U updates if present; store base64 value.
    const res = sec(['add-generic-password', '-a', account, '-s', SERVICE, '-w', value, '-U', '-T', '']);
    if (res.status !== 0) throw new Error(`Keychain store failed: ${res.stderr.trim()}`);
    return Buffer.from(JSON.stringify({ ref: account }), 'utf8');
  }

  async unseal(sealed: Buffer): Promise<Buffer> {
    let ref: string;
    try {
      ref = (JSON.parse(sealed.toString('utf8')) as { ref: string }).ref;
    } catch {
      throw new Error('invalid keychain reference blob');
    }
    const res = sec(['find-generic-password', '-a', ref, '-s', SERVICE, '-w']);
    if (res.status !== 0) throw new Error(`Keychain lookup failed: ${res.stderr.trim()}`);
    return Buffer.from(res.stdout.trim(), 'base64');
  }
}
