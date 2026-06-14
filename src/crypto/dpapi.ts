/**
 * Windows DPAPI sealer — the OS-native primitive named in the brief.
 *
 * Uses System.Security.Cryptography.ProtectedData (Protect/Unprotect) via
 * PowerShell, scope = CurrentUser, with app-specific secondary entropy. The
 * sealed blob is bound to the current Windows user account on this machine: it
 * decrypts only as that user, here. A stolen copy is gibberish elsewhere.
 *
 * Payloads sealed by DPAPI are tiny (a 32-byte VDK, ~33-byte Shamir shares), so
 * the per-call PowerShell spawn cost is irrelevant — it happens at init, boot,
 * and on secret writes only.
 */
import { spawnSync } from 'child_process';
import { Sealer, SealerInfo } from '../types';

const ENTROPY_B64 = Buffer.from('credential-airlock/dpapi/v1', 'utf8').toString('base64');

function encodeCommand(script: string): string {
  return Buffer.from(script, 'utf16le').toString('base64');
}

function runPs(script: string, inputB64: string): string {
  const res = spawnSync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encodeCommand(script)],
    { input: inputB64 + '\n', maxBuffer: 32 * 1024 * 1024, windowsHide: true }
  );
  if (res.error) throw new Error(`DPAPI: failed to spawn PowerShell: ${res.error.message}`);
  if (res.status !== 0) {
    const err = (res.stderr ? res.stderr.toString() : '').trim();
    throw new Error(`DPAPI operation failed (exit ${res.status}): ${err || 'unknown error'}`);
  }
  return res.stdout.toString().trim();
}

const SEAL_SCRIPT = `
Add-Type -AssemblyName System.Security
$ErrorActionPreference='Stop'
$in=[Console]::In.ReadToEnd().Trim()
$bytes=[Convert]::FromBase64String($in)
$ent=[Convert]::FromBase64String('${ENTROPY_B64}')
$out=[System.Security.Cryptography.ProtectedData]::Protect($bytes,$ent,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Out.Write([Convert]::ToBase64String($out))
`;

const UNSEAL_SCRIPT = `
Add-Type -AssemblyName System.Security
$ErrorActionPreference='Stop'
$in=[Console]::In.ReadToEnd().Trim()
$bytes=[Convert]::FromBase64String($in)
$ent=[Convert]::FromBase64String('${ENTROPY_B64}')
$out=[System.Security.Cryptography.ProtectedData]::Unprotect($bytes,$ent,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Out.Write([Convert]::ToBase64String($out))
`;

export class DpapiSealer implements Sealer {
  readonly info: SealerInfo = {
    kind: 'dpapi',
    hardware: false, // DPAPI is OS-bound, not hardware-bound. TPM upgrade documented.
    bound: 'user+machine',
    description: 'Windows DPAPI (ProtectedData, CurrentUser scope, app entropy)',
  };

  async seal(plaintext: Buffer): Promise<Buffer> {
    const out = runPs(SEAL_SCRIPT, plaintext.toString('base64'));
    return Buffer.from(out, 'base64');
  }

  async unseal(sealed: Buffer): Promise<Buffer> {
    const out = runPs(UNSEAL_SCRIPT, sealed.toString('base64'));
    return Buffer.from(out, 'base64');
  }
}

/**
 * Availability probe used at init. Performs a REAL Protect/Unprotect round trip
 * with the same scope + entropy the sealer uses, so a broken DPAPI (no loaded
 * profile, unavailable master key, policy restriction) fails here, not later at
 * the first VDK seal.
 */
export function dpapiSelfTest(): boolean {
  try {
    const script = `
Add-Type -AssemblyName System.Security
$ErrorActionPreference='Stop'
$p=[Text.Encoding]::UTF8.GetBytes('airlock-selftest')
$ent=[Convert]::FromBase64String('${ENTROPY_B64}')
$c=[System.Security.Cryptography.ProtectedData]::Protect($p,$ent,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
$d=[System.Security.Cryptography.ProtectedData]::Unprotect($c,$ent,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
if([Convert]::ToBase64String($p) -eq [Convert]::ToBase64String($d)){[Console]::Out.Write('ok')}
`;
    const res = spawnSync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encodeCommand(script)],
      { windowsHide: true }
    );
    return res.status === 0 && res.stdout.toString().includes('ok');
  } catch {
    return false;
  }
}
