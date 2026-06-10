/**
 * Shared contracts for Credential Airlock. Every module builds against these.
 *
 * INVARIANT: a raw secret value lives only (a) inside the sealed vault blob at
 * rest and (b) transiently in proxy memory at inject time. It is never written
 * to config, policy, audit, logs, or any admin API response.
 */

// ---------------------------------------------------------------------------
// Sealing (hardware root of trust)
// ---------------------------------------------------------------------------
export type SealerKind = 'dpapi' | 'keychain' | 'tpm' | 'passphrase';

export interface SealerInfo {
  kind: SealerKind;
  /** True only when backed by a hardware root of trust (TPM / Secure Enclave). */
  hardware: boolean;
  bound: 'user' | 'machine' | 'user+machine' | 'passphrase';
  description: string;
}

export interface Sealer {
  readonly info: SealerInfo;
  seal(plaintext: Buffer): Promise<Buffer>;
  unseal(sealed: Buffer): Promise<Buffer>;
}

// ---------------------------------------------------------------------------
// Secrets & injection
// ---------------------------------------------------------------------------
export type InjectionMode = 'placeholder' | 'header' | 'query';

export interface InjectionSpec {
  mode: InjectionMode;
  /** placeholder mode: dummy the agent uses, e.g. "__OPENAI_KEY__". */
  placeholder?: string;
  /** Also scan/replace the placeholder inside the request body. */
  injectInBody?: boolean;
  /** header mode: header name to set, e.g. "Authorization". */
  header?: string;
  /** header/placeholder mode: template; "{{secret}}" is replaced. Default "{{secret}}". */
  valueTemplate?: string;
  /** query mode: query parameter name to set. */
  queryParam?: string;
}

/** Stored metadata for a secret. The value is kept separately (sealed). */
export interface SecretMeta {
  name: string;
  /** Dummy token the agent uses (placeholder mode). */
  placeholder: string;
  /** Hosts this secret may EVER be injected toward (glob). Hard security bound. */
  allowedHosts: string[];
  injection: InjectionSpec;
  description?: string;
  createdAt: string;
  updatedAt: string;
  lastRotatedAt?: string;
}

export type SecretWithValue = SecretMeta & { value: string };

/** Decrypted vault, held only in memory. */
export interface VaultData {
  version: number;
  createdAt: string;
  secrets: Record<string, SecretWithValue>;
  ca: { certPem: string; keyPem: string } | null;
  /** Non-secret bookkeeping (e.g. MRK salt). */
  meta: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------
export type PolicyAction = 'allow' | 'deny' | 'require_approval';

export interface RateLimit {
  max: number;
  windowSec: number;
}

export interface AmountLimit {
  /** JSON body field or form field to read the numeric amount from, e.g. "amount". */
  field: string;
  /** Maximum permitted value of that field per matching request. */
  max: number;
  currency?: string;
}

export interface PolicyRule {
  id: string;
  description?: string;
  match: {
    hosts?: string[];
    paths?: string[];
    methods?: string[];
  };
  action: PolicyAction;
  rateLimit?: RateLimit;
  amountLimit?: AmountLimit;
}

export interface Policy {
  /** Always 'deny' — deny-by-default is a non-negotiable invariant. */
  defaultAction: 'deny';
  /** Hosts reachable at all (glob). Nothing else leaves the machine. */
  egressAllowlist: string[];
  rules: PolicyRule[];
}

export interface PolicyDecision {
  action: PolicyAction;
  ruleId?: string;
  reason: string;
}

// ---------------------------------------------------------------------------
// Audit (hash-chained, append-only, never holds secret values)
// ---------------------------------------------------------------------------
export type AuditEvent = 'request' | 'approval' | 'admin' | 'system' | 'migration';
export type AuditDecision =
  | 'allowed'
  | 'denied'
  | 'approval_required'
  | 'approved'
  | 'rejected'
  | 'expired';

export interface AuditEntry {
  seq: number;
  ts: string;
  event: AuditEvent;
  host?: string;
  method?: string;
  path?: string;
  decision?: AuditDecision;
  ruleId?: string;
  reason?: string;
  /** Secret NAMES injected — never values. */
  injected?: string[];
  reqBytes?: number;
  status?: number;
  respBytes?: number;
  latencyMs?: number;
  detail?: Record<string, unknown>;
  prevHash: string;
  hash: string;
}

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------
export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'expired';

export interface ApprovalRequest {
  id: string;
  ts: string;
  host: string;
  method: string;
  path: string;
  summary: string;
  amount?: { field: string; value: number; currency?: string };
  ruleId?: string;
  status: ApprovalStatus;
  expiresAt: string;
}

// ---------------------------------------------------------------------------
// Agents (the launch toggle)
// ---------------------------------------------------------------------------
export interface AgentProfile {
  id: string;
  name: string;
  command: string;
  args: string[];
  cwd?: string;
  /** Extra env merged on top of the auto-wired proxy/CA env. */
  env?: Record<string, string>;
  description?: string;
}

export type AgentRunStatus = 'stopped' | 'running' | 'exited' | 'error';

export interface AgentRuntime {
  id: string;
  status: AgentRunStatus;
  pid?: number;
  startedAt?: string;
  exitedAt?: string;
  exitCode?: number | null;
  lastError?: string;
}

// ---------------------------------------------------------------------------
// Config (non-secret; stored as plaintext JSON in the data dir)
// ---------------------------------------------------------------------------
export interface AirlockConfig {
  version: number;
  proxyHost: string;
  proxyPort: number;
  adminHost: string;
  adminPort: number;
  sealer: SealerKind;
  agents: AgentProfile[];
  /** Require human approval whenever a request matches no allow rule but host is allowlisted. */
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Migration / recovery
// ---------------------------------------------------------------------------
export type ShareKind = 'dpapi' | 'passphrase' | 'offline' | 'vendor';

export interface ShareMeta {
  index: number; // Shamir x-coordinate (1-based)
  kind: ShareKind;
  createdAt: string;
  label: string;
}

export interface MigrationManifest {
  version: number;
  threshold: number; // K
  total: number; // N
  shares: ShareMeta[];
  vdkSalt: string; // hex, HKDF salt for VDK derivation from MRK
  createdAt: string;
}
