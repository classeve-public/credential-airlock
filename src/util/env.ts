/**
 * Environment sanitization for launched/child processes.
 *
 * A launched agent (or any `airlock run -- <cmd>` child) is UNTRUSTED — the whole
 * point of the airlock is that it never holds a real key. But the daemon's own
 * environment may carry the vault-sealing passphrase (AIRLOCK_PASSPHRASE /
 * AIRLOCK_PASSPHRASE_FILE on the passphrase-sealer path), which together with the
 * sealed vdk.seal + vault.enc on disk is enough to decrypt the entire vault
 * offline. So child environments are built from a SANITIZED copy of process.env.
 *
 * We strip the ENTIRE `AIRLOCK_*` namespace rather than a fixed denylist: an
 * allowlist-within-our-own-namespace can't be defeated by adding a future
 * sensitive var (AIRLOCK_PASSPHRASE_2, AIRLOCK_ADMIN_TOKEN, …) and forgetting to
 * list it. wiredEnv() re-adds the one var the child is meant to see (AIRLOCK_ACTIVE)
 * plus the proxy/CA vars, which win because they are layered on top of this copy.
 * Tuning knobs (AIRLOCK_*_MS, ports, home, log level) are intentionally NOT visible
 * to an untrusted child. The most sensitive members are AIRLOCK_PASSPHRASE,
 * AIRLOCK_PASSPHRASE_FILE, AIRLOCK_SEALER and AIRLOCK_HOME, but the sweep is by
 * namespace so it also covers any future AIRLOCK_* var without a code change.
 */

/** Matches every variable in the airlock's own configuration namespace. */
const AIRLOCK_NS_RE = /^AIRLOCK_/i;

/** A copy of `src` (default process.env) with the entire AIRLOCK_* namespace removed. */
export function sanitizedEnv(src: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = { ...src };
  for (const k of Object.keys(out)) {
    if (AIRLOCK_NS_RE.test(k)) delete out[k];
  }
  return out;
}
