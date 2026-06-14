# Credential Airlock — Threat Model

This document is written the way a security review should read it: it states
what the product protects against, what it explicitly does **not**, the concrete
mitigations in the current implementation, and its known limitations. It does
not overclaim. If a guarantee isn't here, we don't make it.

> **Current status: personal / single-operator use. Not third-party audited.**
> Do not make a public security claim about this software until it has been
> through an independent pentest (see the hardening checklist in the
> [README](../README.md#before-you-sell-this-to-others)).

---

## The one-paragraph version

Credential Airlock stops your **real API keys from leaking**: the agent only
ever holds dummies, the vault is sealed to this machine at rest, and the proxy
has no endpoint that reveals a key. It does **not** make a hijacked agent
harmless — an agent that is allowed to charge a card can still charge a card if
it's compromised. That residual risk is contained by **policy, rate/amount
limits, and human approval**, not by hiding the key. And because the proxy can
unwrap real keys, the proxy process itself is the crown jewel and must be
defended accordingly.

---

## Protects against (real, sellable value)

- **Keys in a file / repo / `.env` getting committed or scanned.** None exists.
  The agent is configured with dummy placeholders; there is no real key in its
  source, environment, memory, or context to commit or flag.
- **Disk theft / stolen backup / cloned repo.** The vault (`vault.enc`) is
  `AES-256-GCM` under a Vault Data Key (VDK) that is **sealed to this machine
  and account** (DPAPI, `CurrentUser` scope on Windows). Off the machine, both
  the vault blob and the sealed VDK are gibberish.
- **Agent context / log leakage of the raw key.** The agent never receives the
  raw key, so its logs, traces, prompts, and crash dumps can't contain one.
- **Prompt injection that tries to PRINT or EXFILTRATE the key.** There is no
  reveal capability anywhere — not in the proxy, not in the control-plane API.
  "Show me the key" returns nothing because the code path does not exist.
- **Sending the key to the wrong host.** A secret is injected **only** toward
  the hosts in its `allowedHosts`. An agent that posts `__STRIPE_KEY__` to
  `evil.com` leaks only the literal dummy — and `evil.com` was already blocked
  by deny-by-default egress.
- **Credential sprawl / "everything can use everything."** Policy is
  per-secret and per-host (optionally per-path and per-method), deny-by-default.

---

## Does NOT protect against (say this out loud to customers)

- **A hijacked agent abusing *allowed* actions.** If your policy lets the agent
  charge a card, an injected/compromised agent can charge a card — up to your
  limits. The defense is **tight policy + rate/amount limits + human approval on
  dangerous or irreversible actions**, *not* key-hiding. Hiding the key does
  nothing here; the key was never the leak vector for this attack.
- **Compromise of the PROXY process itself (RCE, supply chain).** The proxy can
  unwrap real keys into its own memory, so it is the **crown jewel**. The
  product brief cites the 2026 LiteLLM incident (an AI-gateway proxy compromised
  via supply chain + a pre-auth SQL injection that exposed ~500,000 corporate
  identities because it concentrated long-lived credentials) and the April 2026
  Bitwarden-CLI npm attack that specifically hunted AI-assistant credentials.
  Mitigation lives in operations, not features: **minimal pinned dependencies,
  signed reproducible builds, run the proxy as its own unprivileged
  user/namespace, no inbound admin endpoint, and aggressive review of every
  dependency.**
- **Plaintext-at-use-time.** At the instant a request is injected and sent, the
  real credential exists in the proxy's process memory. A root-level compromise
  of the running machine **at that moment** can read it. The only thing past
  this is **confidential computing** — encrypted-memory enclaves (AWS Nitro
  Enclaves, AMD SEV, Intel SGX) where even the host OS can't read proxy memory.
  That is an enterprise-tier direction; it is **not** claimed on this build.
- **A user who is fully impersonated during migration.** See
  [The honest tension](#the-honest-tension-migration--recovery).

---

## The honest tension (migration / recovery)

Any recovery path is also a potential attack path. Migration uses a **2-of-3
Shamir** split of the Master Recovery Key:

- **Share 1 (`dpapi`)** — sealed to this machine. Enables daily auto-use; useless
  alone on any other machine.
- **Share 2 (`passphrase`)** — your recovery passphrase (≥ 12 chars), scrypt +
  AES-GCM. A human factor.
- **Share 3 (`offline`)** — printed once (`CA1-…`), stored in a safe. A second
  human factor.

**Daily use never reconstructs the MRK.** It only unseals the VDK via share 1,
so a compromised running machine never holds enough to export or migrate. On a
new machine the DPAPI share can't unseal, so migration requires **both human
factors** — one compromised machine can never migrate silently.

But: **if an attacker fully obtains both human factors (your passphrase *and*
your offline share), they can migrate too.** We make that astronomically hard
(multi-factor, an offline share, optional time delay and out-of-band
confirmation), but we cannot make a vault both *recoverable by the rightful
owner* and *impossible for a perfect impersonator*. Anyone selling
"unrecoverable AND recoverable" is lying. For headless fleets, do not build a
silent migration path at all — decommission the node, provision a fresh one, and
rotate the upstream keys.

---

## Concrete mitigations in this implementation

These are properties of the code as built, not aspirations:

- **Loopback-only planes (enforced).** Both the proxy (`127.0.0.1:7788`) and the
  control plane (`127.0.0.1:7800`) bind to `127.0.0.1` only, and both hosts are
  coerced to a loopback address at startup so a hand-edited config cannot place a
  plane on a network interface. The control plane also enforces a `Host`-header
  check (must be `127.0.0.1`/`localhost`/`::1`) to blunt DNS-rebinding.
- **Token-authed control plane, no reveal route.** Every `/api` call requires a
  one-time token (delivered in the launch URL, persisted to `admin-token` with
  `0600`, compared in constant time). There is deliberately **no endpoint that
  returns a secret value**; `secret list` / `GET /api/secrets` return metadata
  with values stripped.
- **Deny-by-default egress.** A `CONNECT` to any host not on the
  `egressAllowlist` is refused with `403` before TLS is even established. Within
  an allowed host, the first matching rule wins and no match means deny.
- **Per-secret host binding.** Injection checks `matchAnyHost(allowedHosts,
  host)` for each secret; a non-match injects nothing. Host globs are fully
  anchored, so `*.stripe.com` does not match `evil-stripe.com`.
- **Credentials leave only over verified TLS.** When the proxy forwards an intercepted
  request to the real upstream it sets `rejectUnauthorized: true` — it verifies
  the **real** server's certificate. The local CA is used only to present a
  trusted cert *to the agent*, never to accept a forged upstream. The plain-HTTP
  plane refuses to inject a credential over cleartext to a non-loopback host, so a
  hijacked agent cannot downgrade to `http://` to leak the key.
- **Hash-chained, append-only audit with a tip anchor.** Each entry chains
  `SHA-256(prevHash || canonical(entry))`; an out-of-band `audit.tip.json` records
  the latest `{seq, hash}`, so `audit --verify` also detects **tail truncation**
  (deleting recent entries), not just in-place edits. Detected truncation is
  latched in a sticky `audit.tamper.json`, so a later append cannot launder the
  chain back to `ok`. Appends are `fsync`'d, self-correct a missing trailing
  newline, and a torn trailing line is physically truncated on load (no chain
  fork). Secret **names** are logged, never values.
- **Redaction safety-net (logs and responses).** Real secret values are registered
  for redaction when the vault is opened; the audit writer scrubs every entry, and
  the proxy scrubs upstream **response** headers and textual bodies — so a
  reflective upstream cannot echo an injected key back to the agent.
- **Sealing never silently downgrades.** If the platform sealer (DPAPI) is
  unavailable, `init`/`open` fail loudly rather than falling back to weaker
  crypto. The VDK buffer is zeroed in memory on close.
- **Human approval is fail-closed.** A `require_approval` request is held until a
  human acts in the UI; if nobody does within **5 minutes** it **expires and is
  denied**, never auto-approved.
- **Separation of "use" vs "move."** Daily use unseals only the VDK; the MRK is
  reconstructed solely during the deliberate migration ceremony from K-of-N
  shares.
- **Single-writer lock.** The daemon and every mutating CLI command take an
  exclusive lock (`airlock.pid`); a second writer is refused (stale locks from
  dead PIDs are reclaimed), so concurrent processes can't silently clobber the
  vault/policy/config.
- **Crash-survivable daemon.** Top-level `uncaughtException` /
  `unhandledRejection` handlers keep the firewall running rather than letting a
  stray async error drop the proxy and control plane.
- **SSRF egress guard.** The proxy refuses to inject a credential toward an
  internal/loopback/private address that an allowlisted PUBLIC name resolves to
  (DNS-rebinding / inward redirect); loopback literals the operator allowlisted
  are still permitted.
- **Compressed responses fail closed.** `Accept-Encoding` is stripped so bodies
  can be byte-scrubbed; a non-conforming/undecodable/oversize compressed reply is
  dropped with `502` — raw upstream bytes are never forwarded to the agent.
- **DoS limits.** Per-tunnel TLS-handshake (10 s) and idle (120 s) timeouts, a
  concurrent-tunnel cap, an upstream request timeout (60 s), an aggregate in-flight
  byte cap, a bounded pending-approval queue, and size-based audit-log rotation.
- **Hardened control-plane headers.** Every reply carries a strict CSP,
  `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, and
  COOP/CORP (defends against a malicious local page: framing, MIME-sniff,
  inline-script execution).
- **Full deep-audit report:** see [AUDIT.md](AUDIT.md) for the 27-finding audit,
  fixes, evidence, and residual risks.

---

## Known limitations / TODO hardening

Be honest about these in any review:

- **DPAPI is OS/account-bound, not a hardware TPM.** The base Windows build does
  **not** provide a hardware root of trust. TPM 2.0 / Secure-Enclave sealing is
  a documented upgrade path (the `Sealer` interface is pluggable; `tpm` is
  reserved and currently a hard error). Do not claim hardware sealing here.
- **No confidential computing.** Plaintext-at-use-time is unavoidable without an
  encrypted-memory enclave, which this build does not provide.
- **Proxy isolation is the operator's job.** Nothing in this build forces the
  proxy to run as its own unprivileged user/namespace/container. Do it yourself
  before trusting it with anything important.
- **Supply chain is the dominant risk.** The only runtime dependency is
  `node-forge` (pinned `1.4.0`; `npm audit` clean); the integrity of it, of Node,
  and of PowerShell (used for DPAPI) is part of your trust base. Pin, review, and
  prefer signed, reproducible builds. Not yet implemented: signed releases,
  reproducible build attestation.
- **TLS interception requires trusting the local CA.** Agents must trust
  `airlock-ca.crt` (via `NODE_EXTRA_CA_CERTS` / `REQUESTS_CA_BUNDLE` or the OS
  store). The CA private key lives only inside the sealed vault, but a broadly
  imported CA cert widens what the proxy could intercept for that user — scope
  the trust to the agent process where possible (the launcher / `airlock run`
  wire it per-process via env, which is preferable to a system-wide import).
- **Response scrubbing has a size boundary.** To stop a reflective upstream
  echoing an injected key, the proxy strips `Accept-Encoding` (forcing identity),
  decompresses any non-conforming gzip/deflate/br reply **with the decompressed
  output bounded to 10 MB** (so a compression bomb is contained — an over-cap reply
  is forwarded header-scrubbed only), and byte-scrubs response bodies regardless of
  content-type. Identity bodies are fully scrubbed up to 10 MB; beyond that the head
  is scrubbed and the tail is streamed with a sliding-window scrub (a secret
  spanning a chunk boundary is still caught), nothing is sent raw. Header reflection
  is always scrubbed. Response buffering is counted against the same in-flight
  memory cap as requests.
- **The single-writer lock is a best-effort PID file.** Acquisition is atomic
  (`O_EXCL`) and confirmed by an ownership re-read, which makes a concurrent-restart
  reclaim race detectable (the loser backs off). It is not a kernel advisory lock,
  so a pathological race is mitigated, not provably eliminated — adequate for a
  loopback, single-operator tool.
- **The audit tip is file-based tamper-evidence.** It detects tail truncation and
  rollback in the normal and crash cases, but an attacker with write access to the
  data dir who deletes BOTH the tip and the truncated tail can evade detection
  (same class as deleting the whole log). A sealed/out-of-band tip is future work.
- **Amount caps fail closed.** `amountLimit` reads a numeric field from JSON
  (dot-path; robust to leading whitespace/BOM, a spoofed content-type, top-level
  arrays/primitives, and non-numeric values) or `x-www-form-urlencoded` bodies
  (duplicate keys, which parsers disagree on, are rejected). If a rule carries an
  `amountLimit` but the amount cannot be read unambiguously from a present body
  (unparseable encoding such as `multipart/form-data`/binary, a non-finite value,
  or an ambiguous duplicate key), the request is **denied**, so the cap cannot be
  bypassed by re-encoding, malformed values, or parser-differential tricks. Bodies
  a provider signs or seals remain out of scope.
- **Request-signing providers (e.g. AWS SigV4) are out of scope.** Simple
  header/placeholder/query injection cannot produce a valid request signature.
  See [ADAPTERS.md](ADAPTERS.md).
- **Not third-party audited.** No public security claim should be made until an
  independent pentest is complete (README hardening checklist).

---

## Market reality

Gartner has warned that a large share of agentic-AI projects will be cancelled
by 2027 over cost, value, and risk concerns. Lead with **risk reduction a buyer
can verify**, not hype. This threat model is the verifiable part — keep it
accurate.
