# Credential Airlock — Security Audit & Launch-Readiness Report

_Last updated: 2026-05-29. Audited build: see `git log`. Reproduce all evidence with `npm test` and `npm run audit`._

This document is the evidence package for launching Credential Airlock as a
security product. It records what was reviewed, what was found, what was fixed,
what residual risk remains, and the automated tests that hold each fix in place.
It is deliberately honest: a security product earns trust by underclaiming the
guarantee and overdelivering the execution.

> **Honest status.** This build has been put through eight internal review rounds
> (three fix-verification passes, one deep 7-dimension adversarial audit, one
> launch-hardening audit, one fresh-perspective whole-product audit, one
> advanced internals/exploit-chain audit, and one response-lifecycle & validation
> audit) and a
> 209-assertion automated test suite. It has **not**
> had an independent third-party penetration test. Do that before making any public security claim
> or holding a third party's credentials. See [THREAT-MODEL.md](THREAT-MODEL.md).

---

## 1. Methodology

Adversaries considered in scope (per the threat model):

1. **The untrusted / hijacked agent** routed through the proxy.
2. **A hostile or merely reflective allowlisted upstream** (it can choose its
   response headers/body).
3. **A local non-admin process / malicious web page** in the operator's browser.

Out of scope: full root/admin compromise of the host at use time (the proxy
holds plaintext keys in memory by necessity — only confidential computing closes
that, offered as a future enterprise tier).

Review process:

- **Multi-agent adversarial audit.** A deep audit fanned out high-reasoning
  agents across 7 dimensions — (a) red-team key-exfiltration / trust boundary,
  (b) HTTP/proxy protocol & request smuggling, (c) cryptography & key lifecycle
  (verified by fuzzing), (d) served-UI XSS, (e) concurrency & resource
  exhaustion, (f) admin plane + supply chain + operational readiness, (g)
  completeness/claims audit — and **every raw finding was independently,
  adversarially re-verified against the code** (and often reproduced with a probe
  against the compiled build) before being accepted. Three earlier rounds did the
  same against each prior round's fixes.
- **Automated evidence.** Deterministic unit/property tests, an end-to-end TLS
  interception suite, an end-to-end migration-ceremony test, a red-team
  integration suite, and a backup/restore suite — 209 assertions total, run by
  `npm test` — plus a sustained-load soak (`npm run loadtest`).
- **Real-browser verification.** The actual control panel was driven in a real
  browser: auth enforcement, API round-trips, an XSS probe, and the CSP/security
  headers were confirmed live.
- **Dependency audit.** `npm audit` on the runtime dependency tree.

Across the first four rounds, **63 confirmed issues were found and fixed** (23 +
13 + 10 in the three fix-verification rounds, then 27 in the deep audit; some
overlap in class as fixes were hardened). A fifth **launch-hardening** round
(§2.5) audited the launch changes and iterated audit -> fix -> audit to a clean
pass: **20 confirmed issues fixed across four passes (15 + 3 + 2, then 0).** A
sixth, **fresh-perspective whole-product** audit (§2.6) re-attacked the entire
codebase from six independent lenses and iterated to clean: **16 confirmed issues
fixed across four passes (13 + 2 + 1, then 0).** A seventh, **advanced
internals/exploit-chain** audit (§2.7) went deeper — TLS interception, forward-path
smuggling, the streaming scrubber, crypto/migration, concurrency, and invented
exploit chains — and iterated to clean: **9 confirmed issues fixed (8 + 1, then 0),
including 3 high.** An eighth, **response-lifecycle & validation** round
re-reviewed the 7th round's own changes (multi-agent, with empirical Node probes)
and fixed the regressions/gaps it left plus three new findings: **10 confirmed
issues fixed (2 high)** — a response-teardown hang/missing-audit, a loopback guard
that matched DNS names, an injection-time crash, a blind-DNS asymmetry, audit
over-claim on failure, and a corrected/relocated injectability check. In total,
**118 confirmed issues fixed across eight review rounds.** The deep-audit results
are detailed below.

---

## 2. Deep audit results

**34 raw findings → 27 confirmed** (after adversarial verification): 1 critical,
3 high, 9 medium, 12 low, 2 info. **All 27 are fixed.** The ones reachable by an
in-scope adversary now have dedicated regression tests.

### Critical

| # | Finding | Fix | Regression test |
|---|---------|-----|-----------------|
| 1 | **Compressed-response fallback leaked the injected key.** A reflective upstream could set `Content-Encoding: gzip` on a plaintext body echoing the credential; `decompress()` threw and the `catch` forwarded the **raw, un-scrubbed** body. | The compressed path now **fails closed (502)** on any decompress failure or oversize — it never forwards raw upstream bytes. | `e2e` _fake content-encoding fails closed; secret not leaked_ |

### High

| # | Finding | Fix | Regression test |
|---|---------|-----|-----------------|
| 2 | **Oversize compressed response bypassed scrub** (>10 MB compressed streamed raw with `content-encoding` intact → agent recovers the leading plaintext). | Same fail-closed (502); decompression output bounded to 10 MB. | `e2e` _decompression bomb fails closed (502)_ |
| 3 | **Unbounded pending-approval queue** pinned up to 10 MB body each → agent could OOM the firewall. | Pending-approval queue is capped (default 50); over the cap, requests are denied without pinning a body. | covered by approvals cap + `e2e` approval tests |
| 4 | **Vulnerable `node-forge@1.3.1`** (7 advisories incl. cert-chain bypass / signature forgery). | Upgraded to **`node-forge@1.4.0`**; `npm audit` now reports **0 vulnerabilities**. | `npm run audit` |

### Medium (9)

| # | Finding | Fix |
|---|---------|-----|
| 5, 9 | CONNECT tunnels had no TLS-handshake/idle timeout and no concurrency cap (slowloris / fd-pin / DoS). | Per-tunnel **handshake timeout (10 s)** + **idle timeout (120 s)** + **concurrency cap (512)**; active tunnels tracked and released. |
| 6 | WebSocket/Upgrade to an allowlisted host hung the connection. | Upgrade requests are **rejected deterministically (501)** on both planes. |
| 7, 19, 21, 25 | Control panel served with no CSP / X-Frame-Options / nosniff / Referrer-Policy. | **Security headers on every response** (CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, COOP/CORP) — verified not to break the UI in a real browser. |
| 8 | `audit.jsonl` had no size bound (disk-fill DoS) + double `fsync` per request. | **Size-based rotation** with bounded archive retention + a chained rollover anchor; the per-request tip write no longer `fsync`s. |
| 10 | `forward()` set no upstream timeout (hostile upstream pins sockets). | **Upstream request timeout (60 s)**; on timeout the upstream is destroyed → 502. |
| 11 | Corrupt `config.json`/`policy.json` bricked every command with a raw `SyntaxError`. | `readJson` throws a clear error; a corrupt **policy fails safe to deny-all**; `doctor` reports a corrupt config instead of crashing. |
| 12 | `airlock run` / launcher couldn't start `.cmd`/`.bat` shims on Windows (`ENOENT` for npx/claude/aider). | The launcher and `run` use the shell on Windows (the command is operator-configured, loopback + token-authed). |
| 13, 20 | Declared-but-unused `qrcode` dependency (dead supply-chain surface). | **Removed `qrcode`** (and its 30 transitive packages) and `@types/qrcode`. |

### Low (12) — all fixed

- **#14 SSRF egress filter** — the proxy now refuses to inject credentials toward
  an internal/loopback/private address that an allowlisted **public** name
  resolves to (DNS-rebinding / inward redirect). Loopback/localhost **literals**
  the operator explicitly allowlisted are still permitted. _Regression: `redteam`
  SSRF test._
- **#15/#16/#26 HEAD / 204 / 304 framing** — no longer rewrite `content-length`
  (which corrupted HEAD resource length and conditional-GET semantics). _Regression:
  `e2e` HEAD content-length preserved._
- **#17 migration share zeroization** — all reconstructed key material (shares,
  MRK, VDK) is wiped in a `finally` on every path (success / abort / throw).
- **#18 Shamir `combine` rejects an `x=0` share** (a crafted share could otherwise
  dictate the reconstructed secret). _Regression: `unit` shamir tests._
- **#23 amount cap: query + empty-body bypass** — the cap is now read from the
  query string as well as the body, and a capped mutating request with no readable
  amount **fails closed**. _Regression: `unit` query-amount + fail-closed tests._
- **#24 amount cap: negative amounts** — now rejected (`[0, max]`, not just upper
  bound). _Regression: `unit` negative-amount test._
- **#22 admin IPv6 loopback Host** — the loopback Host check now parses `[::1]:port`
  / `::1` correctly (no longer locks out IPv6 clients).
- **#27 CA private key redaction** — the universal-MITM CA key is now registered in
  the redaction net (scrubbed from any log/response).

### Info (2) — addressed

- **#26 204 spurious content-length** — folded into the HEAD/204/304 fix.
- **#27 CA key not redacted** — fixed (see Low).

---

## 2.5 Launch-hardening audit (round 5, four iterative passes)

This round was run as an iterative audit -> fix -> audit loop until a pass came
back clean: **pass 1 found 15, pass 2 found 3 (2 were regressions in pass-1
fixes), pass 3 found 2 (incl. a pre-existing missing lock on `migrate import`),
pass 4 found 0 -- converged.** 20 confirmed issues were fixed across the passes
(plus one the author caught via smoke testing), each with a regression test where
applicable. The single-writer lock now guards EVERY mutation (`init`,
`secret set/rotate/rm`, `migrate setup/import`, `restore`, and the daemon).

A multi-agent adversarial audit of the launch-hardening work (CI/release,
deployment, ops commands, and docs) ran **6 dimensions** with **every finding
independently re-verified against the compiled code** before acceptance: **15
findings — 4 confirmed in-scope + 11 real correctness/honesty defects — all 15
fixed.**

| Sev | Area | Finding | Fix |
|-----|------|---------|-----|
| High | audit / ops | A read-only `Runtime.open` (status, `audit --verify`, `health --deep`, `secret list`) built an `AuditLog` whose constructor truncates a torn tail + writes the tip/tamper marker — a mutation **without the single-writer lock** that could corrupt a concurrently running daemon's hash chain or trip a false sticky tamper marker. | Open-time repair is gated on a `repair` flag; only the lock-holding daemon (`openOrInit`/`initNew`) repairs. Read-only opens never mutate the log. |
| Med | backup | `restore` followed symlinks/junctions inside the data dir (a write-anywhere primitive) and had no entry-name allowlist. | Name allowlist + path containment, **no-symlink-follow** via the atomic temp-file+rename helper, **two-pass integrity** (validate all before writing any). Regression: `test/backup.mjs`. |
| Med | deploy | The Compose healthcheck ran the shallow `health` (port-only) while the docs claimed it verified vault/audit/tamper. | Healthcheck now runs `health --deep` (read-only, safe alongside the daemon) with a longer timeout. |
| Low | docs | Stale "126" assertion count and an inconsistent review-round count across docs. | Reconciled to 176 assertions / seven rounds everywhere. |

The 11 verified-real-but-not-adversary-reachable defects were **also fixed**:
bounded decompression + the single-writer lock on `restore`; cmd.exe-metacharacter
neutralization in the Windows launcher (the irreducible `%VAR%` case documented);
removal of a dead `tamper` branch in `health`; the release workflow builds the
tag's tree on `workflow_dispatch` and attests the SBOM alongside the tarball;
`npm pack` scoped via a `files` allowlist; the agent sidecar waits for
`service_healthy`; and the backup portability note is now sealer-aware.

Passes 2-4 additionally made `migrate setup`, `migrate import`, and `init` hold
the single-writer lock (closing the audit-writer-must-hold-the-lock invariant for
every mutation), tightened the restore name-allowlist to reject host-unwritable
names (Windows ADS/illegal chars), made restore fully two-pass atomic (all
validation before any write), restored the explicit "must be initialized" guard
on `migrate setup`, and documented the Windows quoting residuals honestly. The
final pass found nothing.

---

## 2.6 Whole-product deep audit (round 6, fresh perspective)

A final, fresh-perspective audit re-attacked the ENTIRE codebase (not just the
prior diffs) from six independent adversarial lenses -- secret exfiltration,
HTTP/request-smuggling, cryptography & key lifecycle, web/admin/UI,
policy/audit/DoS, and a completeness/claims critic licensed to challenge the
accepted residuals -- with every finding independently re-verified. It then
iterated audit -> fix -> audit to a clean pass: **14 raw -> 13 confirmed (deep),
then 2, then 1, then 0 -- 16 fixed**, each with a regression test where
applicable. No critical or high survived verification.

| Sev | Area | Finding | Fix |
|-----|------|---------|-----|
| Med | exfiltration | A non-ASCII secret could leak through a RESPONSE HEADER: `scrubHeader` matched code points, but Node delivers header values as latin1, so a secret byte >= 0x80 was not redacted (the body path was already byte-accurate). | Byte-aware header scrub (`scrubLatin1`) + register the latin1 wire form of every secret. Regression: `unit`. |
| Med | SSRF | DNS-rebind TOCTOU: the egress guard resolved once but `forward()` re-resolved with no IP pinning; the plain-HTTP path could then connect to an internal/metadata IP and stream it back. | A connect-time `lookup` re-validates the actual resolved IP and fails closed on a private result (both paths), for non-loopback hosts. |
| Med | policy | Amount-cap bypass: a within-cap BODY amount short-circuited the QUERY check, so `?amount=999999` passed; the approval card was likewise blinded. | The cap now binds body AND query (deny if either is over/negative); the card shows the max of both. Regression: `unit`. |
| Med | honesty | The unqualified "hardware-sealed" headline (README/npm/CLI/CLAUDE.md) contradicted the code (no shipped sealer is hardware-backed) and the product's own honesty model. | Reworded to "OS-sealed (DPAPI/Keychain/passphrase; not a hardware TPM)" on every external surface. |
| Low x8 | various | Host trailing-dot rule evasion (canonicalize host at ingestion); IPv4-mapped + zone-id IPv6 SSRF-classifier gaps (normalize IPv6 to bytes, strip the `%scope` zone -- regression-tested across compressed/expanded/dotted/zone forms); unrecognized rule action now fails closed (eval + savePolicy); approval-pending bodies now count against the in-flight cap; migration is now transactional (manifest written last + a decrypt self-check); a torn first-init now yields an actionable error; a stale `tamper`-field monitoring doc corrected; and a flaky 1-byte Shamir test de-flaked. | all fixed; the classifier / amount / scrub / host-canon fixes carry `unit` regressions, restore carries `test/backup.mjs`. |

Accepted as LOW for this launch tier (see §4): the CONNECT/plain-HTTP destination
**port** is not constrained by the egress allowlist.

---

## 2.7 Advanced internals / exploit-chain audit (round 7)

The deepest pass: eight specialized lenses into the internals the earlier rounds
only skimmed -- TLS leaf-minting, forward-path request smuggling, the streaming
scrubber under pathological framing, crypto/migration depth, concurrency/resource
accounting, the admin/UI, fail-open hunting, and an "invent novel exploit chains"
adversary -- each finding independently re-verified, then iterated to clean:
**8 raw -> 8 confirmed (deep), then 1 (verification: dead code), then 0 -- 9 fixed,
3 of them high.**

| Sev | Area | Finding | Fix |
|-----|------|---------|-----|
| High | exfiltration | The plain-HTTP plane injected the real credential over CLEARTEXT, and an `https://` absolute-form target was silently downgraded to a port-80 dial (voiding `rejectUnauthorized`). A hijacked agent could force the key onto an unencrypted channel with a one-character `http://`. | `handlePlainHttp` honors the request scheme (https -> TLS-verified path, default 443); `handleRequest` REFUSES to inject a credential over cleartext to a non-loopback host (deny + audit) unless `AIRLOCK_ALLOW_CLEARTEXT_EGRESS=1`. Regression: `e2e`. |
| High | scrub | A reflective upstream could echo the injected secret back as a response HEADER NAME — names were copied verbatim (only values were scrubbed). | Header names are scrub + HTTP-token validated and DROPPED if scrubbing changes them; the lowercased secret form is registered (Node lowercases incoming names). Regression: `e2e`. |
| High | env / agent | A launched agent inherited the daemon's full `process.env`, including `AIRLOCK_PASSPHRASE`/`_FILE` — enough to decrypt the whole vault (and the CA key) offline. The untrusted agent is exactly who must NOT have it. | `sanitizedEnv()` strips `AIRLOCK_PASSPHRASE`/`_FILE`/`SEALER`/`HOME` at both spawn sites (launcher + `airlock run`); only proxy/CA vars are passed. Regression: `unit`. |
| Med | smuggling / audit | A secret value/template/header-name with CR/LF/NUL or a code unit > 0xFF made `http.request` throw synchronously in `forward()` — the request HUNG with no response and NO audit line (fail-open on availability + audit). | `forward()` wraps request build + write in try/catch -> audited 502; set-time validation rejects control chars / invalid header names at `secret set`/`rotate`. Regression: `e2e`. |
| Med | DoS | The response-byte in-flight counter leaked on a client abort mid-buffering (the upstream kept flowing, re-incrementing with no release), driving the memory cap toward a permanent 503 wedge. | Release on the upstream stream's `close`/`aborted`/`error` (idempotent) + `up.destroy()` when the client goes away. |
| Med | scrub | A query-mode secret echoed back PERCENT-ENCODED dodged the scrubber (only raw/latin1 forms were registered). | Register `encodeURIComponent(value)` for redaction. Regression: `unit`. |

Also cleaned: `src/util/glob.ts` was UTF-16-encoded with a stray NUL byte where the
cache-key separator should be — rewritten as clean UTF-8 (no behavior change). And
the documented invariant wording was corrected: credentials are injected **only
over verified TLS** (the cleartext plane refuses injection), so "upstream TLS is
verified" holds on every plane that carries a key.

---

## 3. Evidence (automated)

Run `npm test` (builds, then runs all six suites). Current result: **209
assertions, 0 failures** (the 9 `wincmd` assertions run on win32; a macOS
Keychain smoke skips on other platforms). The breakdown below sums to 209.

| Suite | Assertions | Covers |
|-------|-----------:|--------|
| `test/unit.mjs` | 114 | Shamir (400 fuzzed round-trips + the k-of-N threshold property + edge cases + `x=0` rejection), AES-256-GCM (tamper/IV-uniqueness/AAD), HKDF/scrypt, glob anti-bypass anchoring, policy (deny-by-default, amount fail-closed incl. negative/query/duplicate-key, rate-limit, `windowSec=0` fail-closed), migration-share encode/decode + forgery rejection, injection host-binding, audit-chain tamper detection, Windows command-line quoting (DEP0190-safe + cmd-metacharacter neutralization). |
| `test/e2e.mjs` | 44 | Real TLS-interception path: header + placeholder-in-body injection, **deny-by-default egress**, amount caps (6 bypass variants), human approval (approve/deny), audit chain + tip + sticky-tamper, secret-never-on-disk/in-audit, **response scrubbing** (gzip decompress+scrub, octet-stream body, **fake-`Content-Encoding` fails closed**, **zip-bomb fails closed**, HEAD content-length). |
| `test/migration.mjs` | 8 | Full 2-of-3 ceremony **end to end** across a simulated new machine: the real secret recovered from passphrase + offline share, the old machine-bound share correctly unusable, both negative cases (one factor / wrong passphrase) fail closed, `config.sealer` re-keyed. |
| `test/redteam.mjs` | 15 | Active attacks: **injection keyed on CONNECT target not spoofed `Host`**, cross-secret isolation, placeholder-not-injected-to-non-allowed-host, **connection-reuse target integrity**, egress deny, **SSRF private-IP refusal**, admin plane (**no reveal route**, token required, **DNS-rebind Host rejected**, path-traversal blocked). |
| `test/backup.mjs` | 19 | Sealed backup/restore: round-trip fidelity, clobber refusal (no `--force`), **name allowlist / path-traversal / `shares` `.`/`..` / Windows-illegal-name refused**, per-file integrity, **two-pass atomicity** (a bad entry writes nothing), bounded/format-checked decompression, and the write-lock creating a fresh data dir. |
| `test/wincmd.spawn.mjs` | 9 _(win32)_ | Real `cmd.exe` spawn proof: the DEP0190-safe Windows command-line quoting actually round-trips through a live `.cmd` shim — argument boundaries preserved and shell metacharacters (`& \| < > ( ) ^`) neutralized. Skips on non-Windows. |

Dependency audit: `npm run audit` → **0 vulnerabilities** (single runtime dep
`node-forge@1.4.0`).

Real-browser verification (Chromium): token auth enforced (`200` with token,
`401` without), API round-trips, an XSS probe (malicious agent name + secret
host) rendered as inert text with **zero** injected elements / no `onerror`
fired, and the CSP/`X-Frame-Options` headers present without breaking the UI.

---

## 4. Residual risk (honest)

These are known and accepted for a **personal / single-operator** launch; revisit
before multi-tenant or higher-assurance use:

- **Plaintext at use time.** The proxy unwraps real keys into its own memory to
  inject them; a root compromise of the running host can read them. Only
  confidential computing closes this (future enterprise tier).
- **DPAPI is OS/account-bound, not a hardware TPM.** Honest claim: "sealed to your
  Windows account on this machine," not "hardware-sealed." TPM/Secure-Enclave is
  the documented pluggable upgrade.
- **File-based tamper-evidence.** The audit tip + sticky tamper marker detect
  truncation/rollback, but an attacker with full data-dir write who deletes both
  the tip and the tail can still evade detection (the threat model scopes that
  out). A sealed/out-of-band tip is future work.
- **Compressed responses > 10 MB** fail closed (502) rather than streaming; very
  large compressed API responses from a conforming upstream are not supported (we
  strip `Accept-Encoding`, so this is rare).
- **WebSocket / Upgrade is not supported** (rejected 501) — it can't be
  policy-inspected/scrubbed the same way.
- **Audit archives are pruned** beyond the retention bound; offload them if you
  need indefinite retention.
- **The single-writer lock is a best-effort PID file** with an ownership re-read,
  not a kernel advisory lock — a pathological concurrent-restart race is mitigated,
  not provably eliminated.
- **Windows: a literal `%NAME%` in an agent argument** is subject to cmd.exe
  environment expansion when launching `.cmd`/`.bat` agent shims through the shell
  (there is no reliable `cmd /c` escape for `%`). Other shell metacharacters
  (`& | < > ( ) ^`) are neutralized by quoting. Avoid literal `%NAME%` in agent
  args on Windows, or run the agent on a host where no shell is used.
- **The egress allowlist matches by host, not host:port.** An allowlisted host
  implicitly authorizes every port, so a hijacked agent could direct a request to
  a non-standard port on that already-trusted host. CONNECT remains TLS-verified
  to the host's real certificate (so it can't be redirected to an unrelated
  service); credential injection over cleartext is now REFUSED (round-7 fix); and
  deny-by-default still blocks non-allowlisted hosts. The residual is reaching a
  non-standard port on a host the operator already trusts, over verified TLS.
  Front the airlock with a host firewall if you need port scoping. (Round-6 #8,
  accepted LOW for this tier.)
- **Not third-party pentested.** The headline gate before any public claim.

---

## 5. Pre-launch hardening checklist

From the product brief, status as of this build:

- [x] Minimal, pinned dependencies; `npm audit` clean (single dep `node-forge@1.4.0`).
- [x] Deny-by-default egress; no network-exposed admin/reveal endpoint; loopback-only control plane.
- [x] Internal automated tests + multi-round adversarial review (eight rounds).
- [x] CI gates build + the 209-assertion suite + `npm audit` on **Linux/macOS/Windows × Node 20/22/24**, with a weekly advisory canary.
- [x] Release attestation: CI emits a **CycloneDX SBOM + SHA-256 checksums + a SLSA build-provenance attestation** per tagged release. (Bit-for-bit reproducibility is not claimed; the toolchain is pinned.)
- [x] Run the proxy as its own unprivileged user/namespace: a **distroless non-root container**, a **sandboxed systemd unit**, and a **non-elevated Windows task** are provided ([DEPLOY.md](DEPLOY.md)).
- [ ] **Third-party penetration test** (required before any public security claim). Turnkey scope: [PENTEST.md](PENTEST.md).
