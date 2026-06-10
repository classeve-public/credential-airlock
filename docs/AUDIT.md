# Credential Airlock — Security Audit & Launch-Readiness Report

_Last updated: 2026-05-29. Reproduce all evidence with `npm test` and `npm run audit`._

This document is the evidence package for launching Credential Airlock as a
security product. It records what was reviewed, what was found, what was fixed,
what residual risk remains, and the automated tests that hold each fix in place.
It is deliberately honest: a security product earns trust by underclaiming the
guarantee and overdelivering the execution.

> **Honest status.** This build has been put through four internal review rounds
> (three fix-verification passes + one deep 7-dimension adversarial audit) and a
> 126-assertion automated test suite. It has **not** had an independent
> third-party penetration test. Do that before making any public security claim
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

- **Adversarial review.** A deep internal review pass covered 7 dimensions —
  (a) red-team key-exfiltration / trust boundary,
  (b) HTTP/proxy protocol & request smuggling, (c) cryptography & key lifecycle
  (verified by fuzzing), (d) served-UI XSS, (e) concurrency & resource
  exhaustion, (f) admin plane + supply chain + operational readiness, (g)
  completeness/claims audit — and **every raw finding was independently,
  adversarially re-verified against the code** (and often reproduced with a probe
  against the compiled build) before being accepted. Three earlier rounds did the
  same against each prior round's fixes.
- **Automated evidence.** Deterministic unit/property tests, an end-to-end TLS
  interception suite, an end-to-end migration-ceremony test, and a red-team
  integration suite — 126 assertions total, run by `npm test`.
- **Real-browser verification.** The actual control panel was driven in a real
  browser: auth enforcement, API round-trips, an XSS probe, and the CSP/security
  headers were confirmed live.
- **Dependency audit.** `npm audit` on the runtime dependency tree.

Across all rounds, **63 confirmed issues were found and fixed** (23 + 13 + 10 in
the three fix-verification rounds, then 27 in the deep audit; some overlap in
class as fixes were hardened). The deep-audit results are detailed below.

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

## 3. Evidence (automated)

Run `npm test` (builds, then runs all four suites). Current result: **126
assertions, 0 failures.**

| Suite | Assertions | Covers |
|-------|-----------:|--------|
| `test/unit.mjs` | 67 | Shamir (400 fuzzed round-trips + the k-of-N threshold property + edge cases + `x=0` rejection), AES-256-GCM (tamper/IV-uniqueness/AAD), HKDF/scrypt, glob anti-bypass anchoring, policy (deny-by-default, amount fail-closed incl. negative/query/duplicate-key, rate-limit, `windowSec=0` fail-closed), migration-share encode/decode + forgery rejection, injection host-binding, audit-chain tamper detection. |
| `test/e2e.mjs` | 36 | Real TLS-interception path: header + placeholder-in-body injection, **deny-by-default egress**, amount caps (6 bypass variants), human approval (approve/deny), audit chain + tip + sticky-tamper, secret-never-on-disk/in-audit, **response scrubbing** (gzip decompress+scrub, octet-stream body, **fake-`Content-Encoding` fails closed**, **zip-bomb fails closed**, HEAD content-length). |
| `test/migration.mjs` | 8 | Full 2-of-3 ceremony **end to end** across a simulated new machine: the real secret recovered from passphrase + offline share, the old machine-bound share correctly unusable, both negative cases (one factor / wrong passphrase) fail closed, `config.sealer` re-keyed. |
| `test/redteam.mjs` | 15 | Active attacks: **injection keyed on CONNECT target not spoofed `Host`**, cross-secret isolation, placeholder-not-injected-to-non-allowed-host, **connection-reuse target integrity**, egress deny, **SSRF private-IP refusal**, admin plane (**no reveal route**, token required, **DNS-rebind Host rejected**, path-traversal blocked). |

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
- **Not third-party pentested.** The headline gate before any public claim.

---

## 5. Pre-launch hardening checklist

Status as of this build:

- [x] Minimal, pinned dependencies; `npm audit` clean (single dep `node-forge@1.4.0`).
- [x] Deny-by-default egress; no network-exposed admin/reveal endpoint; loopback-only control plane.
- [x] Internal automated tests + multi-round adversarial review.
- [ ] **Third-party penetration test** (required before any public security claim).
- [ ] Signed, reproducible build artifacts / release attestation.
- [ ] Run the proxy as its own unprivileged user/namespace/container (operator deployment step).
