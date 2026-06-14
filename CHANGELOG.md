# Changelog

All notable changes to Credential Airlock are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-06-14

### Changed
- Removed the unused `test/preview-daemon.mjs` helper from the public source tree.
- Removed dev-only maintenance scripts from the shipped npm/GitHub tarball surface;
  source checkout scripts remain available for CI, load testing, package validation,
  and release smoke tests.
- Reconciled launch, install, release, and threat-model documentation with the
  actual `v0.1.x` public release line and the GitHub-release-first workflow.

## [0.1.0] - 2026-06-14

### Added
- First public GitHub release by Classeve.
- Release artifacts: packed tarball, CycloneDX SBOM, SHA-256 checksums, and
  build-provenance attestation.
- Public repository metadata, issue templates, pull request template, support,
  conduct, release, install, deployment, pentest, audit, and launch-readiness
  documentation.

## 0.1.0-prelaunch - launch hardening

### Added
- **CI matrix** (GitHub Actions): build + 209-assertion test suite + `npm audit`
  on Linux, macOS, and Windows across Node 20/22/24. The Windows job exercises
  the real **DPAPI** sealer; a best-effort macOS job smoke-tests the **Keychain**
  sealer; a weekly cron re-runs everything as a new-advisory canary.
- **Release pipeline**: tag-driven build that produces a **CycloneDX SBOM**,
  **SHA-256 checksums**, and a **SLSA build-provenance attestation**, then
  publishes a GitHub Release. Dependabot watches npm + Actions.
- **Public npm packaging**: package metadata, repository links, npm `files[]`,
  `prepare`/`prepack`/`prepublishOnly` lifecycle hooks, and public
  `publishConfig` so `credential-airlock` installs as the `airlock` CLI.
- **Package verification**: `npm run package:check` validates the packed file
  surface and CLI shebang; `npm run smoke:install` packs the release artifact,
  installs it into a temporary npm prefix, and runs the installed `airlock` bin.
- **Install guide**: [docs/INSTALL.md](docs/INSTALL.md) covers npm, GitHub,
  one-shot `npx`/`npm exec`, release tarball, upgrade, reinstall, and
  post-install verification flows.
- **Hardened deployment**: distroless, non-root `Dockerfile`; a hardened
  `docker-compose.yml` (read-only rootfs, dropped caps, no-new-privileges,
  sidecar networking); a fully sandboxed **systemd unit**; a Windows
  scheduled-task installer; and [docs/DEPLOY.md](docs/DEPLOY.md).
- **`airlock backup` / `airlock restore`** — archive/restore the **sealed** data
  dir for disaster recovery. Never touches plaintext; restore is integrity-checked,
  name-allowlisted, no-symlink-follow, two-pass-atomic, and holds the single-writer
  lock. With the DPAPI/Keychain sealer the sealed key is machine-bound (restore on
  the same machine; use `migrate` to move); a passphrase-sealed backup is portable
  to any machine that has the passphrase.
- **`airlock health`** — deep health check (vault openable, audit chain verifies,
  ports) with a non-zero exit code on failure, for systemd/k8s probes.
- **`AIRLOCK_PASSPHRASE_FILE`** — read the passphrase-sealer passphrase from a
  file (systemd `LoadCredential` / Docker secret) instead of an env var.
- **Load/soak test** (`scripts/loadtest.mjs`, `npm run loadtest`) — sustained
  concurrent traffic asserting zero credential leak, all injections succeed,
  deny-by-default holds, and bounded memory; reports throughput/latency/peak RSS.
- Governance: [SECURITY.md](SECURITY.md) (coordinated disclosure, safe harbor,
  no-telemetry statement), [CONTRIBUTING.md](CONTRIBUTING.md),
  [docs/PENTEST.md](docs/PENTEST.md) (turnkey external-test scope), and
  [docs/LAUNCH.md](docs/LAUNCH.md) (the launch-readiness contract).

### Changed
- `airlock run` / the agent launcher no longer rely on Node's deprecated
  shell-with-args spawning on Windows (silences DEP0190) while preserving `.cmd`
  shim support, and now neutralize cmd.exe metacharacters (`& | < > ( ) ^`) in
  arguments by quoting (the irreducible `%VAR%` case is documented).

### Security (launch-hardening audit — 5th review round)
A multi-agent adversarial audit of the launch-hardening changes, run as an
iterative audit/fix loop to a clean pass (20 issues fixed across four passes, each
independently re-verified), produced these fixes — all addressed:
- **Audit log: non-destructive read-only open.** `Runtime.open` (status, `audit
  --verify`, `health --deep`, `secret list`) no longer truncates/rewrites the audit
  log or tip on open — only the lock-holding daemon repairs. This closes a latent
  race where a read-only command could corrupt a concurrently running daemon's
  hash-chained log or trip a false sticky tamper marker. (was: HIGH)
- **`restore` hardening.** Name allowlist + path-containment, no-symlink/junction
  follow (writes via the atomic temp-file+rename helper), two-pass integrity (a bad
  entry leaves nothing written), bounded decompression, and the single-writer lock
  held across the restore (closes a TOCTOU). New `test/backup.mjs` regression suite.
- **Deploy/CI correctness.** Compose healthcheck now runs `health --deep` (matching
  the documented contract); the sidecar waits for `service_healthy`; the release
  workflow builds the tag's tree on dispatch and attests the SBOM alongside the
  tarball; `npm pack` is scoped via `files` so the SBOM isn't embedded in its own
  tarball.
- **Docs honesty.** Corrected the stale assertion count and reconciled the review-
  round count across all docs.

### Security (fresh-perspective whole-product audit -- 6th review round)
A final audit re-attacked the ENTIRE codebase from six independent adversarial
lenses and iterated audit/fix/audit to a clean pass (16 issues fixed across four
passes, each re-verified) -- bringing the total to 99 confirmed issues fixed
across all six review rounds:
- **Non-ASCII secret could leak via a response HEADER.** Header scrubbing is now
  byte-aware (the latin1 on-the-wire form), matching the response-body path.
- **DNS-rebind SSRF (TOCTOU).** The upstream connection now re-validates the IP
  actually resolved at connect time and fails closed on a private/loopback result.
- **Amount-cap bypass via the query string.** The cap now binds the body AND the
  query (deny if either is over/negative); the approval card shows the true max.
- **Unqualified "hardware-sealed" claim** corrected to "OS-sealed (DPAPI/Keychain/
  passphrase; not a hardware TPM)" on every external surface, matching the code.
- Plus: host trailing-dot canonicalization; a hardened IPv6 SSRF classifier
  (normalize-to-bytes + zone-id strip, covering compressed/expanded/mapped/zoned
  forms); unrecognized-action fail-closed (eval + on write); approval-body memory
  accounting; transactional migration setup (manifest-last + self-check); an
  actionable torn-init error; a corrected monitoring doc; and a de-flaked Shamir
  test. New `unit` + `backup` regression coverage.

### Security (advanced internals / exploit-chain audit -- 7th review round)
The deepest pass — eight specialized lenses into the internals — iterated
audit/fix/audit to a clean pass (9 issues fixed, 3 high; 108 confirmed across all
seven rounds):
- **Cleartext credential exfiltration (HIGH).** The plain-HTTP plane injected the
  real key over unencrypted TCP and silently downgraded `https://` to port 80. The
  request scheme is now honored (https -> TLS-verified) and credential injection
  over cleartext to a non-loopback host is refused (opt-in `AIRLOCK_ALLOW_CLEARTEXT_EGRESS`).
- **Secret leak via a response HEADER NAME (HIGH).** Header names were copied
  verbatim; now scrubbed + token-validated and dropped if they carry a secret.
- **Launched agents inherited `AIRLOCK_PASSPHRASE` (HIGH).** A launched agent got
  the daemon's full env — enough to decrypt the vault + CA key offline.
  `sanitizedEnv()` now strips the sealer secrets at both spawn sites.
- Plus: `forward()` fails closed (502 + audit) on an invalid injected header instead
  of hanging, with set-time validation; the in-flight memory counter no longer leaks
  on a client abort; a query-mode secret echoed back percent-encoded is now scrubbed;
  and `src/util/glob.ts` was rewritten from UTF-16-with-a-stray-NUL to clean UTF-8.
- Corrected the documented invariant: credentials are injected only over verified TLS.

### Security (response-lifecycle & validation audit -- 8th review round)
A focused follow-up that re-reviewed the 7th-round changes (multi-agent, with
empirical Node probes) and fixed the regressions/gaps they left, plus three new
findings. All fixes covered by 24 new test assertions (now 209 total, all green):
- **Response-teardown hang + missing audit (HIGH).** On an upstream connection
  reset mid-body (verified: only the *response* stream errors, not the request),
  the new handlers freed the byte counter but never finalized the agent response
  or wrote an audit line — the request hung indefinitely and a credentialed egress
  went unrecorded (with pinned request bytes able to wedge the in-flight cap). The
  whole forward path now routes every terminal event (normal end, upstream
  RST/abort/timeout, client abort, build/write/scrub throw) through one idempotent
  `settle()` — done() fires exactly once, `res` is finalized exactly once, counters
  always rebalance, and a client abort is now audited (`clientAborted`).
- **Loopback guard matched DNS names (HIGH).** `isLocalLiteral` used an unanchored
  `/^127\./`, so `127.evil.com` was treated as loopback and exempted from the
  cleartext-injection guard, the SSRF/rebinding check, AND connect-time IP vetting.
  Now requires a real IPv4 literal (`net.isIPv4`).
- **Injection crash on a malformed value.** A query-mode value with an unpaired
  surrogate threw in `encodeURIComponent` before `forward()`, hanging the request;
  injection is now wrapped (fail-closed 502 + audit) and such values are rejected
  at set time.
- **Blind-DNS exfiltration on the plain plane.** `handlePlainHttp` resolved the
  attacker-supplied host *before* the egress allowlist check; deny-by-default is
  now enforced first (no DNS for a non-allowlisted host), symmetric with CONNECT.
- **Audit fidelity.** A pre-egress failure (invalid injected header / connect
  error) was logged as an *allowed, injected* credential use; it is now recorded
  with `injected:[]` and `delivered:false` so the tamper-evident log never
  over-claims key exposure.
- **Injectable-secret validation, corrected & relocated.** The char-class now
  mirrors Node's real header-value rule (`/[^\t\x20-\x7e\x80-\xff]/`) — rejecting
  CR/LF and code units >0xFF (closing a silent black-hole) while allowing tab and
  high-Latin1 — and lives in `Vault.setSecret`/`rotateSecret` so every write path
  inherits it. `restore` runs a best-effort warn sweep for legacy vaults.
- Plus: the admin API returns an actionable **400** with the validation reason
  (was an opaque 500 / a misleading 404 on rotate); child env strips the entire
  `AIRLOCK_*` namespace (allowlist-within-namespace, drift-proof); the shared
  RFC-7230 token regex is de-duplicated into one leaf module; and the redaction
  scrubber precomputes its needle set instead of re-deriving it per response chunk.

## 0.1.0-dev - 2026-05-29

### Added
- Initial working build (v0–v2): loopback MITM forward proxy with deny-by-default
  egress, per-secret host-bound credential injection, DPAPI/Keychain/passphrase
  sealing, deny-by-default policy engine (rate/amount limits, human approval),
  hash-chained tamper-evident audit log, Shamir 2-of-3 migration ceremony,
  loopback token-authed control panel + UI, and an agent launcher.

### Security
- Deep multi-agent adversarial audit: **63 confirmed issues found and fixed**
  across four review rounds, including a **critical** compressed-response
  key-leak (now fails closed) and node-forge CVEs (upgraded to 1.4.0,
  `npm audit` clean). Full evidence in [docs/AUDIT.md](docs/AUDIT.md).

[Unreleased]: https://github.com/classeve-public/credential-airlock/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/classeve-public/credential-airlock/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/classeve-public/credential-airlock/releases/tag/v0.1.0
