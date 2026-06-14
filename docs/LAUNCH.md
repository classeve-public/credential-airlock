# Credential Airlock — Launch Readiness Criteria

_This is the contract. We do not call it "launch ready" until every **Gate** item
below is green. We deliberately set the bar **above** what a typical self-hosted
security tool ships with — but only at items we can actually achieve and verify._

## 1. What we are launching

**v1.0 — self-hosted, open-source credential firewall for AI agents**, for
**single operators and trusted teams** running it on their own machines/infra.

What that posture means, stated honestly:

- We win on **self-hosting + an honest security model + ruthless execution**, not
  on a claim of being unbreakable. (See [THREAT-MODEL.md](THREAT-MODEL.md).)
- It is **ready to protect your own keys today** and ready to be adopted as an
  open-source project.
- It is **not yet** positioned to hold *other people's* production credentials
  under a contractual security guarantee — that tier additionally requires an
  independent third-party penetration test and (for enterprise) SOC 2. We have
  made that external step **turnkey** rather than a research project (see
  [PENTEST.md](PENTEST.md)), but we do not claim it as done.

This separation is the whole point: **underclaim the guarantee, overdeliver the
execution.**

## 2. The bar (industry baseline → our bar)

Legend: **[Gate]** = blocks launch · **[Stretch]** = better-than-industry, not blocking.

### A. Correctness & test rigor
| Criterion | Industry baseline | Our bar | Status |
|---|---|---|---|
| Automated tests, all green | "some tests" | **209 assertions** across unit/property, e2e TLS, migration ceremony, red-team, backup/restore (+ a Windows cmd.exe spawn proof) | **[Gate]** ✅ |
| CI on every push/PR | often none for OSS | **CI matrix: Linux + macOS + Windows x Node 20/22/24**, build+test+package check+`npm audit` blocking | **[Gate]** ✅ |
| Cross-platform sealer exercised | rarely | Windows job runs **real DPAPI**; macOS job smoke-tests **Keychain**; passphrase path on all | **[Stretch]** ✅ |
| Sustained-load / leak soak test | rarely | **load/soak test** asserts zero credential leak + bounded memory under concurrency | **[Stretch]** ✅ |

### B. Supply chain & build integrity
| Criterion | Industry baseline | Our bar | Status |
|---|---|---|---|
| `npm audit` clean | sometimes | **0 vulns**, single pinned runtime dep, audit is a **blocking CI gate** + weekly cron | **[Gate]** ✅ |
| Committed lockfile, pinned deps | usually | exact-pinned runtime dep + committed `package-lock.json` | **[Gate]** ✅ |
| Installable npm artifact | often untested | public package metadata, tag-driven npm publish, and temp-prefix `airlock` binary smoke test | **[Gate]** ✅ |
| SBOM published | rarely | **CycloneDX SBOM** built & attached to every release | **[Stretch]** ✅ |
| Artifact integrity | rarely | **SHA-256 checksums** + **SLSA build-provenance attestation** on release artifacts | **[Stretch]** ✅ |
| Dependency update hygiene | varies | **Dependabot** for npm + GitHub Actions | **[Stretch]** ✅ |

### C. Deployment hardening (least privilege)
| Criterion | Industry baseline | Our bar | Status |
|---|---|---|---|
| Runs as non-root | often root | **distroless, non-root (uid 65532)** container | **[Gate]** ✅ |
| Hardened service unit | rarely | **systemd unit** with full sandboxing (`ProtectSystem=strict`, `NoNewPrivileges`, seccomp, dropped caps) | **[Stretch]** ✅ |
| Secret not in process args/env-dump | varies | **`AIRLOCK_PASSPHRASE_FILE`** (systemd `LoadCredential` / Docker secret) | **[Stretch]** ✅ |
| Control plane never network-exposed | n/a | loopback-only, coerced at startup, token-authed | **[Gate]** ✅ |
| Documented deployment model | varies | [DEPLOY.md](DEPLOY.md): per-platform sealer, sidecar networking, monitoring | **[Gate]** ✅ |

### D. Operational maturity
| Criterion | Industry baseline | Our bar | Status |
|---|---|---|---|
| Disaster-recovery backup | varies | **`airlock backup` / `restore`** (sealed data dir; never touches plaintext) | **[Stretch]** ✅ |
| Health probe for monitoring | varies | **`airlock health`** — deep check, non-zero exit on failure (systemd/k8s-friendly) | **[Stretch]** ✅ |
| Tamper / integrity monitoring | rarely | hash-chained audit + `audit --verify` + sticky tamper marker surfaced by `health` | **[Stretch]** ✅ |
| Key rotation | varies | **`airlock secret rotate`** (agents unaffected) | **[Gate]** ✅ |
| Migration to a new machine | rarely | Shamir 2-of-3 ceremony, tested end-to-end | **[Stretch]** ✅ |

### E. Security posture & governance
| Criterion | Industry baseline | Our bar | Status |
|---|---|---|---|
| LICENSE | usually | Apache-2.0 | **[Gate]** ✅ |
| Coordinated disclosure policy | often missing | **[SECURITY.md](../SECURITY.md)** — reporting channel, scope, safe harbor, SLAs, supported versions | **[Gate]** ✅ |
| Documented threat model + honest claims | rarely | [THREAT-MODEL.md](THREAT-MODEL.md) + a public residual-risk list | **[Gate]** ✅ |
| Changelog / SemVer | varies | **[CHANGELOG.md](../CHANGELOG.md)**, SemVer | **[Gate]** ✅ |
| No telemetry / privacy statement | rarely explicit | explicit **"phones home: never"** | **[Stretch]** ✅ |
| Audit evidence package | almost never | **[AUDIT.md](AUDIT.md)** — methodology, findings→fixes→tests, residuals | **[Stretch]** ✅ |

### F. Independent validation (the honest gate)
| Criterion | Industry baseline | Our bar | Status |
|---|---|---|---|
| Internal adversarial review | rarely | **7 rounds** multi-agent audit (incl. fresh-perspective + advanced-internals passes), every finding re-verified against code | **[Stretch]** ✅ |
| Third-party penetration test | varies (often post-launch) | **turnkey pentest package** prepared ([PENTEST.md](PENTEST.md)); the test itself is **the gate before holding others' keys or any public security guarantee** | ⛔ **external — not done** |

## 3. The one thing we cannot self-certify

A literal **independent third-party penetration test** cannot be performed by the
author. What we *did* do:

1. Pushed internal adversarial review as far as it goes (7 rounds, every finding
   reproduced against the compiled build).
2. Wrote [PENTEST.md](PENTEST.md) so an external firm can stand up a target and
   start attacking the documented trust boundary in under an hour.
3. Kept every public claim honest about this gap.

**Go / No-Go:**

- **GO** to launch as an open-source / self-hosted tool for your own and trusted
  teams' keys, with the honest model above. _All Gate items in A–E are green._
- **NO-GO** on marketing it as audited/certified, or holding third parties'
  production credentials under guarantee, **until item F (external pentest) is
  signed off.**

We are at **GO** for the v1.0 posture in §1.
