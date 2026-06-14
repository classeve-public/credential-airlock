# Contributing to Credential Airlock

Thanks for helping. This is a security tool, so the bar for changes to the trust
boundary is deliberately high. Read this before sending a PR.

## Build, test, audit

```
npm install
npm run build        # tsc -> dist/
npm test             # build + unit + e2e + migration + redteam + backup + wincmd (209 assertions)
npm run audit        # npm audit --omit=dev  (must report 0 vulnerabilities)
npm run package:check # verify public package metadata, files, and CLI shebang
npm run smoke:install # pack, install into a temp npm prefix, and run airlock help
npm run loadtest     # sustained no-leak / bounded-memory soak (optional, slower)
```

On Linux/macOS, set a passphrase sealer for the suite:
`AIRLOCK_SEALER=passphrase AIRLOCK_PASSPHRASE=... npm test`. On Windows the
default DPAPI sealer is used automatically. CI runs all of this on every push.

## Non-negotiable security invariants

These are verified by `test/`. **A PR that regresses any of them will not be
merged.** If you change `src/proxy/**`, `src/policy/**`, `src/crypto/**`,
`src/vault/**`, or `src/audit/**`, you must run `npm test` and keep every
assertion green, and add a test for new behavior.

- **No reveal path.** No CLI/API/proxy route ever returns a secret value.
- **Deny-by-default egress** on both the CONNECT and plain-HTTP paths.
- **Per-secret host binding** — a secret is injected only toward its `allowedHosts`.
- **Upstream TLS is verified** (`rejectUnauthorized: true`).
- **Sealing never silently downgrades**; the resolved kind is recorded in config.
- **The vault is never overwritten** on a transient error.
- **Audit is append-only, hash-chained, tip-anchored**, and never contains secrets.
- **The control plane is loopback-only** (coerced at startup) and token-authed.
- **Amount caps and approvals fail closed.**
- A single-writer lock guards all mutations.

See `CLAUDE.md` and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for the full
architecture and boundary.

## Pull requests

- Keep changes focused; match the surrounding code style.
- Describe the security impact of the change explicitly.
- New behavior on the trust boundary needs a regression test in the matching
  suite (`unit`, `e2e`, `migration`, or `redteam`).
- Never commit a real secret. The repo is structured so secrets only ever live in
  the sealed vault under your data dir, never in the tree.

## Reporting vulnerabilities

Do **not** open a public issue. Follow [SECURITY.md](SECURITY.md).
