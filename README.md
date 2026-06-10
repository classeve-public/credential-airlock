# Credential Airlock

**A self-hosted, OS-sealed credential firewall for AI agents.**
Your agents never hold your real API keys. The real keys are sealed to this
machine. Every outbound request is policy-checked and audited before it leaves.

Windows-first. Node/TypeScript. You run it; we never see your credentials.

> **Status: personal / single-operator use. Not yet third-party audited.**
> See [Before you sell this to others](#before-you-sell-this-to-others) before you put it
> in front of anyone else's secrets, and read the [Threat Model](docs/THREAT-MODEL.md) before
> you trust it with yours. Internal review evidence (4 review rounds, 63 issues
> fixed, 126-assertion test suite, `npm audit` clean) is documented in
> [docs/AUDIT.md](docs/AUDIT.md).

---

## What it is (in one breath)

Three parts on your own machine:

1. **The agent** sees only **dummy placeholders** — `__OPENAI_KEY__`,
   `__STRIPE_KEY__`, `dummy_cf_token`. It never holds, decrypts, or logs a real
   key. There is nothing real in its memory or context to leak, and your secret
   scanners have nothing to flag.

2. **The proxy** is the **trust boundary** — a small loopback forward proxy.
   The agent points `HTTP(S)_PROXY` at it. It is **deny-by-default**: any host
   not on the egress allowlist is refused (`403`). For allowlisted hosts it
   TLS-intercepts the connection (with a CA your agent trusts), enforces policy,
   swaps the dummy for the **real** credential, and re-encrypts to the real
   upstream — **whose certificate it verifies**. It has **no endpoint that
   reveals a key**. "Reveal the key" is not a capability that exists.

3. **The vault** seals secrets **at rest**. On Windows the sealer is **DPAPI**
   (`ProtectedData`, `CurrentUser` scope). A stolen disk image or cloned repo
   is gibberish on any other machine or account.

That's it. The agent can't leak a key it never had; a thief can't read a vault
sealed to your account on this box; and nothing leaves the machine that policy
didn't allow.

---

## Honest positioning (read this before you get excited)

This product wins on **execution and honesty**, not on novel cryptography.

- **It is not "unbreakable."** Nobody's is. We do not claim it is.
- **The architecture is not new.** Dummy keys + an injecting proxy already ship
  as open-source and commercial products. We are a well-executed, fully
  self-hosted take with a real migration story — not a new invention.
- **It does not make a hijacked agent safe.** It stops the **key** from
  leaking. It cannot stop a compromised agent from **using** the key's power
  within whatever policy you granted. That gap is closed by **policy and human
  approval**, not by hiding the key. Read [THREAT-MODEL.md](docs/THREAT-MODEL.md).

What you *can* honestly say is in [Claims we make / claims we do not
make](#claims-we-make--claims-we-do-not-make). If a sentence isn't in the
"CAN say" list, don't say it.

### The competitive reality

These exist as of 2026. Study them; don't pretend they don't.

| Tool | What it is |
|---|---|
| **Infisical "Agent Vault"** (OSS) | Substitutes dummy header values like `__anthropic_api_key__` with real creds on outbound requests. HTTP proxy + vault. This is the same dummy-key idea, shipping. |
| **AgentSecrets** (OSS) | Zero-knowledge proxy; pulls the real value from the OS keychain and injects at the transport layer; the key never enters agent memory. |
| **Pipelock / PipeLab** (OSS, Apache-2.0) | AI-agent firewall, ~20 MB Go binary; agent has no network, proxy has no secrets, scanning boundary between them. |
| **Akeyless** (commercial) | Secretless brokered access; JIT ephemeral creds injected by a gateway; SPIFFE/SPIRE workload identity. |
| **Aembit** (commercial) | Agentic-AI IAM; workload attestation + ephemeral credentials + least privilege. |

**Why a buyer would honestly pick this instead:**

1. **Fully self-hosted, zero vendor trust.** We never see or hold your keys —
   which is also the strongest security posture: we can't leak what we never
   have, and we don't become a single mega-target.
2. **Sealing by default.** The vault is sealed with the OS-native root of trust
   (DPAPI on Windows today). Hardware TPM / Secure-Enclave sealing is the
   documented upgrade path — the `Sealer` interface is pluggable.
3. **A real migration ceremony.** Most tools punt on "how do I move to a new
   laptop without leaving a backdoor." This one treats it as a deliberate,
   human-verified 2-of-3 ceremony (see [Migration](#migration)).
4. **Turnkey UX.** One process, point your agent's proxy at it, flip a toggle.

---

## 60-second quickstart

> Windows 11 + PowerShell. Requires **Node ≥ 20**. For a deeper walkthrough
> (trusting the CA, routing a Python agent, an end-to-end OpenAI example) see
> [docs/QUICKSTART.md](docs/QUICKSTART.md).

```powershell
# 1. Install deps and build
npm install
npm run build

# 2. Initialize the vault (sealed to your Windows account on this machine via DPAPI)
node dist/index.js init

# 3. Store a secret. It is ONLY ever injected toward the hosts you list here.
node dist/index.js secret set openai --value "sk-REAL-KEY" --host api.openai.com

# 4. Start the airlock (proxy + local control panel). This opens your browser.
node dist/index.js start
#    Proxy (point agents here): http://127.0.0.1:7788
#    Control panel:             http://127.0.0.1:7800/?token=<one-time-token>

# 5a. In the control panel: add an agent (its command), then flip its toggle to launch it
#     through the airlock — env is pre-wired so it only sees dummies.

# 5b. ...or run any command through the airlock directly:
node dist/index.js run -- python my_agent.py
```

Your agent now uses the placeholder `__OPENAI__` (or whatever you configured)
instead of the real key. Rotate the key with `secret rotate` and the agent
never changes — it only ever knew the dummy.

> `npm start` / `npm run airlock` are shortcuts for `node dist/index.js`.
> Throughout the docs, `airlock <cmd>` means `node dist/index.js <cmd>` (the
> package also installs an `airlock` bin that maps to `dist/index.js`).

---

## Architecture

```
                            YOUR MACHINE  (nothing below leaves it without policy approval)
  ┌──────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                    │
  │   ┌─────────────┐   dummy placeholders only      ┌──────────────────────────────┐ │
  │   │  AI AGENT   │  ──────────────────────────▶   │   PROXY  (the trust boundary)│ │
  │   │             │   HTTP(S)_PROXY=127.0.0.1:7788 │   loopback :7788             │ │
  │   │  sees only  │                                │                              │ │
  │   │ __OPENAI__  │  CONNECT api.openai.com:443    │  1. egress allowlist?        │ │
  │   │             │  CONNECT evil.com:443  ──────▶ │     no  -> 403 (deny default)│ │
  │   └─────────────┘                                │     yes -> TLS-intercept     │ │
  │         ▲                                        │  2. policy.evaluate()        │ │
  │         │ NODE_EXTRA_CA_CERTS / REQUESTS_CA_     │     deny | allow | approval  │ │
  │         │ BUNDLE point at airlock-ca.crt so the  │  3. inject REAL credential   │ │
  │         │ agent trusts the intercept cert.       │     (only toward allowedHosts)│ │
  │         │                                        │  4. verify REAL upstream cert │ │
  │         │                                        │  5. append-only hash-chained  │ │
  │         │                                        │     audit  (NEVER the value)  │ │
  │         │                                        └───────────────┬──────────────┘ │
  │   ┌─────┴───────┐                                                │ real key,      │
  │   │ CONTROL UI  │  127.0.0.1:7800  token-authed                  │ verified TLS   │
  │   │ (loopback)  │  NO reveal endpoint                            │                │
  │   └─────┬───────┘                                                │                │
  │         │ reads/writes metadata + policy                         │                │
  │   ┌─────▼─────────────────────────────────────┐                 │                │
  │   │  VAULT   vault.enc = AES-256-GCM(VDK, …)   │                 │                │
  │   │  VDK sealed by DPAPI -> vdk.seal           │   real values   │                │
  │   │  decrypted ONLY into proxy memory  ────────┼─────────────────┘                │
  │   └────────────────────────────────────────────┘                                  │
  │                                                                                    │
  └──────────────────────────────────────────────────────────────────────────│───────┘
                                                                               ▼
                                                                  ┌──────────────────────┐
                                                                  │  REAL UPSTREAM API    │
                                                                  │  api.openai.com, …    │
                                                                  │  (cert verified)      │
                                                                  └──────────────────────┘
```

**At-rest model** (all under the data dir):

| File | Contents |
|---|---|
| `vault.enc` | `AES-256-GCM(VDK, vaultJSON)` — portable, safe to back up, gibberish alone. |
| `vdk.seal` | `Sealer.seal(VDK)` — machine/account-bound (DPAPI on Windows). Enables daily auto-use. |
| `manifest.json` | Shamir(MRK) metadata for migration only. The VDK is `HKDF(MRK, salt)`. |
| `policy.json` | Egress allowlist + rules. Non-secret. `defaultAction` is forced to `deny` on load. |
| `config.json` | Ports, sealer kind, registered agents. Non-secret. |
| `audit.jsonl` | Append-only, hash-chained log. Never contains secret values. |
| `airlock-ca.crt` | The local CA cert to trust (public; not a secret). |
| `airlock-ca-bundle.pem` | System roots **+** the local CA, for tools that want one bundle. |
| `shares/` | Migration shares (`share-1.dpapi`, `share-2.pass.json`). Created only by `migrate setup`. |

Daily use unseals the VDK with no human and **without** reconstructing the MRK.
The MRK is reconstructed **only** during the deliberate migration ceremony.

---

## Why dummy + host-binding actually helps

Two independent mechanisms protect the real key, and you should understand both:

1. **Per-secret host binding.** A secret is injected **only** toward the hosts
   listed in its `allowedHosts`. If a hijacked agent sends `__STRIPE_KEY__` to
   `evil.com`, the proxy injects nothing — the literal dummy is forwarded, not
   the real key. The real key cannot go anywhere its own policy doesn't permit.
2. **Deny-by-default egress.** `evil.com` isn't on the allowlist, so the
   `CONNECT` was already refused with `403` long before injection was even
   considered.

Host patterns use a tiny glob (`*`, `?`) that is **fully anchored**:
`*.stripe.com` matches `api.stripe.com` but **not** `evil-stripe.com`. Prefer
exact hostnames where you can.

---

## Command reference

`airlock <cmd>` = `node dist/index.js <cmd>`. Data dir is printed by
`airlock help` and `airlock doctor`.

### Lifecycle

```
airlock init [--passphrase <p>]
        Initialize the vault, sealed by the platform sealer (DPAPI on Windows).
        --passphrase only applies to the passphrase sealer (Linux / forced).

airlock start            (alias: up)
        Start the proxy (:7788) and the local control panel (:7800), print the
        banner with the tokenized panel URL, and open it in your browser.
        Ctrl+C to stop.

airlock run -- <command...>
        Start the proxy, then run <command> with HTTP(S)_PROXY, NO_PROXY,
        NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, SSL_CERT_FILE, CURL_CA_BUNDLE
        and AIRLOCK_ACTIVE=1 pre-wired. The command sees only dummies. Exits
        with the child's exit code and stops the proxy.

airlock status
        Print runtime status as JSON (proxy/admin ports, sealer info, secret
        and agent summaries, policy, audit verification, migration state).

airlock doctor
        Environment self-test: platform, data dir, initialized?, auto-selected
        sealer, DPAPI self-test, sealer-create check, and whether ports 7788 /
        7800 are free.

airlock ca
        Print the CA cert path and instructions to trust it.

airlock env
        Print the proxy/CA environment variables for the current shell
        (PowerShell `$env:` syntax on Windows). Use to wire a shell by hand:
        `node dist/index.js env | Out-String | Invoke-Expression`
```

### Secrets

```
airlock secret set <name> (--value <v> | --stdin) --host <h> [--host <h2> ...]
        [--mode header|placeholder|query]
        [--header <H>]                  header mode: header name (default Authorization)
        [--template "Bearer {{secret}}"] header/placeholder: {{secret}} is substituted
        [--placeholder __NAME__]         placeholder mode dummy (default __<NAME>__)
        [--in-body]                      placeholder mode: also replace inside the body
        [--query-param <p>]              query mode param name (default api_key)
        [--desc <text>]
        --host is REQUIRED (one or more). The secret is ONLY ever injected
        toward these hosts. Setting a secret also opens egress for, and adds an
        allow rule covering, those hosts (turnkey, still deny-by-default).

airlock secret list
        List secret metadata: name, injection mode, allowed hosts, placeholder.
        NEVER prints the value (there is no code path that can).

airlock secret rm <name>
        Delete a secret and its auto-generated allow rule.

airlock secret rotate <name> (--value <v> | --stdin)
        Replace the real value. Agents are unaffected — they only knew the dummy.
```

**Injection modes.** Default mode is `header` unless you pass `--placeholder`
(which selects `placeholder` mode) or set `--mode` explicitly.

- `header` — sets a header (default `Authorization: Bearer {{secret}}`). The
  agent doesn't even need a dummy; the proxy adds the header for you.
- `placeholder` — the agent puts a dummy (e.g. `__OPENAI__`) wherever the key
  goes; the proxy swaps it in matching **headers**, and in the **body** too if
  `--in-body` is set.
- `query` — appends `?<param>=<secret>` to the URL (default param `api_key`).

### Policy & audit

```
airlock policy show
        Print the active policy (egress allowlist + rules) as JSON.

airlock audit [--limit <n>]      Show the last n entries (default 50).
airlock audit --verify           Recompute the hash chain and report the first
                                 broken entry, if any.
```

> The policy file is edited via the control panel (`PUT /api/policy`) or by hand
> in `policy.json`. There is no `airlock policy set` command. `defaultAction` is
> always re-forced to `deny` on load, so a bad edit can't open you up by default.

### Agents

```
airlock agent add --name <n> --command <c> [--arg <a> ...] [--cwd <d>]
        Register an agent (a command to launch through the airlock). Launch it
        from the control panel toggle, or with `airlock run -- <command> ...`.

airlock agent list
airlock agent rm <id>
```

### Migration

```
airlock migrate setup --passphrase <p>
        Configure the 2-of-3 recovery ceremony (passphrase must be >= 12 chars).
        Prints the OFFLINE recovery share ONCE (CA1-...). Print it; store it in a
        safe. See "Migration" below.

airlock migrate import --passphrase <p> --offline-share <s> [--delay <sec>]
        On a NEW machine (with the data dir copied over): reconstruct the vault
        from the human factors and re-seal it to this machine. --delay adds
        deliberate friction before reconstruction.
```

### Control panel API (loopback only)

`airlock start` also serves a token-authed control plane on `127.0.0.1:7800`.
Routes (all under `/api`, all require the `x-airlock-token` header except the
SSE stream which takes the token in the query): `status`, `secrets`
(GET/POST/DELETE, `POST .../rotate`), `policy` (GET/PUT), `audit`,
`audit/verify`, `approvals` (`POST .../approve|deny`), `agents`
(GET/POST/DELETE, `POST .../launch|stop`, `GET .../logs`), `proxy/start`,
`proxy/stop`, `migration/setup`, plus `GET /ca.crt`. **No route returns a secret
value.**

---

## Policy

Policy is **deny-by-default at two layers**:

1. **Egress** — the host must match the `egressAllowlist` glob, or the request
   is denied outright (the `CONNECT` never even completes).
2. **Rules** — within an allowed host, the **first matching rule** wins
   (`allow` | `deny` | `require_approval`). No matching rule ⇒ `deny`.

Each rule matches on `hosts` / `paths` / `methods` (any omitted field matches
anything) and may carry:

- **`rateLimit`** `{ max, windowSec }` — sliding window; over budget ⇒ deny.
- **`amountLimit`** `{ field, max, currency? }` — a **hard ceiling** on a named
  numeric field read from a JSON body (supports dot-paths like `a.b.c`) or a
  form body. Over the limit ⇒ deny. (See the Stripe example in
  [docs/ADAPTERS.md](docs/ADAPTERS.md).)
- **`action: require_approval`** — the request is **held** while a human
  approves it in the control panel. If nobody acts within **5 minutes** it
  **expires and is denied**.

Example `policy.json`:

```json
{
  "defaultAction": "deny",
  "egressAllowlist": ["api.openai.com", "api.stripe.com"],
  "rules": [
    { "id": "allow-openai", "match": { "hosts": ["api.openai.com"] }, "action": "allow",
      "rateLimit": { "max": 60, "windowSec": 60 } },
    { "id": "cap-charges", "match": { "hosts": ["api.stripe.com"], "paths": ["/v1/charges"] },
      "action": "require_approval", "amountLimit": { "field": "amount", "max": 5000, "currency": "usd" } }
  ]
}
```

---

## Audit

Every forwarded request, approval, admin action, and system/migration event is
written to `audit.jsonl` as one JSON line. The log is:

- **Append-only and hash-chained.** Each entry's `hash =
  SHA-256(prevHash || canonical(entry))`. Tampering with or deleting any line
  breaks the chain; `airlock audit --verify` reports the first broken `seq`.
- **Free of secret values.** It records secret **names** that were injected,
  never values, and a scrub pass strips any accidentally-included secret
  material before writing.

---

## Configuration & data locations

The data dir is resolved as:

| Platform | Path |
|---|---|
| **Windows** | `%LOCALAPPDATA%\CredentialAirlock` (e.g. `C:\Users\<you>\AppData\Local\CredentialAirlock`) |
| macOS | `~/Library/Application Support/CredentialAirlock` |
| Linux | `$XDG_DATA_HOME/credential-airlock` (else `~/.local/share/credential-airlock`) |

Environment overrides:

| Variable | Effect | Default |
|---|---|---|
| `AIRLOCK_HOME` | Override the entire data dir | platform path above |
| `AIRLOCK_PROXY_PORT` | Proxy port | `7788` |
| `AIRLOCK_ADMIN_PORT` | Control-panel port | `7800` |
| `AIRLOCK_SEALER` | Force a sealer kind (`dpapi`/`keychain`/`passphrase`) | platform auto |
| `AIRLOCK_PASSPHRASE` | Passphrase for the passphrase sealer | — |

The proxy and the control panel both bind **`127.0.0.1` only**. The control
plane is token-authed (the one-time token is embedded in the launch URL and
also written to `admin-token` with `0600` perms), enforces a `Host`-header
check against DNS-rebinding, and has **no endpoint that reveals a key**.

### The sealer, honestly

On Windows the sealer is **DPAPI** (`ProtectedData`, `CurrentUser` scope, with
app-specific entropy). That means:

- **It is OS/account-bound, not a hardware TPM.** The sealed `vdk.seal` decrypts
  only **as your Windows user, on this machine**. Copy it elsewhere and it's
  gibberish.
- **It is not hardware sealing.** We do **not** claim a hardware root of trust
  on the base Windows build. The honest claim is: *"sealed to your Windows
  account on this machine; a stolen disk or repo is useless elsewhere."*
- **Hardware sealing is the documented upgrade path.** The `Sealer` interface is
  pluggable (`dpapi` / `keychain` / `passphrase` today; `tpm` is reserved and
  currently a hard error pointing you at DPAPI). TPM 2.0 / Secure-Enclave
  sealing is future work, offered as an enterprise direction — not shipped here.

The sealer never silently downgrades: if DPAPI is unavailable, `init`/`open`
fail loudly rather than falling back to weaker crypto.

---

## Migration

Moving to a new machine is **possible but deliberately hard** — manual, heavily
verified, and impossible for one compromised machine to do silently. The key
idea is to separate **"use the key"** (machine-bound, automatic) from **"move
the key"** (human-bound, multi-factor, deliberate).

`airlock migrate setup --passphrase <p>` configures a **2-of-3 Shamir** split of
the Master Recovery Key:

- **Share 1 — `dpapi`:** sealed to **this** machine. Enables daily auto-use;
  enables **nothing** alone on a different machine.
- **Share 2 — `passphrase`:** your recovery passphrase (≥ 12 chars), protected
  with scrypt + AES-GCM. A human factor.
- **Share 3 — `offline`:** the `CA1-…` share printed **once**, never stored.
  Print it and put it in a safe. A second human factor.

**Daily use never reconstructs the MRK** — it only unseals the VDK via share 1.
On a new machine the DPAPI share can't unseal, so migration requires **both
human factors** (passphrase **and** offline share). One compromised running
machine can never migrate or export silently.

To migrate: copy the data dir to the new machine and run
`airlock migrate import --passphrase <p> --offline-share <CA1-…> [--delay <sec>]`.
On success the vault is re-sealed to the new machine; **strongly rotate your
upstream provider keys afterward** (belt and suspenders).

**The honest tension (we say this out loud):** any recovery path is also an
attack path. If an attacker fully obtains **both** human factors, they can
migrate too. We make that astronomically hard — multi-factor, an offline share,
optional delay and out-of-band confirmation — but we **cannot** make a vault
both recoverable by you and impossible for a perfect impersonator. Anyone
selling "unrecoverable AND recoverable" is lying. For headless fleets, don't
build a silent migration path at all: decommission the node, provision a fresh
one, and rotate the upstream keys.

---

## Before you sell this to others

This is currently fit for **personal / single-operator use and has not been
through a third-party security audit.** A product that holds other people's
keys is the highest-value target on the internet (see the LiteLLM and
Bitwarden-CLI incidents of 2026). Treat the
following as **non-negotiable before you make any public security claim** or put
this in front of someone else's credentials:

- [ ] **Minimal, pinned dependencies; review every one.** Supply chain is how
      LiteLLM-class incidents happen. (This build has a single runtime dep,
      `node-forge`, pinned to `1.4.0`; `npm run audit` reports 0 vulnerabilities.)
- [ ] **Signed, reproducible builds.** Ship artifacts a buyer can verify.
- [ ] **Run the proxy as its own unprivileged user** (its own
      user/namespace/container). It can unwrap real keys — it is the crown jewel.
- [ ] **No network-exposed admin or "reveal" endpoint. Ever.** The control plane
      stays loopback-only; there is deliberately no reveal route.
- [ ] **Third-party pentest before any public security claim.**

Until those are done, market it as exactly what it is: a self-hosted credential
firewall for your own agents, with honest limits.

---

## Claims we make / claims we do not make

Underpromise the guarantee, overdeliver the execution.

**CAN say (truthful, defensible):**

- "Your AI agents never hold your real API keys."
- "Keys are sealed to your hardware; a stolen disk or repo is useless
  elsewhere." *(On this Windows build, read "hardware" as "your Windows account
  on this machine" — DPAPI, not a TPM. See [the sealer note](#the-sealer-honestly).)*
- "Self-hosted: we never see or store your credentials."
- "Centralized policy and full audit logging for every agent request."

**CANNOT say (false / will get you breached or sued):**

- "Unhackable" / "100% secure" / "security that never existed."
- "Immune to prompt injection." (It stops key theft, not action abuse.)
- "Your keys can never be used by an attacker." (A compromised live machine can
  still use them within policy.)
- "Recoverable but impossible to steal." (Recovery = attack surface.)

---

## Documentation

- [docs/QUICKSTART.md](docs/QUICKSTART.md) — Windows 11 + PowerShell walkthrough,
  trusting the CA, routing a real agent, an end-to-end OpenAI example.
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — what it protects against, what it
  does **not**, concrete mitigations, and known limitations.
- [docs/ADAPTERS.md](docs/ADAPTERS.md) — copy-paste `secret set` recipes for
  OpenAI, Anthropic, Stripe, GitHub, Cloudflare, SendGrid, Slack, Gemini,
  Notion, and Twilio.

## About

Built and maintained by [ClassEve](https://classeve.com) — engineering for AI agents and developer tooling. Project page: [classeve.com/public/airlock](https://classeve.com/public/airlock).

## License

Apache-2.0. Copyright 2026 ClassEve. See [LICENSE](LICENSE).
