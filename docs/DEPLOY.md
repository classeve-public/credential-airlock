# Deploying Credential Airlock

Credential Airlock is loopback-only by design: the proxy and control panel bind
`127.0.0.1` (coerced at startup). The deployment question is therefore mostly
**which sealer protects the vault** and **how the agent reaches the loopback
proxy**. This guide covers both, with least-privilege hardening for each mode.

## Sealer by platform (honest)

| Platform | Sealer | Bound to | Notes |
|---|---|---|---|
| Windows | **DPAPI** | your Windows account on this machine | the daily-use path; run as your user (not SYSTEM) |
| macOS | **Keychain** | user + machine (ThisDeviceOnly) | needs an unlocked login keychain |
| Linux / container | **passphrase** (scrypt) | the passphrase you supply | use a file-based secret, never a plain env var in production |

DPAPI/Keychain are OS/account-bound, **not** a hardware TPM. TPM/Secure-Enclave
and KMS sealers are the documented pluggable upgrade. To move a vault between
machines, use the migration ceremony (`airlock migrate`), not a file copy.

## Mode 1 — Windows host (recommended for personal use)

```powershell
npm install -g credential-airlock
airlock init
airlock secret set openai --value <KEY> --host api.openai.com

$pkg = Join-Path (npm root -g) 'credential-airlock'
& (Join-Path $pkg 'deploy\install-service-windows.ps1') # start at logon, as your user, non-elevated
Start-ScheduledTask -TaskName 'CredentialAirlock'
```

Run agents through it: `airlock run -- <agent...>` (wires HTTP(S)_PROXY + the
CA automatically), or point a shell at it with `airlock env`.

## Mode 2 — macOS host

```bash
npm install -g credential-airlock
airlock init        # uses the Keychain sealer
airlock secret set openai --value <KEY> --host api.openai.com
airlock start
```

For autostart, wrap `airlock start` in a `launchd` LaunchAgent (user agent, so
it runs as you and the Keychain is unlocked).

## Mode 3 — Linux host (systemd, hardened)

Use the passphrase sealer with a root-only secret file. Full steps are in the
header of [`deploy/airlock.service`](../deploy/airlock.service):

```bash
sudo useradd --system --home-dir /var/lib/credential-airlock --shell /usr/sbin/nologin airlock
npm install -g credential-airlock
NPM_ROOT="$(npm root -g)"
sudo mkdir -p /opt/credential-airlock
sudo cp -a "$NPM_ROOT/credential-airlock/." /opt/credential-airlock/
sudo install -d -m 700 /etc/credential-airlock
printf '%s' 'a-long-random-passphrase' | sudo tee /etc/credential-airlock/passphrase >/dev/null
sudo chmod 600 /etc/credential-airlock/passphrase
sudo cp deploy/airlock.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now airlock
```

The unit runs as a dedicated unprivileged user with `ProtectSystem=strict`,
`NoNewPrivileges`, a seccomp `@system-service` filter, all capabilities dropped,
and the passphrase delivered via `LoadCredential` (never in the unit text or the
process environment dump).

## Mode 4 — Docker / Compose (distroless, non-root)

```bash
printf '%s' 'a-long-random-passphrase' > airlock_passphrase.txt
docker compose up --build
```

The image is **distroless and non-root (uid 65532)**, the rootfs is read-only,
all caps are dropped, `no-new-privileges` is set, and the passphrase arrives as a
Docker secret (`AIRLOCK_PASSPHRASE_FILE`). The container has **no published
ports** — see networking below.

## Networking model: loopback + sidecar

The proxy is loopback-only, so an agent must reach `127.0.0.1:7788` **inside the
same network namespace**:

- **Same host (host installs):** the agent runs on the same machine — just set
  `HTTP_PROXY`/`HTTPS_PROXY` to `http://127.0.0.1:7788` (or use `airlock run`).
- **Containers:** run the agent as a **sidecar** sharing the airlock's netns
  (`network_mode: "service:airlock"` in Compose, or the same Pod in Kubernetes).
  The provided `docker-compose.yml` shows this. Never publish 7788/7800 to a
  network — that would break the loopback-only invariant.

Each agent must trust the CA at `$AIRLOCK_HOME/airlock-ca.crt` (mounted at
`/data/airlock-ca.crt` in the container). `airlock run` and the launcher wire
`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and
`GIT_SSL_CAINFO` for you.

## Monitoring

- **Liveness/readiness:** `airlock health` (shallow) exits non-zero if the proxy
  isn't listening or `config.json` is corrupt; `airlock health --deep` additionally
  opens the vault and verifies the audit chain, exiting non-zero if either fails.
  Use the deep form as a container healthcheck (already wired in Compose) or a k8s
  probe; the shallow form as a quick systemd watchdog.
- **Integrity:** `airlock audit --verify` returns the chain status `{ ok, entries }`;
  **alert if `ok` is false.** A set tamper marker, an in-place edit, a gap, or tail
  truncation all surface as `ok:false` (there is no separate `tamper` field).
- **Logs:** structured logs go to stdout — ship them with your normal collector.
  They never contain secret values.

## Backup, restore, migrate

- `airlock backup --out airlock-backup.tar` archives the **sealed** data dir
  (vault, CA, audit, config). It contains no plaintext, but on Windows/macOS the
  sealed VDK is machine-bound, so a backup restores **on the same machine**
  (disaster recovery for accidental deletion).
- `airlock restore airlock-backup.tar` restores it (refuses to clobber a live
  vault unless `--force`).
- To move to a **new machine**, set up `airlock migrate` (Shamir 2-of-3) and
  import there — do not copy the sealed VDK across machines.

## Upgrades

Host installs:

```bash
npm install -g credential-airlock@latest
sudo systemctl restart airlock  # Linux service installs
```

Windows scheduled-task installs pick up the upgraded global package on next
start. Container installs should rebuild from the pinned release tag or tarball.
The config carries a `version`; the vault format is stable. Run `airlock health`
after upgrading.

## Hardening checklist

- [ ] Run as a dedicated, **non-root / non-admin** user (service files do this).
- [ ] Passphrase via a **file secret**, never a plain env var, in production.
- [ ] **Do not publish** ports 7788/7800 to any network.
- [ ] Restrict the data dir to the service user (`chmod 700`).
- [ ] Wire `airlock health` into your supervisor and alert on `audit --verify`.
- [ ] Keep the host patched and Node current; CI gates `npm audit` on every push.
