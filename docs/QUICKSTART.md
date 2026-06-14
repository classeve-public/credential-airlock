# Quickstart - Windows 11 + PowerShell

A precise, copy-paste walkthrough: install the airlock, store a secret, trust
the local CA, point a test client at the proxy, and route a real AI agent so it
only ever sees a dummy key.

Every command below uses the installed `airlock` CLI. In a source checkout,
`npm start`, `npm run airlock`, or `node dist/index.js <cmd>` run the same
entrypoint after `npm install && npm run build`.

> **Prerequisites:** Windows 11, **Node >= 20**, PowerShell. DPAPI sealing uses
> `powershell.exe` under the hood, which is present by default.

---

## 1. Install

```powershell
npm install -g credential-airlock
```

Sanity-check your environment:

```powershell
airlock doctor
```

You should see your platform, the data dir
(`%LOCALAPPDATA%\CredentialAirlock`), `sealer (auto): dpapi`, `DPAPI self-test:
OK`, and whether ports `7788` (proxy) and `7800` (control panel) are free. If
the DPAPI self-test fails, the vault can't seal — fix that before continuing.

---

## 2. Initialize the vault

```powershell
airlock init
```

This creates the data dir, generates the Vault Data Key (VDK) and the local CA,
and seals the VDK with **DPAPI** (`CurrentUser` scope). Output ends with the
sealer description, e.g. `Windows DPAPI (ProtectedData, CurrentUser scope, app
entropy)`.

> Re-running `init` when already initialized is a no-op and just prints the data
> dir. `secret set` will also auto-initialize if you skip this step.

---

## 3. Store a secret (bound to its host)

The most important flag is `--host`: a secret is **only ever injected toward the
hosts you list**. Setting a secret also opens egress for, and adds an allow rule
covering, those hosts — turnkey, but still deny-by-default for everything else.

Two common shapes:

```powershell
# Header mode (default): the proxy ADDS "Authorization: Bearer <real key>".
# The agent doesn't even need to know a placeholder.
airlock secret set openai --value "sk-REPLACE-ME" --host api.openai.com

# Placeholder mode: the agent uses a dummy you choose; the proxy swaps it.
airlock secret set openai `
  --value "sk-REPLACE-ME" `
  --host api.openai.com `
  --mode placeholder --placeholder __OPENAI__ --in-body
```

Avoid putting the real key in your shell history. Pipe it from stdin instead:

```powershell
$env:OPENAI_REAL = "sk-REPLACE-ME"
$env:OPENAI_REAL | airlock secret set openai --stdin --host api.openai.com
Remove-Item Env:\OPENAI_REAL
```

Verify (this prints **metadata only** — never the value):

```powershell
airlock secret list
# • openai  [header]  -> api.openai.com  (placeholder __OPENAI__)

airlock policy show
```

---

## 4. Start the airlock

```powershell
airlock start
```

You'll see a banner like:

```
   Proxy (point agents here): http://127.0.0.1:7788
   Control panel:             http://127.0.0.1:7800/?token=<one-time-token>
   Sealer:                    Windows DPAPI (ProtectedData, CurrentUser scope, app entropy)
   CA cert (trust this):      C:\Users\<you>\AppData\Local\CredentialAirlock\airlock-ca.crt
```

Your browser opens the tokenized control-panel URL. The token authenticates you;
treat that URL like a password. Leave this window running (`Ctrl+C` stops it).

The control panel lets you add/rotate secrets, edit policy, watch the live audit
stream, approve held requests, and register/launch agents — all over loopback,
with **no endpoint that reveals a key**.

---

## 5. Trust the local CA

For TLS hosts, the proxy intercepts the connection with a certificate minted by
the local CA. Your client must trust that CA or it will reject the connection.
You have three options; per-process env (the first two) is preferred over a
system-wide import.

Get the path any time:

```powershell
airlock ca
```

### Option A — per-process env (Node clients)

```powershell
$ca = Join-Path $env:LOCALAPPDATA "CredentialAirlock\airlock-ca.crt"
$env:NODE_EXTRA_CA_CERTS = $ca
```

### Option B — per-process env (Python / requests / curl)

Use the **bundle** (system roots **plus** the local CA), so other TLS still works:

```powershell
$bundle = Join-Path $env:LOCALAPPDATA "CredentialAirlock\airlock-ca-bundle.pem"
$env:REQUESTS_CA_BUNDLE = $bundle
$env:SSL_CERT_FILE      = $bundle
$env:CURL_CA_BUNDLE     = $bundle
```

### Option C — import `airlock-ca.crt` into the Windows trust store

Only if you need it system-wide (broadens what could be intercepted for your
user — scope to the process where you can):

```powershell
Import-Certificate -FilePath (Join-Path $env:LOCALAPPDATA "CredentialAirlock\airlock-ca.crt") `
  -CertStoreLocation Cert:\CurrentUser\Root
```

> **You usually don't need to do any of this by hand.** `airlock run`
> and the control-panel launch toggle wire `NODE_EXTRA_CA_CERTS`,
> `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, the proxy variables,
> and `AIRLOCK_ACTIVE=1` automatically for the process they launch.

---

## 6. Point a test client at the proxy

To wire your **current** shell by hand (e.g. to test with `curl`), print and
apply the env:

```powershell
airlock env
# emits $env:HTTP_PROXY=..., $env:NODE_EXTRA_CA_CERTS=..., etc.

# Apply it to THIS shell:
airlock env | Out-String | Invoke-Expression
```

Now exercise the firewall. A blocked host (not on the allowlist) is refused;
an allowed host is intercepted, the credential is injected, and the upstream
cert is verified:

```powershell
# Allowed: reaches OpenAI WITH your real key injected. You never typed the key here.
curl.exe https://api.openai.com/v1/models

# Blocked by deny-by-default egress -> 403 from credential-airlock:
curl.exe https://example.com/
```

Watch it happen live:

```powershell
airlock audit --limit 10
airlock audit --verify     # recompute the hash chain; should be ok:true
```

> Reset your shell when done: `Remove-Item Env:\HTTP_PROXY, Env:\HTTPS_PROXY,
> Env:\NODE_EXTRA_CA_CERTS, Env:\REQUESTS_CA_BUNDLE -ErrorAction SilentlyContinue`
> (or just open a new shell). `airlock run` and the launcher don't pollute your
> shell — they set env only for the child process.

---

## 7. Route an AI agent

The cleanest path: let the airlock launch your agent so its environment is
pre-wired and it sees only dummies.

### One-off, from any shell

```powershell
airlock run -- python my_agent.py
```

`run` starts the proxy (if not already running), launches the command with all
proxy/CA env set, streams its output, and exits with the child's exit code,
stopping the proxy afterward.

### Registered agent + control-panel toggle

```powershell
airlock agent add --name "research-bot" --command "python" --arg "my_agent.py"
airlock agent list
```

Then in the control panel (`http://127.0.0.1:7800/?token=…`), flip the agent's
toggle to launch it through the airlock and watch its requests and any approval
prompts in real time.

---

## 8. End-to-end OpenAI example (with a dummy)

This shows the whole point: the agent's code contains a **dummy**, never the
real key. The proxy swaps it on the way out.

**Configure the secret in placeholder mode** so the agent's literal `__OPENAI__`
gets replaced in the `Authorization` header (and body, with `--in-body`):

```powershell
$env:OPENAI_REAL = "sk-REPLACE-ME"
$env:OPENAI_REAL | airlock secret set openai `
  --stdin --host api.openai.com `
  --mode placeholder --placeholder __OPENAI__ --in-body
Remove-Item Env:\OPENAI_REAL
```

**`my_agent.py`** — note the key is the dummy string, not a real key, and there
is no real secret anywhere in the file or its environment:

```python
import os
from openai import OpenAI

# The agent only ever knows the DUMMY. The proxy injects the real key.
client = OpenAI(api_key="__OPENAI__")

resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Say hello from behind the airlock."}],
)
print(resp.choices[0].message.content)
```

**Run it through the airlock:**

```powershell
airlock run -- python my_agent.py
```

What happened end to end:

1. `run` set `HTTP(S)_PROXY=http://127.0.0.1:7788`, pointed the CA env at the
   bundle, and launched Python.
2. The OpenAI SDK sent `Authorization: Bearer __OPENAI__` to
   `api.openai.com` via the proxy.
3. The proxy checked the host against the egress allowlist (allowed), evaluated
   policy, **replaced `__OPENAI__` with your real key**, and forwarded the
   request to the real `api.openai.com` — **verifying its certificate**.
4. The append-only audit log recorded the request (`injected: ["openai"]`) —
   the secret **name**, never the value.

Confirm:

```powershell
airlock audit --limit 5
```

> Prefer header mode (`--mode header`) when the SDK lets the proxy own the
> `Authorization` header — then the agent needs no dummy at all. Use placeholder
> mode when the credential is embedded somewhere the proxy must find and swap.

---

## 9. (Optional) set up migration

If you'll ever move to another machine, configure the 2-of-3 recovery ceremony
**now**, while you have the working vault:

```powershell
airlock migrate setup --passphrase "correct horse battery staple"
```

This prints the **offline recovery share once** (`CA1-…`). Print it and store it
in a safe — it is never written to disk. To migrate later, copy the data dir to
the new machine and run, **on the new machine**:

```powershell
airlock migrate import --passphrase "correct horse battery staple" `
  --offline-share "CA1-...." --delay 0
```

You need **both** the passphrase and the offline share (the old machine's DPAPI
share can't unseal elsewhere). After a successful import, **rotate your upstream
provider keys**. See [README — Migration](../README.md#migration) and
[THREAT-MODEL.md](THREAT-MODEL.md) for the honest tension here.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Client error: self-signed / unknown CA | The CA isn't trusted by that client. Use `run` / the launcher, or set `NODE_EXTRA_CA_CERTS` / `REQUESTS_CA_BUNDLE` (§5). |
| `403 blocked_by_credential_airlock` | Host isn't on the egress allowlist, or a rule denied it. Add the host (e.g. via `secret set --host`) or adjust `policy.json`. |
| Request hangs, then is denied | A `require_approval` rule matched and nobody approved within 5 minutes (it expired). Approve it in the control panel. |
| `DPAPI self-test failed` | PowerShell / `System.Security.ProtectedData` unavailable. The vault can't seal on this machine. |
| `proxy port appears busy` | Another airlock is running, or `7788` is taken. Set `AIRLOCK_PROXY_PORT`. |
| Real key didn't get injected | Check `secret list`: is the host in `allowedHosts`, and is the mode/placeholder right? Placeholder-in-body requires `--in-body`. |
