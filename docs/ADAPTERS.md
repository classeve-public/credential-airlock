# Adapters — provider cookbook

Copy-paste recipes for configuring popular APIs. Each entry gives the **host(s)**
to allow and the exact `airlock secret set ...` command (and/or injection
settings) to use.

How injection works, in one line each:

- **`header` mode** (default): the proxy **sets** a header on the outbound
  request - `--header <Name> --template "<value with {{secret}}>"`. The default
  is `Authorization: Bearer {{secret}}`. The agent needs no dummy.
- **`placeholder` mode**: the agent puts a dummy (e.g. `__OPENAI__`) where the
  key goes; the proxy swaps it in matching headers, and in the body too with
  `--in-body`. Select it with `--mode placeholder` or just by passing
  `--placeholder`.
- **`query` mode**: the proxy appends `?<param>=<secret>` to the URL -
  `--mode query --query-param <p>` (default param `api_key`).

Three rules that apply everywhere:

1. `--host` is **required** and is a **hard security bound** - the secret is
   only ever injected toward those hosts. Setting it also opens egress for, and
   adds an allow rule covering, those hosts.
2. Host patterns are a fully-anchored glob (`*`, `?`). `*.example.com` matches
   `api.example.com` but **not** `evil-example.com`. Prefer exact hostnames.
3. **Never put the real secret in your shell history.** Use `--stdin`:
   `Get-Content key.txt | airlock secret set <name> --stdin --host <h> ...`.

> Commands use the installed `airlock` CLI. In a source checkout, `npm run
> airlock -- <cmd>` or `node dist/index.js <cmd>` reaches the same entrypoint
> after build. PowerShell line-continuation is a backtick (`` ` ``).

---

## OpenAI

- **Host:** `api.openai.com`
- **Auth:** `Authorization: Bearer <key>`

```powershell
# Header mode (default) - proxy adds the Authorization header; agent needs no dummy.
airlock secret set openai --value "sk-..." --host api.openai.com

# Or placeholder mode - agent uses api_key="__OPENAI__" in code/body.
airlock secret set openai --value "sk-..." --host api.openai.com `
  --mode placeholder --placeholder __OPENAI__ --in-body
```

> Using the Azure OpenAI endpoint instead? It authenticates with an `api-key`
> header and a per-resource host - see [Azure OpenAI](#azure-openai-variant).

---

## Anthropic

- **Host:** `api.anthropic.com`
- **Auth:** `x-api-key: <key>` (note: **not** a Bearer token; also needs an
  `anthropic-version` header, which your SDK sets - the proxy only injects the key)

```powershell
airlock secret set anthropic --value "sk-ant-..." --host api.anthropic.com `
  --mode header --header "x-api-key" --template "{{secret}}"
```

`--template "{{secret}}"` injects the raw key with no `Bearer ` prefix.

---

## Stripe

- **Host:** `api.stripe.com`
- **Auth:** HTTP Basic with the secret key as the username -
  `Authorization: Basic base64(<key>:)`. The Stripe SDKs build this for you;
  for the airlock, inject it as a Bearer-style secret-key header, which Stripe
  also accepts (`Authorization: Bearer <key>`).

```powershell
airlock secret set stripe --value "sk_live_..." --host api.stripe.com
# default header mode => Authorization: Bearer sk_live_...
```

### Stripe with an amount cap (the headline policy feature)

Stripe charge/PaymentIntent amounts are sent as the `amount` field (in the
smallest currency unit - cents). Add a rule with an `amountLimit` so a hijacked
agent can't charge more than your ceiling. Over the limit is **denied**; pair it
with `require_approval` to hold borderline charges for a human.

Edit `policy.json` (data dir) or `PUT /api/policy` from the control panel. The
secret already created the egress entry and a baseline allow rule
(`allow-secret-stripe`); add a **more specific** rule and place it **before**
that baseline so it matches first:

```json
{
  "defaultAction": "deny",
  "egressAllowlist": ["api.stripe.com"],
  "rules": [
    {
      "id": "stripe-cap-charges",
      "description": "Hold any charge over $50.00 for human approval; hard-deny over the cap.",
      "match": { "hosts": ["api.stripe.com"], "paths": ["/v1/charges", "/v1/payment_intents"], "methods": ["POST"] },
      "action": "require_approval",
      "amountLimit": { "field": "amount", "max": 5000, "currency": "usd" }
    },
    { "id": "allow-secret-stripe", "match": { "hosts": ["api.stripe.com"] }, "action": "allow" }
  ]
}
```

How it behaves: Stripe charges are `application/x-www-form-urlencoded`, and the
amount cap reads the `amount` form field. A request with `amount=4200` is held
for approval (<= cap), `amount=9999` is **denied outright** (> cap), and the
approval card surfaces the amount and currency. (`amountLimit.field` also
supports dot-paths for JSON bodies, e.g. `transfer_data.amount`.)

---

## GitHub

- **Hosts:** `api.github.com` (REST/GraphQL). Add `uploads.github.com` if you
  upload release assets.
- **Auth:** `Authorization: Bearer <token>` (fine-grained / classic PAT or app
  token). `token <PAT>` also works; Bearer is preferred.

```powershell
airlock secret set github --value "ghp_..." `
  --host api.github.com --host uploads.github.com
# default header mode => Authorization: Bearer ghp_...
```

---

## Cloudflare

- **Host:** `api.cloudflare.com`
- **Auth:** `Authorization: Bearer <API token>` (recommended). Legacy
  global-key auth uses `X-Auth-Email` + `X-Auth-Key` headers instead - see note.

```powershell
airlock secret set cloudflare --value "cf_..." --host api.cloudflare.com
# default header mode => Authorization: Bearer cf_...
```

> Legacy global API key: that scheme needs **two** headers (`X-Auth-Email`,
> `X-Auth-Key`). Each `airlock` secret injects **one** header, so set the key as
> `--header "X-Auth-Key" --template "{{secret}}"` and let your client send the
> static, non-secret `X-Auth-Email` itself. Prefer scoped API tokens (single
> Bearer header) to avoid this.

---

## SendGrid

- **Host:** `api.sendgrid.com`
- **Auth:** `Authorization: Bearer <API key>`

```powershell
airlock secret set sendgrid --value "SG.xxxx" --host api.sendgrid.com
# default header mode => Authorization: Bearer SG.xxxx
```

---

## Slack

- **Host:** `slack.com` (Web API lives under `https://slack.com/api/...`)
- **Auth:** `Authorization: Bearer xoxb-...` (bot) or `xoxp-...` (user)

```powershell
airlock secret set slack --value "xoxb-..." --host slack.com
# default header mode => Authorization: Bearer xoxb-...
```

> Incoming webhooks (`hooks.slack.com`) embed the token in the **URL path**, not
> a header - that's a static URL secret, not a header injection. If you must,
> store the whole webhook URL out of band rather than through header injection.

---

## Google Gemini

- **Host:** `generativelanguage.googleapis.com`
- **Auth:** API key as a query parameter `?key=<key>` (the simple Gemini API
  key flow). OAuth bearer tokens are a separate flow.

```powershell
airlock secret set gemini `
  --value "AIza..." --host generativelanguage.googleapis.com `
  --mode query --query-param key
```

This appends `?key=<real key>` (or `&key=...`) to each request to that host. The
agent's code/URL contains no key.

> If you use Gemini via an `Authorization: Bearer` OAuth token instead, use
> header mode (default) and treat the bearer token as the secret. OAuth tokens
> are short-lived; rotate with `secret rotate` as they refresh.

---

## Notion

- **Hosts:** `api.notion.com`
- **Auth:** `Authorization: Bearer <integration token>` (also requires a
  static `Notion-Version` header, which your client sets).

```powershell
airlock secret set notion --value "secret_..." --host api.notion.com
# default header mode => Authorization: Bearer secret_...
```

---

## Twilio

- **Host:** `api.twilio.com`
- **Auth:** HTTP Basic - `AccountSid:AuthToken`. The proxy injects **one**
  header, so build the full `Basic` value and inject it as the secret.

```powershell
# Pre-compute Basic <base64(ACCOUNT_SID:AUTH_TOKEN)> and store THAT as the secret value.
$pair  = "AC_your_sid:your_auth_token"
$basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
$basic | airlock secret set twilio --stdin --host api.twilio.com `
  --mode header --header "Authorization" --template "Basic {{secret}}"
```

Here the "secret" is the base64 of `sid:token`; the proxy emits
`Authorization: Basic <that>`. Rotate by recomputing `$basic` after a token roll
and running `secret rotate twilio --stdin`.

> Twilio uses Basic auth, not request signing for the REST API, so simple header
> injection works. (Twilio **webhook signature validation** is a different,
> inbound concern and unrelated to outbound credential injection.)

---

## Azure OpenAI (variant)

- **Host:** `<your-resource>.openai.azure.com` (per-resource)
- **Auth:** `api-key: <key>` header

```powershell
airlock secret set azure-openai --value "..." `
  --host myresource.openai.azure.com `
  --mode header --header "api-key" --template "{{secret}}"
```

---

## What does NOT work: request-signing providers (e.g. AWS SigV4)

**Simple header/placeholder/query injection cannot support providers that sign
the request.** AWS (SigV4), Google Cloud service-account signed JWT flows,
Alibaba Cloud, and similar schemes don't send a static secret in a header.
Instead the client computes an **HMAC signature over the request** - method,
host, path, headers, a hash of the body, and a timestamp - using the secret key,
and sends only the resulting `Authorization: AWS4-HMAC-SHA256 ...Signature=...`
header.

Why the airlock can't inject that:

- The signature depends on the **exact** request the client built; there is no
  fixed string to swap in.
- The proxy injects credentials **after** the client has already sent the
  request, so it can't run the signing algorithm on the client's behalf, and any
  header it rewrites would **invalidate** a signature the client already
  computed.
- Recomputing the signature inside the proxy would mean re-implementing each
  provider's signing scheme and key-derivation — out of scope for this build,
  and exactly the kind of provider-specific complexity the simple-injection
  model deliberately avoids.

**What to do instead** for signed providers: keep using their native credential
chain (the AWS SDK with an instance/role or `~/.aws/credentials`, Workload
Identity, etc.) and rely on those providers' own scoping (IAM roles, short-lived
STS credentials, least privilege). You can still route that traffic through the
airlock for **egress allow-listing and audit** — just don't try to inject the
signing key. (Token-based services that send a static bearer/api-key header —
most of the providers above — are the sweet spot for injection.)
