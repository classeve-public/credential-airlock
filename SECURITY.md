# Security Policy

Credential Airlock is a security product. We treat vulnerability reports as the
highest-priority work and we hold ourselves to an honest, coordinated process.

## Honest status

This build has been through **eight internal adversarial review rounds** and a
**209-assertion automated test suite** (see [docs/AUDIT.md](docs/AUDIT.md)). It
has **not** yet had an independent third-party penetration test. We have prepared
a turnkey scope for one in [docs/PENTEST.md](docs/PENTEST.md). Until that is
signed off, do not treat Credential Airlock as certified to hold a third party's
production credentials under guarantee. It is ready for self-hosted, single-
operator and trusted-team use with the model described in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## No telemetry

Credential Airlock **never phones home.** It makes no outbound connection except
the upstream API calls your own agents make through the proxy. There is no
analytics, no crash reporting, no license check, no update ping. You can verify
this with the airlock pointed at itself, or with any network monitor.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.x (latest minor) | ✅ security fixes |
| older 0.x | ❌ please upgrade |

Until 1.0, only the latest released minor receives security fixes.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Preferred: open a private report via GitHub Security Advisories:
<https://github.com/classeve-public/credential-airlock/security/advisories/new>

If you cannot use GitHub advisories, email the maintainer privately at
**ranjitbarnala0@gmail.com**. This inbox is monitored for security reports; for
anything sensitive, ask in your first message and we will arrange an encrypted
channel before you send details.

Please include:

- A description of the issue and the security impact.
- Step-by-step reproduction (a script or request capture is ideal).
- The affected version / commit (`airlock --help` shows the build; `git rev-parse HEAD`).
- Your assessment of severity and any suggested fix.

If you find a way to **extract a sealed secret value**, **inject a credential
toward a non-allowlisted host**, **bypass deny-by-default egress**, or **tamper
the audit log without detection**, that is critical — say so up front.

## Our commitments (response targets)

| Stage | Target |
|-------|--------|
| Acknowledge your report | within **72 hours** |
| Initial triage + severity | within **7 days** |
| Fix for Critical/High | prioritized; coordinated release ASAP |
| Fix for Medium/Low | next scheduled release |

We will keep you updated, credit you (if you wish), and coordinate disclosure.

## Coordinated disclosure

We ask for up to **90 days** to ship a fix before public disclosure, and we will
work with you on timing. We will publish a security advisory and a
[CHANGELOG](CHANGELOG.md) entry for every fixed vulnerability.

## Safe harbor

We will not pursue or support legal action against researchers who:

- Act in good faith and avoid privacy violations, data destruction, and service
  degradation against systems they do not own.
- Only test against **their own** installation of Credential Airlock.
- Give us reasonable time to remediate before public disclosure.

Testing against your own local install is explicitly welcome — see
[docs/PENTEST.md](docs/PENTEST.md) for a ready-made scope and target setup.

## Scope

In scope: the proxy trust boundary, the injection path, the policy engine, the
vault/sealing, the audit chain, the loopback control plane + UI, the CLI, and the
migration ceremony. Out of scope: full root/admin compromise of the host at use
time (the proxy necessarily holds plaintext keys in memory — only confidential
computing closes that; it is a documented future tier). See the threat model for
the full boundary.
