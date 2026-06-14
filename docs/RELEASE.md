# Release Runbook

This runbook is for maintainers cutting a public Credential Airlock release from
`classeve-public/credential-airlock`.

## Release Requirements

- GitHub repository is public.
- GitHub Actions are enabled.
- npm package ownership is ready for `credential-airlock`.
- Either npm trusted publishing is configured for this repository, or the repo
  has an `NPM_TOKEN` secret with publish rights.
- Local checks pass on the release commit.

Do not create a release tag until the npm publishing prerequisite is ready. The
tag workflow publishes the package, creates the GitHub release assets, generates
the SBOM, computes checksums, and writes build-provenance attestation.

## Preflight

```bash
npm ci
npm test
npm run audit
npm run package:check
npm run smoke:install
npm run loadtest
npm pack --dry-run
```

Confirm the packed file list includes:

- `dist/`
- `docs/`
- `deploy/`
- `public/`
- `scripts/`
- `README.md`, `NOTICE.md`, `LICENSE`, `CHANGELOG.md`, `SECURITY.md`
- `policy.example.json`, `Dockerfile`, `docker-compose.yml`

## Cut A Release

```bash
git checkout main
git pull --ff-only
npm version patch --no-git-tag-version
npm install --package-lock-only --ignore-scripts
npm test
npm run audit
npm run smoke:install
git add package.json package-lock.json CHANGELOG.md
git commit -m "release: v0.1.1"
git tag -s v0.1.1 -m "Credential Airlock v0.1.1"
git push origin main
git push origin v0.1.1
```

If you do not use signed tags locally, use an annotated tag:

```bash
git tag -a v0.1.1 -m "Credential Airlock v0.1.1"
```

## After The Workflow

Verify:

- GitHub Release exists for the tag.
- `.tgz`, `sbom.cdx.json`, and `SHA256SUMS.txt` are attached.
- npm shows the published version:

```bash
npm view credential-airlock version
npm install -g credential-airlock@latest
airlock doctor
```

## Rollback

npm releases are immutable. If a bad version is published:

1. Publish a fixed patch version.
2. Mark the bad version deprecated:

```bash
npm deprecate credential-airlock@0.1.1 "Use credential-airlock@0.1.2 or newer."
```

3. Publish a GitHub advisory if the release has security impact.
