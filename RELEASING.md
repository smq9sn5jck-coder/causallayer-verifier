# Releasing

This package publishes to npm automatically via the
[`Release to npm`](.github/workflows/release.yml) GitHub Action whenever a
semver tag `vX.Y.Z` is pushed.

## One-time setup

1. Generate an npm **automation** token (not a publish token) at
   <https://www.npmjs.com/settings/~/tokens>. Automation tokens skip the
   interactive 2FA prompt, which is what CI needs.
2. Add the token to this repo at
   **Settings → Secrets and variables → Actions → New repository secret**
   with the name `NPM_TOKEN`.

## Cutting a release

```bash
# 1. Bump the version in package.json and CHANGELOG.md
npm version patch    # or: minor / major
# (this creates a commit and a tag locally)

# 2. Push commit + tag
git push origin main --follow-tags
```

The workflow will:

1. Verify the pushed tag's version matches `package.json`.
2. Run `npm test`.
3. Run `npm publish --provenance --access public`. The `--provenance` flag
   records a cryptographically verifiable build attestation on npm so
   consumers can confirm the published tarball was built from this exact
   GitHub commit by this exact workflow.
4. Create a GitHub Release with auto-generated notes.

## What gets published

The npm tarball contains only the files listed in `package.json`'s `files`
field: `lib/`, `bin/`, `README.md`, `LICENSE`. The CI workflow's
`npm pack --dry-run` check enforces this so future additions can't
silently bloat the tarball or leak dev-time files.

## Versioning policy

Strict semver. Any change to the canonical-JSON algorithm, the Merkle tree
construction, or the signature scheme is a **major** version bump,
accompanied by a written deprecation notice in the public anchor-log
repository (see `STATUS.md`).
