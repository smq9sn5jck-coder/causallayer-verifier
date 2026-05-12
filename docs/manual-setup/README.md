# Manual setup: GitHub Actions workflows

This folder contains two GitHub Actions workflow files staged as `.txt`
because the integration that authored this PR does not hold the
`workflows` repo permission. Once a maintainer with write access to
`.github/workflows/` adds them, the verifier will publish to npm
automatically on every `vX.Y.Z` tag and run CI on every push and PR.

## One-time setup

1. Create the workflow files (in the GitHub web UI or locally):

   ```bash
   mkdir -p .github/workflows
   cp docs/manual-setup/release.yml.txt .github/workflows/release.yml
   cp docs/manual-setup/ci.yml.txt      .github/workflows/ci.yml
   git add .github/workflows/release.yml .github/workflows/ci.yml
   git commit -m "ci: add release and CI workflows"
   git push
   ```

2. Add an npm automation token as a repo secret:

   - Generate the token at <https://www.npmjs.com/settings/~/tokens>
     (token type: **Automation** — automation tokens skip the
     interactive 2FA prompt that CI cannot answer).
   - Add it at **Settings → Secrets and variables → Actions → New
     repository secret**, name `NPM_TOKEN`.

## Cutting the first release

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow will verify the tag matches `package.json`, run
`npm test`, then `npm publish --provenance --access public`. The
`--provenance` flag attaches a cryptographically verifiable build
attestation to the npm page so consumers can confirm the published
tarball was built from this exact GitHub commit by this exact workflow
— a strictly stronger trust signal than a hand-published package, which
matters for a moat verifier.

After the first successful publish, the README's
`npm install -g causallayer-verifier` instruction resolves for the
first time.

## Why these are staged as `.txt`

GitHub Apps require a separate, opt-in `workflows` permission to add or
modify files under `.github/workflows/`. This permission was not
granted to the integration that opened this PR. Staging the workflow
files as `.txt` lets the rest of the release plumbing (CHANGELOG,
RELEASING, .npmignore, `publishConfig.provenance`, `prepublishOnly`)
ship now, with the workflow files copied into place by a human or
re-pushed after the permission is granted.
