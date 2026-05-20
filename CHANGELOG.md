# Changelog

All notable changes to `causallayer-verifier` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Any change to the canonical-JSON algorithm, the Merkle tree construction, or
the signature scheme is a **major** version bump, accompanied by a written
deprecation notice in the public anchor-log repository.

## [Unreleased]

### Documented

- `RELEASING.md` already references `.github/workflows/release.yml` for the
  automated tag-triggered npm publish flow, but the workflow file itself was
  never committed. Pushing a `vX.Y.Z` tag therefore did nothing. The
  workflow content is documented in the `feature/release-workflow` PR
  description for manual addition via the GitHub UI (the bot identity used
  for repo automation lacks the `workflows` permission needed to commit
  files under `.github/workflows/`).
- A companion CI workflow (`ci.yml`) running the unit + 36-vector
  adversarial suite on Node 18 / 20 / 22 for every push and PR to `main` is
  also documented in the PR for manual addition.

## [0.1.0] — Initial public release

### Added

- Independent, zero-dependency verifier for CausalLayer / Faultkey signed
  daily accuracy ledgers and Merkle anchor records.
- `lib/index.js` programmatic API: `verifyAnchor`, `computeMerkleRoot`,
  `verifySignature`, `canonicalJSON`.
- `bin/causallayer-verify` CLI for verifying anchor files against a public
  Ed25519 key, with `--offline` mode.
- 4 smoke tests covering canonical JSON, Merkle root recomputation,
  Ed25519 signature verification, and tamper detection.
- Strict semver versioning policy documented in `STATUS.md`.
- Uses only the Node.js standard library (`node:crypto`, `node:fs`,
  `node:path`). No runtime dependencies.

### Trust model

This package is intentionally designed to be auditable in one sitting
(under 200 lines of standard-library Node.js) and runnable fully offline.
It makes no network calls back to CausalLayer at verification time.

[Unreleased]: https://github.com/smq9sn5jck-coder/causallayer-verifier/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/smq9sn5jck-coder/causallayer-verifier/releases/tag/v0.1.0
