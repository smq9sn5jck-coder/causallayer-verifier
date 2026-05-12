# Changelog

All notable changes to `causallayer-verifier` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Any change to the canonical-JSON algorithm, the Merkle tree construction, or
the signature scheme is a **major** version bump, accompanied by a written
deprecation notice in the public anchor-log repository.

## [Unreleased]

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
