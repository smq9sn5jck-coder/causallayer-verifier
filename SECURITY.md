# Security Policy

## Scope

This policy applies to the `causallayer-verifier` package and its
distributed npm artefacts. The verifier is the public attack surface of
CausalLayer's cryptographic accountability layer: anyone using it to
audit a CausalLayer accuracy claim must be able to trust that the
verifier itself has not been compromised.

## Supported versions

The verifier follows semantic versioning. Security fixes are issued
against the current minor release line. Older minor releases are
patched only when a vulnerability is exploitable in published anchor
records currently relied upon by third parties.

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a vulnerability

Please report security vulnerabilities **privately**. Do not open a
public GitHub issue.

- **Preferred channel:** [GitHub Security Advisories](https://github.com/smq9sn5jck-coder/causallayer-verifier/security/advisories/new)
- **Alternative channel:** open a minimal public issue requesting a
  private disclosure channel; we will provide one within two business
  days.

When reporting, please include:

1. A clear description of the vulnerability and its impact on a
   third-party verifier (e.g., does it allow a forged anchor to be
   accepted as valid? does it leak private-key material? does it
   enable denial-of-verification?).
2. A minimal reproducer (command line, anchor file, or test vector).
3. The version of the verifier and Node.js runtime under which the
   issue reproduces.
4. Whether you intend to publish the finding, and on what timeline.

## Disclosure timeline

- **Acknowledgement:** within two business days of receipt.
- **Triage and assessment:** within five business days.
- **Fix and release:** target within thirty days for critical issues
  (verifier accepts forged anchors, key-confusion, RCE in the verifier
  process); target within ninety days for lower-severity issues.
- **Coordinated disclosure:** we credit reporters by name (or pseudonym
  if requested) in the release notes and in `CHANGELOG.md`.

## Out-of-scope

The following are explicitly out of scope for this security policy and
should be reported through the standard issue tracker:

- Bugs that affect ergonomics, output formatting, or performance
  without affecting correctness of verification.
- Issues that depend on a verifier user already trusting a forged
  public key (key-distribution is the user's responsibility — see
  `public-key.pem` in the anchor-log repository for the canonical key).
- Issues in the engine itself (private repository) — these are
  reportable but cannot be triaged through this public repository.

## Cryptographic dependencies

This package has zero runtime dependencies. All cryptographic
operations use Node.js built-in modules (`crypto`). The signing scheme
is Ed25519 (RFC 8032). The anchor digest is SHA-256 (FIPS 180-4) over
canonical JSON. Independent timestamping is provided by
OpenTimestamps anchored to the Bitcoin blockchain.

## Public key

The canonical CausalLayer Ed25519 public key is published at:

- https://github.com/smq9sn5jck-coder/causallayer-anchor-log/blob/main/public-key.pem

Fingerprint (SHA-256 of DER-encoded public key):
`5b7fc9b398b162e4900f43bddf55cda93c8c7d0b1749cc86e0cbb5754582d6e6`

The canonical public key was rotated on 2026-05-14 during the
pre-genesis operational onboarding of the engine's publication
pipeline. The contemporaneous post-mortem is at
https://github.com/smq9sn5jck-coder/causallayer-anchor-log/blob/main/KEY-ROTATION-2026-05-14.md.
No authoritative anchor was ever signed under the prior key.

If you receive a CausalLayer anchor signed by any other key, treat it
as untrusted and report the discrepancy through the channel above.
