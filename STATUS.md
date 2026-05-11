# Verifier Status

> Honest, single-page status of the independent CausalLayer verifier package.
> See also: [`causallayer-anchor-log/STATUS.md`](https://github.com/smq9sn5jck-coder/causallayer-anchor-log/blob/main/STATUS.md).

---

## What this package is

A standalone, zero-dependency Node.js package that independently verifies CausalLayer signed
anchor records. It uses only the Node standard library (`node:crypto`, `node:fs`,
`node:path`). It makes **no network calls back to CausalLayer**. It requires no API key,
no account, and no permission from the vendor.

If you can run `node`, you can audit CausalLayer.

---

## What you can verify with this package today

| Capability | Status |
|---|---|
| Recompute Merkle root over an anchor's leaf set | **Working** |
| Verify Ed25519 signature against the published public key | **Working** |
| Confirm the canonical JSON serialisation matches the engine | **Working** |
| Detect any tampering with an anchor file after the fact | **Working** |
| Print OpenTimestamps proof file path for separate OTS verification | **Working** |
| Verify any anchor currently in the public anchor log | **Working — no anchors exist yet (pre-genesis)** |

---

## What this package deliberately does NOT do

- It does not connect to CausalLayer servers for any reason.
- It does not fetch the public key over the network — the public key is bundled in the
  verifier package and in the anchor-log repository, so the verifier can be run completely
  offline once cloned.
- It does not validate the *content* of the underlying liability attributions. Verification is
  cryptographic, not substantive. Whether a specific attribution is *correct* is a question for
  the engine's accuracy methodology, not for this verifier.

---

## Trust model

The verifier is intentionally designed to be trustable by an adversary. Specifically:

1. Read [`bin/verify-anchor.js`](./bin/verify-anchor.js) and [`lib/`](./lib/) yourself.
   The entire codebase is under 200 lines of standard-library Node. If you cannot audit it in
   one sitting, the package is too complex and we have failed.
2. Fetch the public key from any independent source: the public anchor-log repository, the
   marketing site's `.well-known` directory, an independent mirror, or directly from a
   regulator or auditor who has obtained their own copy.
3. Run the verifier locally with `--offline` or simply disconnect from the network. There is
   no network dependency at verification time.

If the verifier ever requires anything more than this, the moat is broken and we want to know
about it. Open a public issue.

---

## Versioning policy

The package follows strict semantic versioning. Any change to the canonical-JSON algorithm, the
Merkle tree construction, or the signature scheme is a **major** version bump and is accompanied
by a written deprecation notice in the anchor-log repository. We do not change verification
semantics silently.

The exact verification semantics required to validate any anchor are pinned by the major version
number recorded in the anchor record itself (when present). An anchor signed under verifier
version `1.x` is verified by the latest `1.x` verifier; future major versions remain
backward-compatible for old anchors.

---

## Reporting issues

If you find a verification edge case, a security issue, or any discrepancy between this
verifier and the published anchor log, please open a public issue at
<https://github.com/smq9sn5jck-coder/causallayer-verifier/issues>. Security issues that should
not be publicly disclosed before remediation can be reported privately via the contact email
listed in `package.json`.

---

*Last material change tracked via GitHub commit history of this file.*
