# causallayer-verifier

> **Independent, zero-dependency verifier** for the
> [CausalLayer](https://github.com/smq9sn5jck-coder/causallayer-anchor-log) AI-liability engine's
> signed daily accuracy ledgers and Merkle anchor records.

[![npm](https://img.shields.io/npm/v/causallayer-verifier.svg)](https://www.npmjs.com/package/causallayer-verifier)
[![CI](https://github.com/smq9sn5jck-coder/causallayer-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/smq9sn5jck-coder/causallayer-verifier/actions/workflows/ci.yml)
[![tests](https://img.shields.io/badge/tests-40%20passing-brightgreen)](test/)
[![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](package.json)
[![provenance](https://img.shields.io/badge/npm-provenance-blue)](https://docs.npmjs.com/generating-provenance-statements)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](#install)

> **Self-audited.** 4 smoke tests + 36 adversarial vectors covering Merkle tampering,
> signature forgery, ledger-chain breakage, and canonical-JSON ordering.
> Run `npm test` to reproduce. The release pipeline blocks publishing if any vector regresses.

Audit any AI-liability accuracy claim CausalLayer makes — without trusting
the vendor, without an account, without an API key, without a network call
back to CausalLayer. Just the [public anchor log](https://github.com/smq9sn5jck-coder/causallayer-anchor-log),
the published Ed25519 public key, and ~30 lines of standard-library Node.

---

## Why this exists

Every AI vendor claims accuracy. Almost none let you check the claim
cryptographically after the fact, without their cooperation. CausalLayer's
product is *causal liability analysis for AI incidents* — assigning fault
between agents, vendors, and operators. That product is worthless unless
its accuracy track record is independently verifiable, especially in
adversarial settings (litigation, regulatory enforcement, insurance
disputes).

This package exists so any third party — opposing counsel, an
internal-audit team, a regulator, an insurer, a journalist — can:

1. Pull a daily anchor record from the public
   [`causallayer-anchor-log`](https://github.com/smq9sn5jck-coder/causallayer-anchor-log) repo.
2. Recompute the Merkle root from the leaves.
3. Verify the Ed25519 signature against the publicly published key.
4. Independently confirm the OpenTimestamps proof against the Bitcoin blockchain.

If any of those four steps fails, the accuracy claim CausalLayer made on
that date is provably false.

---

## Install

```bash
npm install -g causallayer-verifier
# or run ad-hoc with npx
npx causallayer-verifier <anchor.json>
```

Requires Node ≥ 18. **Zero runtime dependencies** — only Node's built-in
`crypto`, `fs`, and `path` modules. Audit `lib/index.js` (about 130 lines)
yourself before trusting it.

---

## CLI usage

```bash
# Clone the public anchor log
git clone https://github.com/smq9sn5jck-coder/causallayer-anchor-log
cd causallayer-anchor-log

# Verify any anchor (uses the sibling public-key.pem automatically)
causallayer-verify anchors/2026-05-10.json

# Or pass an explicit key path
causallayer-verify anchors/2026-05-10.json --key ./public-key.pem

# Verify the OpenTimestamps proof (requires `pip install opentimestamps-client`)
ots verify anchors/2026-05-10.json.ots
```

Output:

```
anchor file  : /path/to/anchors/2026-05-10.json
public key   : /path/to/public-key.pem
anchor date  : 2026-05-10
leaf count   : 17
merkle root  : OK
ed25519 sig  : OK   algo=ed25519
ots proof    : present  (run: ots verify anchors/2026-05-10.json.ots)
```

Exits **0** on full success, **1** on verification failure, **2** on
invalid usage.

---

## Library usage

```js
const {
  merkleRoot,
  verifyAnchor,
  verifyLedgerLink,
  verifySignature,
} = require("causallayer-verifier");
const fs = require("node:fs");

const record = JSON.parse(fs.readFileSync("anchors/2026-05-10.json", "utf8"));
const publicKeyPem = fs.readFileSync("public-key.pem", "utf8");

const { merkleOk, signatureOk } = verifyAnchor(record, publicKeyPem);
if (!merkleOk || !signatureOk) {
  throw new Error("CausalLayer anchor failed independent verification");
}
```

---

## What gets verified

| Layer                    | Property checked                                                  | How |
|--------------------------|-------------------------------------------------------------------|-----|
| Ledger row               | Hash chain from row N to row N-1                                  | `verifyLedgerLink(prev, cur)` |
| Daily Merkle anchor      | Recomputed root equals claimed root                               | `verifyAnchor(record, key)` |
| Engine authorship        | Ed25519 signature over canonical-JSON payload                     | `verifyAnchor(record, key)` |
| Time of existence        | OpenTimestamps proof anchored to a Bitcoin block                  | `ots verify <file>.ots` (external) |
| Public-key authenticity  | Compare `public-key.pem` fingerprint to multiple published copies | manual / out-of-band |

Combined, a forged claim requires (a) a SHA-256 collision, (b) a
post-hoc rewrite of the `causallayer-anchor-log` GitHub history, **and**
(c) a rewrite of the Bitcoin blockchain. None of the three is feasible.

---

## Public key — where to fetch

The canonical Ed25519 public key is published in the
[`causallayer-anchor-log`](https://github.com/smq9sn5jck-coder/causallayer-anchor-log) repository:

- [`public-key.pem`](https://github.com/smq9sn5jck-coder/causallayer-anchor-log/blob/main/public-key.pem) (PEM)
- [`public-key.jwk.json`](https://github.com/smq9sn5jck-coder/causallayer-anchor-log/blob/main/public-key.jwk.json) (JWK)
- [`fingerprint.txt`](https://github.com/smq9sn5jck-coder/causallayer-anchor-log/blob/main/fingerprint.txt) (SHA-256 fingerprint)

GitHub's commit history makes silent rotation of the fingerprint detectable.
If in doubt about authenticity, cross-check the fingerprint against
out-of-band sources (e.g., a CausalLayer team member's signed message).

> **Bootstrap notice (May 2026):** The public key currently shipped is a
> *development* key. The first authoritative anchor commit will publish the
> production key and rotate the bootstrap files. Do not pin the bootstrap
> fingerprint.

---

## Reporting integrity issues

If you find a discrepancy between a published anchor and what CausalLayer
claims publicly, please file a P0 issue on this repo:
<https://github.com/smq9sn5jck-coder/causallayer-verifier/issues>.

---

## What is CausalLayer?

**CausalLayer** is a deterministic causal-attribution engine for AI-liability
incidents. Given a description of an AI failure (a Tesla AutoPilot crash, a
rogue agent decision, a privacy violation), it produces a structured
allocation of fault across the parties involved (manufacturer, deployer,
operator, user), an estimated damages range calibrated against ~44 verified
settlement cases, and a full auditable causal chain.

This verifier doesn't run the engine — it lets anyone independently confirm
the engine's *published accuracy claims*. The engine itself is private; the
receipts are public.

## Related

- Public anchor log: <https://github.com/smq9sn5jck-coder/causallayer-anchor-log>
- Genesis declaration: <https://github.com/smq9sn5jck-coder/causallayer-anchor-log/blob/main/GENESIS.md>
- Current status (what's verifiable today vs. pending): <https://github.com/smq9sn5jck-coder/causallayer-anchor-log/blob/main/STATUS.md>

## License

[MIT](LICENSE)
