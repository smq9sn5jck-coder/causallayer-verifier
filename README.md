# causallayer-verifier

> **Independent, zero-dependency verifier** for [CausalLayer / Faultkey](https://faultkey.ai)
> signed daily accuracy ledgers and Merkle anchor records.

[![npm](https://img.shields.io/npm/v/causallayer-verifier.svg)](https://www.npmjs.com/package/causallayer-verifier)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](#install)

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

The canonical Ed25519 public key is published at:

- <https://faultkey.ai/.well-known/causallayer-cert/public-key.pem> (PEM)
- <https://faultkey.ai/.well-known/causallayer-cert/public-key.jwk.json> (JWK)
- <https://faultkey.ai/.well-known/causallayer-cert/fingerprint.txt> (SHA-256 fingerprint)
- Mirrored in the [`causallayer-anchor-log`](https://github.com/smq9sn5jck-coder/causallayer-anchor-log) repo

If those copies ever disagree, **do not trust either** until you have
out-of-band confirmation of the correct fingerprint.

> **Bootstrap notice (May 2026):** The public key currently shipped is a
> *development* key. The first authoritative anchor commit will publish the
> production key and rotate the bootstrap files. Do not pin the bootstrap
> fingerprint.

---

## Reporting integrity issues

If you find a discrepancy between a published anchor and what CausalLayer
claims publicly, please file a P0 issue on this repo or email
**security@faultkey.ai**.

---

## Related

- Public anchor log: <https://github.com/smq9sn5jck-coder/causallayer-anchor-log>
- Public certificate verifier (browser): <https://faultkey.ai/.well-known/causallayer-cert/verify.html>
- Public anchor verifier (browser): <https://faultkey.ai/.well-known/causallayer-cert/verify-anchor.html>
- Public accuracy track record: <https://faultkey.ai/track-record>

## License

[MIT](LICENSE)
