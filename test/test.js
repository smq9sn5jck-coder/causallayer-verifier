/**
 * Smoke test: generate an Ed25519 keypair, build a tiny anchor, sign it,
 * verify it. Confirms the canonicalisation + signature path is sound and
 * compatible with what the engine produces.
 */
"use strict";

const crypto = require("node:crypto");
const assert = require("node:assert");
const {
  merkleRoot,
  canonicalize,
  verifyAnchor,
  verifyLedgerLink,
  sha256,
} = require("../lib/index");

// 1. Merkle root determinism
{
  const root1 = merkleRoot(["a", "b", "c"]);
  const root2 = merkleRoot(["a", "b", "c"]);
  assert.strictEqual(root1, root2, "merkleRoot must be deterministic");
  assert.notStrictEqual(merkleRoot(["a", "b", "c"]), merkleRoot(["a", "b", "d"]));
}

// 2. Canonicalisation key ordering
{
  const a = canonicalize({ b: 1, a: 2 });
  const b = canonicalize({ a: 2, b: 1 });
  assert.strictEqual(a, b, "canonicalize must order keys");
}

// 3. Round-trip anchor sign/verify
{
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const leaves = ["row-1", "row-2", "row-3", "row-4"];
  const payload = {
    anchorDate: "2026-05-10",
    merkleRoot: merkleRoot(leaves),
    leafCount: leaves.length,
    leaves,
  };
  const sig = crypto.sign(
    null,
    Buffer.from(canonicalize(payload), "utf8"),
    privateKey
  );
  const record = {
    payload,
    signature: sig.toString("hex"),
    signatureAlgorithm: "ed25519",
    publicKeyFingerprint: "test-fp",
  };
  const result = verifyAnchor(record, publicKey);
  assert.strictEqual(result.merkleOk, true);
  assert.strictEqual(result.signatureOk, true);

  // Tamper with a leaf -> Merkle should now fail
  const tampered = { ...record, payload: { ...payload, leaves: ["x", ...leaves.slice(1)] } };
  const r2 = verifyAnchor(tampered, publicKey);
  assert.strictEqual(r2.merkleOk, false);
}

// 4. Ledger link
{
  const prev = { rowHash: "aa", prevRowHash: null };
  const cur = {
    payload: { foo: 1 },
    rowHash: sha256(Buffer.from(canonicalize({ foo: 1 }), "utf8")),
    prevRowHash: "aa",
  };
  const r = verifyLedgerLink(prev, cur);
  assert.strictEqual(r.linkOk, true);
  assert.strictEqual(r.rowHashOk, true);
}

console.log("OK: 4/4 smoke tests passed");
