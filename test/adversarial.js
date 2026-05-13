/**
 * Adversarial test suite for causallayer-verifier.
 *
 * The smoke tests in test.js cover the happy paths. This suite covers
 * the attacker-and-bug-driven negative paths: tampered payloads, swapped
 * keys, malformed inputs, edge-case Merkle trees, signature-encoding
 * variants, and ledger-chain breakage.
 *
 * Every assertion is named so a failure tells you exactly which adversarial
 * vector tripped. Run via `node test/adversarial.js` (also wired into
 * `npm test` alongside the smoke tests).
 */
"use strict";

const crypto = require("node:crypto");
const assert = require("node:assert");
const {
  merkleRoot,
  canonicalize,
  verifySignature,
  verifyAnchor,
  verifyLedgerLink,
  sha256,
} = require("../lib/index");

let passed = 0;
let failed = 0;
function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ok   · ${name}`);
  } catch (e) {
    failed++;
    console.log(`  FAIL · ${name}`);
    console.log(`         ${e.message}`);
  }
}

// ---------------------------------------------------------------------------
// Section A — Merkle root algorithmic invariants
// ---------------------------------------------------------------------------
console.log("\n[A] Merkle root");

test("empty input yields the empty-buffer hash", () => {
  const root = merkleRoot([]);
  const expected = crypto
    .createHash("sha256")
    .update(Buffer.alloc(0))
    .digest("hex");
  assert.strictEqual(root, expected);
});

test("single leaf root equals sha256(leaf)", () => {
  const root = merkleRoot(["only-leaf"]);
  const expected = crypto
    .createHash("sha256")
    .update(Buffer.from("only-leaf", "utf8"))
    .digest("hex");
  assert.strictEqual(root, expected);
});

test("two-leaf root concatenates child hashes", () => {
  const a = crypto.createHash("sha256").update(Buffer.from("a", "utf8")).digest();
  const b = crypto.createHash("sha256").update(Buffer.from("b", "utf8")).digest();
  const expected = crypto
    .createHash("sha256")
    .update(Buffer.concat([a, b]))
    .digest("hex");
  assert.strictEqual(merkleRoot(["a", "b"]), expected);
});

test("odd leaf count duplicates the last leaf (engine convention)", () => {
  // 3-leaf tree should equal 4-leaf tree with last leaf duplicated
  const odd = merkleRoot(["a", "b", "c"]);
  const even = merkleRoot(["a", "b", "c", "c"]);
  assert.strictEqual(odd, even, "odd-count duplication invariant violated");
});

test("leaf order is significant", () => {
  assert.notStrictEqual(merkleRoot(["a", "b", "c"]), merkleRoot(["c", "b", "a"]));
});

test("a single-character change in any leaf changes the root", () => {
  const base = merkleRoot(["alpha", "beta", "gamma", "delta"]);
  assert.notStrictEqual(base, merkleRoot(["alpha", "bata", "gamma", "delta"]));
  assert.notStrictEqual(base, merkleRoot(["alpha", "beta", "gamma", "delts"]));
});

test("non-array input throws TypeError", () => {
  assert.throws(() => merkleRoot("not-an-array"), TypeError);
  assert.throws(() => merkleRoot(null), TypeError);
  assert.throws(() => merkleRoot(undefined), TypeError);
});

test("hex root is always 64 characters", () => {
  for (const size of [0, 1, 2, 3, 7, 8, 15, 16, 31, 64, 100]) {
    const leaves = Array.from({ length: size }, (_, i) => `leaf-${i}`);
    assert.strictEqual(
      merkleRoot(leaves).length,
      64,
      `size ${size} produced wrong-length root`
    );
  }
});

// ---------------------------------------------------------------------------
// Section B — Canonical JSON
// ---------------------------------------------------------------------------
console.log("\n[B] Canonical JSON");

test("nested objects sort keys at every depth", () => {
  const a = canonicalize({ z: { b: 1, a: 2 }, a: { d: 3, c: 4 } });
  const b = canonicalize({ a: { c: 4, d: 3 }, z: { a: 2, b: 1 } });
  assert.strictEqual(a, b);
});

test("array order is preserved (arrays are ordered)", () => {
  assert.notStrictEqual(canonicalize([1, 2, 3]), canonicalize([3, 2, 1]));
});

test("null, true, false, numbers serialise as plain JSON", () => {
  assert.strictEqual(canonicalize(null), "null");
  assert.strictEqual(canonicalize(true), "true");
  assert.strictEqual(canonicalize(false), "false");
  assert.strictEqual(canonicalize(42), "42");
  assert.strictEqual(canonicalize(3.14), "3.14");
});

test("strings are JSON-escaped", () => {
  assert.strictEqual(canonicalize('hi "you"'), '"hi \\"you\\""');
  assert.strictEqual(canonicalize("line\nbreak"), '"line\\nbreak"');
});

test("deeply nested mixed structure round-trips key-stably", () => {
  const a = canonicalize({
    list: [{ b: 1, a: 2 }, { d: 3, c: 4 }],
    obj: { nested: { z: [1, 2], y: "x" } },
  });
  const b = canonicalize({
    obj: { nested: { y: "x", z: [1, 2] } },
    list: [{ a: 2, b: 1 }, { c: 4, d: 3 }],
  });
  assert.strictEqual(a, b);
});

// ---------------------------------------------------------------------------
// Section C — Signature verification (adversarial)
// ---------------------------------------------------------------------------
console.log("\n[C] Signature verification");

const { publicKey: pkA, privateKey: skA } = crypto.generateKeyPairSync("ed25519");
const { publicKey: pkB } = crypto.generateKeyPairSync("ed25519");

function signCanonical(payload, sk) {
  return crypto.sign(null, Buffer.from(canonicalize(payload), "utf8"), sk);
}

test("hex signature verifies", () => {
  const payload = { foo: "bar", n: 1 };
  const sig = signCanonical(payload, skA).toString("hex");
  assert.strictEqual(verifySignature(payload, sig, pkA), true);
});

test("base64 signature verifies (same key, same payload)", () => {
  const payload = { foo: "bar", n: 1 };
  const sig = signCanonical(payload, skA).toString("base64");
  assert.strictEqual(verifySignature(payload, sig, pkA), true);
});

test("signature does NOT verify against the wrong public key", () => {
  const payload = { foo: "bar" };
  const sig = signCanonical(payload, skA).toString("hex");
  assert.strictEqual(verifySignature(payload, sig, pkB), false);
});

test("any payload mutation invalidates the signature", () => {
  const payload = { foo: "bar", n: 1 };
  const sig = signCanonical(payload, skA).toString("hex");
  assert.strictEqual(verifySignature({ foo: "bar", n: 2 }, sig, pkA), false);
  assert.strictEqual(verifySignature({ foo: "bar", n: 1, extra: 0 }, sig, pkA), false);
  assert.strictEqual(verifySignature({ foo: "baz", n: 1 }, sig, pkA), false);
});

test("re-ordered keys still verify (canonical-JSON property)", () => {
  const sig = signCanonical({ z: 1, a: 2, m: 3 }, skA).toString("hex");
  assert.strictEqual(verifySignature({ a: 2, m: 3, z: 1 }, sig, pkA), true);
});

test("a single-bit flip in the signature invalidates it", () => {
  const payload = { foo: "bar" };
  const sig = signCanonical(payload, skA);
  const flipped = Buffer.from(sig);
  flipped[0] = flipped[0] ^ 0x01;
  assert.strictEqual(
    verifySignature(payload, flipped.toString("hex"), pkA),
    false
  );
});

test("accepts PEM string and KeyObject equally", () => {
  const payload = { foo: "bar" };
  const sig = signCanonical(payload, skA).toString("hex");
  const pem = pkA.export({ type: "spki", format: "pem" });
  assert.strictEqual(verifySignature(payload, sig, pem), true);
  assert.strictEqual(verifySignature(payload, sig, pkA), true);
});

// ---------------------------------------------------------------------------
// Section D — Anchor verification (adversarial)
// ---------------------------------------------------------------------------
console.log("\n[D] Anchor verification");

function makeAnchor(leaves, sk, overrides = {}) {
  const payload = {
    anchorDate: "2026-05-13",
    merkleRoot: merkleRoot(leaves),
    leafCount: leaves.length,
    leaves,
    ...overrides.payload,
  };
  const sig = signCanonical(payload, sk).toString("hex");
  return {
    payload,
    signature: sig,
    signatureAlgorithm: "ed25519",
    publicKeyFingerprint: "fp-test",
    ...overrides.envelope,
  };
}

test("happy-path anchor verifies", () => {
  const anchor = makeAnchor(["r1", "r2", "r3", "r4"], skA);
  const r = verifyAnchor(anchor, pkA);
  assert.strictEqual(r.merkleOk, true);
  assert.strictEqual(r.signatureOk, true);
  assert.strictEqual(r.recomputedRoot, r.claimedRoot);
});

test("leaf swap detected by Merkle check", () => {
  const anchor = makeAnchor(["r1", "r2", "r3", "r4"], skA);
  anchor.payload.leaves = ["r1", "r2", "r4", "r3"]; // swap last two
  const r = verifyAnchor(anchor, pkA);
  assert.strictEqual(r.merkleOk, false, "Merkle should detect leaf swap");
  // Signature also fails because payload changed
  assert.strictEqual(r.signatureOk, false);
});

test("leaf insertion detected", () => {
  const anchor = makeAnchor(["r1", "r2"], skA);
  anchor.payload.leaves = ["r1", "r2", "r3"];
  anchor.payload.leafCount = 3;
  const r = verifyAnchor(anchor, pkA);
  assert.strictEqual(r.merkleOk, false);
  assert.strictEqual(r.signatureOk, false);
});

test("forged Merkle root (claim doesn't match leaves) detected", () => {
  const anchor = makeAnchor(["r1", "r2"], skA);
  anchor.payload.merkleRoot = "0".repeat(64);
  const r = verifyAnchor(anchor, pkA);
  assert.strictEqual(r.merkleOk, false);
  // Signature also fails because payload was mutated post-sign
  assert.strictEqual(r.signatureOk, false);
});

test("swapped signing key detected (anchor signed by attacker)", () => {
  const { privateKey: skAttacker } = crypto.generateKeyPairSync("ed25519");
  const anchor = makeAnchor(["r1"], skAttacker);
  const r = verifyAnchor(anchor, pkA); // verify against legitimate key
  assert.strictEqual(r.merkleOk, true); // Merkle still ok, leaves are real
  assert.strictEqual(r.signatureOk, false, "wrong-key signature must fail");
});

test("anchor with missing payload throws", () => {
  assert.throws(() => verifyAnchor({}, pkA), TypeError);
  assert.throws(() => verifyAnchor(null, pkA), TypeError);
  assert.throws(() => verifyAnchor({ payload: null }, pkA), TypeError);
});

test("anchor with empty leaves array verifies if signed honestly", () => {
  const anchor = makeAnchor([], skA);
  const r = verifyAnchor(anchor, pkA);
  assert.strictEqual(r.merkleOk, true);
  assert.strictEqual(r.signatureOk, true);
});

test("date mutation invalidates signature", () => {
  const anchor = makeAnchor(["r1"], skA);
  anchor.payload.anchorDate = "1970-01-01";
  const r = verifyAnchor(anchor, pkA);
  assert.strictEqual(r.signatureOk, false, "date back-dating must be detected");
});

// ---------------------------------------------------------------------------
// Section E — Ledger chain (adversarial)
// ---------------------------------------------------------------------------
console.log("\n[E] Ledger chain");

function makeRow(payload, prev) {
  const rowHash = sha256(Buffer.from(canonicalize(payload), "utf8"));
  return {
    payload,
    rowHash,
    prevRowHash: prev ? prev.rowHash : null,
  };
}

test("genesis row (prev=null) verifies", () => {
  const r0 = makeRow({ event: "genesis", n: 0 }, null);
  const result = verifyLedgerLink(null, r0);
  assert.strictEqual(result.linkOk, true);
  assert.strictEqual(result.rowHashOk, true);
});

test("two-row honest chain verifies", () => {
  const r0 = makeRow({ event: "genesis" }, null);
  const r1 = makeRow({ event: "second", at: "2026-05-13" }, r0);
  const result = verifyLedgerLink(r0, r1);
  assert.strictEqual(result.linkOk, true);
  assert.strictEqual(result.rowHashOk, true);
});

test("broken prevRowHash detected", () => {
  const r0 = makeRow({ event: "genesis" }, null);
  const r1 = makeRow({ event: "second" }, r0);
  r1.prevRowHash = "deadbeef".repeat(8);
  const result = verifyLedgerLink(r0, r1);
  assert.strictEqual(result.linkOk, false, "broken backlink must be detected");
});

test("tampered payload detected by rowHash mismatch", () => {
  const r0 = makeRow({ event: "genesis" }, null);
  r0.payload.event = "tampered";
  const result = verifyLedgerLink(null, r0);
  assert.strictEqual(result.rowHashOk, false);
});

test("inserted row breaks the previous-next backlink", () => {
  // honest chain: r0 -> r1 -> r2
  const r0 = makeRow({ event: "genesis" }, null);
  const r1 = makeRow({ event: "second" }, r0);
  const r2 = makeRow({ event: "third" }, r1);

  // attacker inserts r1b between r1 and r2
  const r1b = makeRow({ event: "INSERTED" }, r1);
  // attacker leaves r2 unchanged → r2.prevRowHash still points at r1, not r1b
  const result = verifyLedgerLink(r1b, r2);
  assert.strictEqual(
    result.linkOk,
    false,
    "verifyLedgerLink must detect inserted rows when checked against the inserted predecessor"
  );
});

test("removed row breaks the chain (prevRowHash points at deleted row)", () => {
  const r0 = makeRow({ event: "genesis" }, null);
  const r1 = makeRow({ event: "second" }, r0);
  const r2 = makeRow({ event: "third" }, r1);
  // attacker deletes r1; auditor tries r0 -> r2
  const result = verifyLedgerLink(r0, r2);
  assert.strictEqual(result.linkOk, false, "removed-row gap must be detected");
});

// ---------------------------------------------------------------------------
// Section F — Cross-version compatibility self-check
// ---------------------------------------------------------------------------
console.log("\n[F] Cross-version compatibility");

test("merkleRoot output matches a hand-computed reference vector", () => {
  // Reference vector: sha256(sha256("a") || sha256("b"))
  const sa = crypto.createHash("sha256").update("a").digest();
  const sb = crypto.createHash("sha256").update("b").digest();
  const expected = crypto
    .createHash("sha256")
    .update(Buffer.concat([sa, sb]))
    .digest("hex");
  assert.strictEqual(merkleRoot(["a", "b"]), expected);
});

test("canonicalize output matches a hand-written reference", () => {
  assert.strictEqual(
    canonicalize({ b: [1, 2], a: { y: 1, x: 2 } }),
    '{"a":{"x":2,"y":1},"b":[1,2]}'
  );
});

// ---------------------------------------------------------------------------
console.log("\n" + "=".repeat(60));
console.log(`Adversarial suite: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
