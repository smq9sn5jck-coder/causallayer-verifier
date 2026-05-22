/**
 * End-to-end production-anchor test.
 *
 * Loads every signed anchor in test/fixtures/anchors/ (a sealed snapshot
 * of the public causallayer-anchor-log) and asserts that each one
 * verifies fully under the patched verifier (body sha, Merkle root,
 * public-key fingerprint, Ed25519 signature).
 *
 * Also runs adversarial mutation probes against the latest production
 * anchor to confirm that every tamper vector is detected.
 *
 * Run: `node test/production-anchors.js`
 */
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const assert = require("node:assert");

const { verifyAnchor, verifyAuditBatchV1 } = require("../lib/index");

const fixturesDir = path.join(__dirname, "fixtures", "anchors");
const publicKeyPath = path.join(__dirname, "fixtures", "public-key.pem");

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

if (!fs.existsSync(fixturesDir) || !fs.existsSync(publicKeyPath)) {
  console.log(
    "production-anchors: fixtures not present, skipping (see test/fixtures/README.md)"
  );
  process.exit(0);
}

const pem = fs.readFileSync(publicKeyPath, "utf8");
const anchorFiles = fs
  .readdirSync(fixturesDir)
  .filter((f) => f.endsWith(".json"))
  .sort();

console.log(`\n[P] Production anchors (${anchorFiles.length})`);
for (const f of anchorFiles) {
  test(`${f} verifies fully`, () => {
    const record = JSON.parse(
      fs.readFileSync(path.join(fixturesDir, f), "utf8")
    );
    const r = verifyAnchor(record, pem);
    assert.ok(
      r.schema === "causallayer.audit-batch.v1" ||
        r.schema === "schemaVersion-0.1",
      `unknown schema: ${r.schema}`
    );
    assert.strictEqual(r.merkleOk, true, "merkle root");
    assert.strictEqual(r.signatureOk, true, "ed25519 signature");
    assert.strictEqual(r.allOk, true, "allOk");
    if (r.schema === "causallayer.audit-batch.v1") {
      assert.strictEqual(r.bodyShaOk, true, "batch_body_sha256");
      assert.strictEqual(r.fingerprintOk, true, "pubkey fingerprint");
    }
  });
}

console.log("\n[Q] Adversarial mutations against the latest production anchor");
const latest = anchorFiles[anchorFiles.length - 1];
const latestRecord = JSON.parse(
  fs.readFileSync(path.join(fixturesDir, latest), "utf8")
);

function clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

test("baseline: latest anchor verifies", () => {
  const r = verifyAnchor(latestRecord, pem);
  assert.strictEqual(r.allOk, true);
});

test("tamper: flip one byte of batch_body_sha256 -> bodyShaOk false, signatureOk false", () => {
  const m = clone(latestRecord);
  m.batch_body_sha256 =
    "0" + m.batch_body_sha256.slice(1) === m.batch_body_sha256
      ? "1" + m.batch_body_sha256.slice(1)
      : "0" + m.batch_body_sha256.slice(1);
  const r = verifyAnchor(m, pem);
  assert.strictEqual(r.bodyShaOk, false);
  assert.strictEqual(r.signatureOk, false);
  assert.strictEqual(r.allOk, false);
});

test("tamper: mutate a leaf's sha256 -> bodyShaOk false (body changes), merkleOk false", () => {
  const m = clone(latestRecord);
  m.leaves[0].sha256 = "0".repeat(64);
  const r = verifyAnchor(m, pem);
  assert.strictEqual(r.merkleOk, false);
  assert.strictEqual(r.bodyShaOk, false);
});

test("tamper: forge batch_merkle_root -> merkleOk false, bodyShaOk false", () => {
  const m = clone(latestRecord);
  m.batch_merkle_root = "f".repeat(64);
  const r = verifyAnchor(m, pem);
  assert.strictEqual(r.merkleOk, false);
  assert.strictEqual(r.bodyShaOk, false);
});

test("tamper: flip one bit of signature_hex -> signatureOk false", () => {
  const m = clone(latestRecord);
  const s = m.signature.signature_hex;
  m.signature.signature_hex =
    (s[0] === "0" ? "1" : "0") + s.slice(1);
  const r = verifyAnchor(m, pem);
  assert.strictEqual(r.signatureOk, false);
  assert.strictEqual(r.allOk, false);
});

test("tamper: wrong pubkey fingerprint claim -> fingerprintOk false", () => {
  const m = clone(latestRecord);
  m.signature.pubkey_sha256_fingerprint = "a".repeat(64);
  const r = verifyAnchor(m, pem);
  assert.strictEqual(r.fingerprintOk, false);
});

test("attacker key: signature does not verify under a wrong key", () => {
  const { publicKey: attackerPub, privateKey: attackerPriv } =
    crypto.generateKeyPairSync("ed25519");
  const attackerPem = attackerPub
    .export({ format: "pem", type: "spki" })
    .toString();
  // (Optional re-sign would prove forge resistance; signature_hex was
  // produced by the legitimate key, so under attacker key it MUST fail.)
  const r = verifyAuditBatchV1(latestRecord, attackerPem);
  assert.strictEqual(r.signatureOk, false, "wrong-key signature must fail");
  assert.strictEqual(r.fingerprintOk, false, "wrong-key fingerprint must fail");
  // Silence unused-var lint.
  void attackerPriv;
});

test("tamper: drop a leaf entirely -> merkleOk false, bodyShaOk false", () => {
  const m = clone(latestRecord);
  m.leaves.pop();
  m.leaf_count = m.leaves.length;
  const r = verifyAnchor(m, pem);
  assert.strictEqual(r.merkleOk, false);
  assert.strictEqual(r.bodyShaOk, false);
});

test("tamper: swap two adjacent leaves -> merkleOk false, bodyShaOk false", () => {
  if (latestRecord.leaves.length < 2) return; // not applicable
  const m = clone(latestRecord);
  const [a, b] = [m.leaves[0], m.leaves[1]];
  m.leaves[0] = b;
  m.leaves[1] = a;
  const r = verifyAnchor(m, pem);
  assert.strictEqual(r.merkleOk, false);
  assert.strictEqual(r.bodyShaOk, false);
});

test("tamper: change schema string -> verifyAnchor refuses or fails", () => {
  const m = clone(latestRecord);
  m.schema = "causallayer.audit-batch.v2";
  // Auto-detect now sees an unknown schema and falls back to legacy path,
  // which will throw because there's no .payload. Either behaviour is
  // acceptable (refuse-or-fail); we accept both.
  let ok = true;
  try {
    const r = verifyAnchor(m, pem);
    ok = r.allOk === false || r.signatureOk === false;
  } catch (_) {
    ok = true;
  }
  assert.strictEqual(ok, true, "v2 schema must not silently verify");
});

console.log(
  "\n============================================================"
);
console.log(
  `Production-anchor suite: ${passed} passed, ${failed} failed`
);
process.exit(failed === 0 ? 0 : 1);
