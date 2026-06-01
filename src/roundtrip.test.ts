/**
 * Provenance round-trip test.
 *
 * This is the test that protects FaultKey's actual moat: a certificate's value
 * is that an independent party can verify it. Here we play the PRODUCER (the
 * engine): build a CausalCertificateV1, sign it with a freshly generated
 * Ed25519 key, register that key, and assert the verifier accepts it — then
 * assert it rejects every form of tampering.
 *
 * Crucially, the producer side uses the verifier's OWN exported `canonicalize`,
 * `sha256Hex`, and `computeMerkleRoot`. That pins the contract: if the signing
 * scheme and the verification scheme ever drift (different key ordering,
 * different undefined/null handling, different merkle construction), this test
 * fails. It is the cross-component guarantee that the engine, the verifier, and
 * the cert-worker all agree byte-for-byte on what a signature covers.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import {
  verifyCertificate,
  canonicalize,
  sha256Hex,
  computeMerkleRoot,
  type CausalCertificateV1,
} from "./index";

const KEY_ID = "ed25519:roundtrip-test-key";

// Generate one Ed25519 keypair for the whole file and register the public key
// with the verifier via the env override seam (applyExtraIssuerKeys).
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicKeyBase64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");
process.env.CAUSALLAYER_ISSUER_KEYS = JSON.stringify([
  {
    key_id: KEY_ID,
    alg: "ed25519",
    public_key_base64: publicKeyBase64,
    status: "active",
    valid_from: "2020-01-01T00:00:00Z",
  },
]);

/**
 * Build a fully valid, signed CausalCertificateV1 exactly as a conforming
 * producer must: merkle_root over canonicalized chain nodes, request_hash over
 * the canonical input fields, signature over canonicalize(cert minus
 * signature/anchor).
 */
function buildSignedCert(): CausalCertificateV1 {
  const causal_chain = [
    { step: 1, node: "incident", label: "AI agent exceeded authorised scope" },
    { step: 2, node: "deviation", label: "no human oversight checkpoint" },
    { step: 3, node: "harm", label: "financial loss to claimant" },
  ];

  const incident_id = "INC-ROUNDTRIP-0001";
  const timestamp = "2026-06-01T00:00:00Z";
  const jurisdiction = "EU";
  const law_as_of = "2026-01-01";

  const merkle_root = computeMerkleRoot(causal_chain.map((n) => canonicalize(n)));
  const request_hash = sha256Hex(
    canonicalize({ incident_id, timestamp, jurisdiction, law_as_of }),
  );

  // Everything except `signature` (and `anchor`, which is deleted before signing).
  const unsigned: Omit<CausalCertificateV1, "signature"> = {
    cert_id: "cert-roundtrip-0001",
    schema: "CausalCertificateV1",
    version: "1.0",
    incident_id,
    timestamp,
    law_as_of,
    jurisdiction,
    issuer: { id: "did:web:faultkey.com#scoring-engine", key_id: KEY_ID, algorithm: "ed25519" },
    merkle_root,
    request_hash,
    outputs: { primary_liable: "ai_provider", liability_pct: 62 },
    causal_chain,
  };

  // Ed25519 is one-shot in Node: sign(null, data, key) over the canonical bytes.
  const signable = canonicalize(unsigned);
  const signatureHex = cryptoSign(null, Buffer.from(signable, "utf8"), privateKey).toString("hex");

  return { ...unsigned, signature: signatureHex };
}

describe("provenance round-trip: producer → verifier", () => {
  it("a correctly signed certificate VERIFIES (no fail checks)", async () => {
    const cert = buildSignedCert();
    const result = await verifyCertificate(cert);

    const sig = result.checks.find((c) => c.name === "Signature");
    assert.equal(sig?.status, "pass", `signature check should pass: ${sig?.detail}`);

    const merkle = result.checks.find((c) => c.name === "Merkle Tree");
    assert.equal(merkle?.status, "pass", `merkle check should pass: ${merkle?.detail}`);

    const hash = result.checks.find((c) => c.name === "Hash Consistency");
    assert.equal(hash?.status, "pass", `hash check should pass: ${hash?.detail}`);

    // An unanchored cert is VERIFIED_WITH_NOTES (anchor warn + recompute skip),
    // never FAILED.
    assert.notEqual(result.verdict, "FAILED", "verdict must not be FAILED for a valid cert");
    assert.equal(failCount(result), 0, "no checks should fail for a valid cert");
  });

  it("rejects a tampered output (signature no longer matches body)", async () => {
    const cert = buildSignedCert();
    cert.outputs.liability_pct = 99; // tamper after signing
    const result = await verifyCertificate(cert);
    assert.equal(signatureStatus(result), "fail", "signature must fail when outputs are altered");
    assert.equal(result.verdict, "FAILED");
  });

  it("rejects a tampered causal chain (merkle root no longer matches)", async () => {
    const cert = buildSignedCert();
    cert.causal_chain[0].label = "FABRICATED ROOT CAUSE";
    const result = await verifyCertificate(cert);
    // Both signature (body changed) and merkle (chain changed) should fail.
    assert.equal(merkleStatus(result), "fail", "merkle must fail when the chain is altered");
    assert.equal(result.verdict, "FAILED");
  });

  it("rejects a tampered input field (request_hash no longer matches)", async () => {
    const cert = buildSignedCert();
    cert.jurisdiction = "US"; // changes both request_hash basis and signed body
    const result = await verifyCertificate(cert);
    assert.equal(hashStatus(result), "fail", "request_hash must fail when inputs are altered");
    assert.equal(result.verdict, "FAILED");
  });

  it("rejects a forged signature", async () => {
    const cert = buildSignedCert();
    cert.signature = "00".repeat(64); // 64-byte zero signature
    const result = await verifyCertificate(cert);
    assert.equal(signatureStatus(result), "fail");
    assert.equal(result.verdict, "FAILED");
  });

  it("rejects a cert signed by an unregistered key", async () => {
    const cert = buildSignedCert();
    cert.issuer.key_id = "ed25519:not-in-registry";
    const result = await verifyCertificate(cert);
    const trust = result.checks.find((c) => c.name === "Issuer Trust");
    assert.equal(trust?.status, "fail", "issuer trust must fail for an unknown key");
    assert.equal(result.verdict, "FAILED");
  });

  it("canonicalize is key-order independent (the property the signature relies on)", () => {
    const a = { b: 1, a: { d: 4, c: 3 }, arr: [{ y: 2, x: 1 }] };
    const b = { arr: [{ x: 1, y: 2 }], a: { c: 3, d: 4 }, b: 1 };
    assert.equal(canonicalize(a), canonicalize(b));
  });
});

// ─── helpers ─────────────────────────────────────────────────────────────────
function failCount(r: Awaited<ReturnType<typeof verifyCertificate>>): number {
  return r.checks.filter((c) => c.status === "fail").length;
}
function signatureStatus(r: Awaited<ReturnType<typeof verifyCertificate>>): string | undefined {
  return r.checks.find((c) => c.name === "Signature")?.status;
}
function merkleStatus(r: Awaited<ReturnType<typeof verifyCertificate>>): string | undefined {
  return r.checks.find((c) => c.name === "Merkle Tree")?.status;
}
function hashStatus(r: Awaited<ReturnType<typeof verifyCertificate>>): string | undefined {
  return r.checks.find((c) => c.name === "Hash Consistency")?.status;
}
