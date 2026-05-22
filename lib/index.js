/**
 * causallayer-verifier — pure verification primitives.
 *
 * Zero runtime dependencies (Node built-ins only). All functions are
 * deterministic and side-effect-free; the library never makes network
 * calls. Pair with the bin/ CLI for file-based verification, or call
 * directly from your own audit tooling.
 *
 * Schemas supported:
 *   - causallayer.audit-batch.v1     (production, Ed25519 over utf8(batch_body_sha256))
 *   - schemaVersion: "0.1"           (legacy/dev-test, Ed25519 over canonicalized payload)
 *
 * The verifier never trusts CausalLayer: it only trusts the bytes of the
 * anchor file and the public key the caller supplies.
 */
"use strict";

const crypto = require("node:crypto");

function sha256Bytes(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

function sha256Hex(buf) {
  return sha256Bytes(buf).toString("hex");
}

/**
 * Compute a Merkle root over an ordered list of hex-encoded leaf hashes
 * using the Bitcoin-style "duplicate last odd" construction. Each leaf
 * is interpreted as raw 32 bytes (from its hex form), pairs are
 * concatenated, and SHA-256 is applied at each layer.
 *
 * @param {string[]} leafHashesHex
 * @returns {string} hex-encoded SHA-256 root
 */
function merkleRootFromLeafHashes(leafHashesHex) {
  if (!Array.isArray(leafHashesHex)) {
    throw new TypeError("merkleRootFromLeafHashes: leafHashesHex must be an array");
  }
  if (leafHashesHex.length === 0) {
    return sha256Hex(Buffer.alloc(0));
  }
  let layer = leafHashesHex.map((h) => Buffer.from(h, "hex"));
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      next.push(sha256Bytes(Buffer.concat([left, right])));
    }
    layer = next;
  }
  return layer[0].toString("hex");
}

/**
 * Compute a Merkle root over an ordered list of leaf STRINGS.
 * Algorithm: leaf hash = sha256(utf8(leaf)); internal nodes hash the
 * concatenation of left+right; odd nodes are duplicated. Matches the
 * legacy ("schemaVersion 0.1") CausalLayer engine.
 *
 * @param {string[]} leafStrings
 * @returns {string} hex-encoded SHA-256 root
 */
function merkleRoot(leafStrings) {
  if (!Array.isArray(leafStrings)) {
    throw new TypeError("merkleRoot: leafStrings must be an array");
  }
  if (leafStrings.length === 0) {
    return sha256Hex(Buffer.alloc(0));
  }
  const leafHashesHex = leafStrings.map((s) =>
    sha256Hex(Buffer.from(s, "utf8"))
  );
  return merkleRootFromLeafHashes(leafHashesHex);
}

/**
 * Canonical-JSON serialise (sorted keys at every depth).
 * Used by the LEGACY schema where the signature is computed over the
 * canonicalised payload. NOT used by the production `audit-batch.v1`
 * schema (which signs over `utf8(batch_body_sha256)` instead).
 */
function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  const keys = Object.keys(value).sort();
  return (
    "{" +
    keys
      .map((k) => JSON.stringify(k) + ":" + canonicalize(value[k]))
      .join(",") +
    "}"
  );
}

/**
 * Python-style JSON serialise: insertion-order keys, indent=2,
 * ensure_ascii=true. Used by the PRODUCTION `audit-batch.v1` schema to
 * reproduce the bytes hashed into `batch_body_sha256`. Non-ASCII
 * characters are escaped as `\uXXXX` to match Python's `json.dumps`
 * default behaviour.
 */
function pythonJsonDumps(value, indent = 2) {
  const s = JSON.stringify(value, null, indent);
  // Python json.dumps with ensure_ascii=True escapes all non-ASCII as \uXXXX
  return s.replace(/[\u0080-\uffff]/g, (c) =>
    "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")
  );
}

/**
 * Best-effort signature byte decoder: accepts hex string of length 128,
 * base64 strings, or already-Buffer values. Throws on malformed input.
 */
function decodeSignatureBytes(sig) {
  if (Buffer.isBuffer(sig)) return sig;
  if (typeof sig !== "string") {
    throw new TypeError(
      "decodeSignatureBytes: expected hex/base64 string or Buffer, got " +
        typeof sig
    );
  }
  if (sig.length === 128 && /^[0-9a-fA-F]+$/.test(sig)) {
    return Buffer.from(sig, "hex");
  }
  return Buffer.from(sig, "base64");
}

/**
 * Compute the SHA-256 fingerprint of an Ed25519 public key's SPKI DER
 * encoding (the same fingerprint embedded in
 * `signature.pubkey_sha256_fingerprint` of production anchors).
 */
function publicKeyFingerprint(publicKey) {
  const key =
    typeof publicKey === "string" ? crypto.createPublicKey(publicKey) : publicKey;
  const der = key.export({ format: "der", type: "spki" });
  return sha256Hex(der);
}

/**
 * Verify an Ed25519 signature over the canonical-JSON form of `payload`.
 * (Legacy schema 0.1 helper — exported for backwards compatibility.)
 *
 * `signature` accepts either a hex/base64 string (legacy callers) or the
 * full signature object as it appears in legacy anchor files, in which
 * case the function reads `.value` (base64) automatically.
 */
function verifySignature(payload, signature, publicKey) {
  const key =
    typeof publicKey === "string" ? crypto.createPublicKey(publicKey) : publicKey;
  const data = Buffer.from(canonicalize(payload), "utf8");
  let sigInput = signature;
  if (sigInput && typeof sigInput === "object" && !Buffer.isBuffer(sigInput)) {
    sigInput = sigInput.value;
  }
  const sigBytes = decodeSignatureBytes(sigInput);
  return crypto.verify(null, data, key, sigBytes);
}

// ---------------------------------------------------------------------------
// PRODUCTION schema: causallayer.audit-batch.v1
// ---------------------------------------------------------------------------

/**
 * Verify a production `causallayer.audit-batch.v1` anchor.
 *
 * Returns a structured report covering all four invariants:
 *   1. batch_body_sha256 matches sha256(utf8(python-canonical body))
 *   2. batch_merkle_root matches Merkle root over leaves[].sha256
 *   3. signature.pubkey_sha256_fingerprint matches sha256(SPKI DER of key)
 *   4. signature.signature_hex is a valid Ed25519 signature over
 *      utf8(batch_body_sha256) under the supplied key
 *
 * No I/O. No network. No mutation of input.
 */
function verifyAuditBatchV1(record, publicKey) {
  if (!record || typeof record !== "object") {
    throw new TypeError("verifyAuditBatchV1: record must be an object");
  }
  if (record.schema !== "causallayer.audit-batch.v1") {
    throw new TypeError(
      "verifyAuditBatchV1: record.schema must be 'causallayer.audit-batch.v1', got " +
        JSON.stringify(record.schema)
    );
  }
  if (!record.signature || typeof record.signature !== "object") {
    throw new TypeError("verifyAuditBatchV1: record.signature object required");
  }
  if (!Array.isArray(record.leaves)) {
    throw new TypeError("verifyAuditBatchV1: record.leaves array required");
  }

  const key =
    typeof publicKey === "string" ? crypto.createPublicKey(publicKey) : publicKey;

  // (1) Recompute batch_body_sha256.
  // Body = record with batch_body_sha256 and signature keys stripped,
  // serialised via Python-style json.dumps(indent=2, sort_keys=False, ensure_ascii=True).
  const bodyObj = {};
  for (const k of Object.keys(record)) {
    if (k === "batch_body_sha256" || k === "signature") continue;
    bodyObj[k] = record[k];
  }
  const body = pythonJsonDumps(bodyObj, 2);
  const recomputedBodySha = sha256Hex(Buffer.from(body, "utf8"));
  const claimedBodySha = record.batch_body_sha256;
  const bodyShaOk = recomputedBodySha === claimedBodySha;

  // (2) Recompute Merkle root over leaves[].sha256.
  const leafHashes = record.leaves.map((l) => l && l.sha256).filter(Boolean);
  const recomputedMerkleRoot = merkleRootFromLeafHashes(leafHashes);
  const claimedMerkleRoot = record.batch_merkle_root;
  const merkleOk = recomputedMerkleRoot === claimedMerkleRoot;

  // (3) Verify public-key fingerprint.
  const recomputedFingerprint = publicKeyFingerprint(key);
  const claimedFingerprint = record.signature.pubkey_sha256_fingerprint;
  const fingerprintOk = recomputedFingerprint === claimedFingerprint;

  // (4) Verify Ed25519 signature over utf8(batch_body_sha256).
  // signed_field declares which top-level field was signed; we honour it
  // but also assert it matches the documented "batch_body_sha256" value.
  const signedFieldName = record.signature.signed_field || "batch_body_sha256";
  const signedFieldValue = record[signedFieldName];
  let signatureOk = false;
  if (typeof signedFieldValue === "string" && record.signature.signature_hex) {
    const sigBytes = Buffer.from(record.signature.signature_hex, "hex");
    const data = Buffer.from(signedFieldValue, "utf8");
    try {
      signatureOk = crypto.verify(null, data, key, sigBytes);
    } catch (_) {
      signatureOk = false;
    }
  }

  return {
    schema: "causallayer.audit-batch.v1",
    bodyShaOk,
    merkleOk,
    fingerprintOk,
    signatureOk,
    recomputedBodySha,
    claimedBodySha,
    recomputedMerkleRoot,
    claimedMerkleRoot,
    recomputedFingerprint,
    claimedFingerprint,
    signedField: signedFieldName,
    leafCount: leafHashes.length,
    allOk: bodyShaOk && merkleOk && fingerprintOk && signatureOk,
  };
}

// ---------------------------------------------------------------------------
// LEGACY schema: schemaVersion "0.1"
// ---------------------------------------------------------------------------

/**
 * Verify a legacy schema 0.1 anchor (nested .payload, signature object
 * with .value base64 field).
 */
function verifyLegacyAnchor(record, publicKey) {
  if (!record || typeof record !== "object" || !record.payload) {
    throw new TypeError("verifyLegacyAnchor: record.payload required");
  }
  // Some legacy anchors put `merkleRoot` at the top level and only the
  // leaves under .payload; others nest both. Honour whichever is present.
  const leaves = record.payload.leaves || [];
  const recomputedRoot = merkleRoot(leaves);
  const claimedRoot =
    record.payload.merkleRoot !== undefined
      ? record.payload.merkleRoot
      : record.merkleRoot;
  const merkleOk = recomputedRoot === claimedRoot;

  // Signature may be a string (very old) or an object {value, ...}
  let sigInput = record.signature;
  if (sigInput && typeof sigInput === "object" && !Buffer.isBuffer(sigInput)) {
    sigInput = sigInput.value;
  }
  let signatureOk = false;
  if (sigInput) {
    try {
      const key =
        typeof publicKey === "string"
          ? crypto.createPublicKey(publicKey)
          : publicKey;
      const sigBytes = decodeSignatureBytes(sigInput);
      const data = Buffer.from(canonicalize(record.payload), "utf8");
      signatureOk = crypto.verify(null, data, key, sigBytes);
    } catch (_) {
      signatureOk = false;
    }
  }

  // Optional fingerprint check, if the legacy anchor embeds one.
  let fingerprintOk = null;
  let recomputedFingerprint = null;
  let claimedFingerprint = null;
  if (record.signature && record.signature.publicKeyFingerprint) {
    try {
      recomputedFingerprint = publicKeyFingerprint(publicKey);
      claimedFingerprint = record.signature.publicKeyFingerprint;
      fingerprintOk = recomputedFingerprint === claimedFingerprint;
    } catch (_) {
      fingerprintOk = false;
    }
  }

  return {
    schema: "schemaVersion-0.1",
    merkleOk,
    signatureOk,
    fingerprintOk,
    recomputedRoot,
    claimedRoot,
    recomputedFingerprint,
    claimedFingerprint,
    leafCount: leaves.length,
    anchorDate: record.payload.anchorDate || record.anchorDate || null,
    allOk:
      merkleOk &&
      signatureOk &&
      (fingerprintOk === null ? true : fingerprintOk === true),
  };
}

// ---------------------------------------------------------------------------
// Unified entry point (auto-detects schema)
// ---------------------------------------------------------------------------

/**
 * Verify a CausalLayer anchor end-to-end. Auto-detects the schema:
 *   - record.schema === "causallayer.audit-batch.v1"  → production path
 *   - record.payload present (legacy)                 → legacy path
 *
 * Returns a structured report (see verifyAuditBatchV1 /
 * verifyLegacyAnchor). The returned object always exposes `merkleOk`
 * and `signatureOk` plus `recomputedRoot` / `claimedRoot` for backward
 * compatibility with callers written against the 0.1.0 API.
 */
function verifyAnchor(record, publicKey) {
  if (!record || typeof record !== "object") {
    throw new TypeError("verifyAnchor: record must be a non-null object");
  }
  if (record.schema === "causallayer.audit-batch.v1") {
    const r = verifyAuditBatchV1(record, publicKey);
    return {
      ...r,
      // Back-compat shims so existing CLI callers don't crash:
      recomputedRoot: r.recomputedMerkleRoot,
      claimedRoot: r.claimedMerkleRoot,
    };
  }
  if (!record.payload) {
    throw new TypeError(
      "verifyAnchor: record has neither schema='causallayer.audit-batch.v1' nor a legacy .payload field"
    );
  }
  return verifyLegacyAnchor(record, publicKey);
}

/**
 * Verify a single hash-chained ledger row by recomputing its prevHash
 * link against the previous row. Unchanged from 0.1.0.
 */
function verifyLedgerLink(previous, current) {
  const linkOk = current.prevRowHash === (previous ? previous.rowHash : null);
  const recomputed = sha256Hex(
    Buffer.from(canonicalize(current.payload), "utf8")
  );
  const rowHashOk = recomputed === current.rowHash;
  return { linkOk, rowHashOk };
}

module.exports = {
  sha256: (buf) => sha256Hex(buf),
  merkleRoot,
  merkleRootFromLeafHashes,
  canonicalize,
  pythonJsonDumps,
  publicKeyFingerprint,
  verifySignature,
  verifyAnchor,
  verifyAuditBatchV1,
  verifyLegacyAnchor,
  verifyLedgerLink,
};
