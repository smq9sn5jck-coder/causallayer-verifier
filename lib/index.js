/**
 * causallayer-verifier — pure verification primitives.
 *
 * Zero dependencies. All functions are deterministic and side-effect-free
 * (the library never makes network calls). Pair with the bin/ CLI for
 * file-based verification, or call directly from your own audit tooling.
 */
"use strict";

const crypto = require("node:crypto");

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

/**
 * Compute a Merkle root over an ordered list of leaf strings.
 * Algorithm: leaf hash = sha256(utf8(leaf)); internal nodes hash the
 * concatenation of left+right; odd nodes are duplicated. Matches the
 * CausalLayer engine.
 *
 * @param {string[]} leafStrings
 * @returns {string} hex-encoded SHA-256 root
 */
function merkleRoot(leafStrings) {
  if (!Array.isArray(leafStrings)) {
    throw new TypeError("merkleRoot: leafStrings must be an array");
  }
  if (leafStrings.length === 0) {
    return sha256(Buffer.alloc(0)).toString("hex");
  }
  let layer = leafStrings.map((s) => sha256(Buffer.from(s, "utf8")));
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      next.push(sha256(Buffer.concat([left, right])));
    }
    layer = next;
  }
  return layer[0].toString("hex");
}

/**
 * Canonical-JSON serialise: stable key ordering at every depth.
 * Required to recompute the exact bytes the engine signed.
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
 * Verify an Ed25519 signature over the canonical JSON form of `payload`.
 *
 * @param {object} payload    The signed payload (will be canonicalised).
 * @param {string} signature  Hex (length 128) or base64 string.
 * @param {string|crypto.KeyObject} publicKey  PEM string or KeyObject.
 * @returns {boolean}
 */
function verifySignature(payload, signature, publicKey) {
  const key =
    typeof publicKey === "string" ? crypto.createPublicKey(publicKey) : publicKey;
  const data = Buffer.from(canonicalize(payload), "utf8");
  const sig = Buffer.from(
    signature,
    signature.length === 128 && /^[0-9a-fA-F]+$/.test(signature) ? "hex" : "base64"
  );
  return crypto.verify(null, data, key, sig);
}

/**
 * Verify a CausalLayer anchor record end-to-end (Merkle + signature).
 * Does NOT check the OpenTimestamps proof — use `ots verify` for that.
 *
 * @param {object} record
 * @param {string|crypto.KeyObject} publicKey
 * @returns {{merkleOk: boolean, signatureOk: boolean, recomputedRoot: string, claimedRoot: string}}
 */
function verifyAnchor(record, publicKey) {
  if (!record || typeof record !== "object" || !record.payload) {
    throw new TypeError("verifyAnchor: record.payload required");
  }
  const recomputedRoot = merkleRoot(record.payload.leaves || []);
  const claimedRoot = record.payload.merkleRoot;
  const merkleOk = recomputedRoot === claimedRoot;
  const signatureOk = verifySignature(record.payload, record.signature, publicKey);
  return { merkleOk, signatureOk, recomputedRoot, claimedRoot };
}

/**
 * Verify a single hash-chained ledger row by recomputing its prevHash
 * link against the previous row.
 *
 * @param {{rowHash: string, prevRowHash: string|null}} previous
 * @param {{rowHash: string, prevRowHash: string|null, payload: object}} current
 * @returns {{linkOk: boolean, rowHashOk: boolean}}
 */
function verifyLedgerLink(previous, current) {
  const linkOk = current.prevRowHash === (previous ? previous.rowHash : null);
  const recomputed = sha256(
    Buffer.from(canonicalize(current.payload), "utf8")
  ).toString("hex");
  const rowHashOk = recomputed === current.rowHash;
  return { linkOk, rowHashOk };
}

module.exports = {
  sha256: (buf) => sha256(buf).toString("hex"),
  merkleRoot,
  canonicalize,
  verifySignature,
  verifyAnchor,
  verifyLedgerLink,
};
