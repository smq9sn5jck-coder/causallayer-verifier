# CausalLayer Post-Incident Attribution Specification (v0.1)

> **Status:** Draft (v0.1)
> **Author:** CausalLayer
> **Date:** 2026-05-14

This document specifies the canonical data structures, cryptographic primitives, and verification procedures for CausalLayer's post-incident AI-liability attribution certificates.

It is intended for developers building independent verifiers, auditors reviewing CausalLayer's public anchor log, and integrators consuming CausalLayer certificates in claims-handling or regulatory-reporting workflows.

---

## 1. Core Concepts

CausalLayer is a deterministic engine that assigns fault and calibrates damages for AI incidents. To make its output independently verifiable, the engine produces two types of cryptographic artefacts:

1. **Attribution Certificates:** JSON documents describing a specific incident, the fault allocation, and the damages range. Each certificate is signed by the engine.
2. **Daily Anchors:** JSON documents containing a Merkle root over all certificates issued on a given day. The anchor is signed by the engine and timestamped against the Bitcoin blockchain via OpenTimestamps.

A third party verifies a claim by confirming that a specific certificate's hash is included in a published daily anchor, and that the anchor itself is authentic and timestamped.

---

## 2. Certificate Schema

An attribution certificate is a JSON object with the following required fields:

```jsonc
{
  "type": "certificate",
  "version": "0.1",
  "incidentId": "string", // Opaque identifier
  "issuedAt": "string", // RFC 3339 timestamp
  "incidentDescription": "string",
  "harmType": "string", // e.g., "financial", "safety", "privacy", "death"
  "severity": "string", // Calibrated severity tier
  "faultAllocation": [
    {
      "party": "string", // e.g., "operator", "deployer", "model_vendor"
      "percentage": 0, // Integer 0-100
      "rationale": "string"
    }
  ],
  "damages": {
    "low": "string", // USD amount
    "high": "string",
    "methodology": "string"
  },
  "causalChain": [
    {
      "step": 1,
      "node": "string",
      "edges": ["string"]
    }
  ],
  "evidentiaryProperties": {
    "fre902_13_14_eligible": true,
    "eidas_qts_compatible": true,
    "australian_evidence_act_47_48_eligible": true
  },
  "signature": {
    "algorithm": "Ed25519",
    "publicKeyFingerprint": "string", // SHA-256 of SPKI DER, hex
    "value": "string" // Base64
  },
  "anchor": {
    "anchorLogRepo": "string", // URL to the public anchor log
    "dailyAnchorDate": "string", // YYYY-MM-DD
    "merkleLeafIndex": 0,
    "merkleRoot": "string", // Hex
    "openTimestampsProofPath": "string"
  }
}
```

### 2.1. Canonicalisation

Before hashing or signing, the JSON object (excluding the `signature` and `anchor` fields) MUST be canonicalised. CausalLayer uses a strict subset of RFC 8785 (JCS):

1. Whitespace is removed.
2. Object keys are sorted lexicographically by Unicode code point.
3. Strings are UTF-8 encoded.
4. Numbers are represented without trailing zeroes or unnecessary exponents.

The exact implementation used by the reference verifier is:

```javascript
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
```

### 2.2. Certificate Digest

The digest of a certificate is the SHA-256 hash of its canonicalised form (excluding `signature` and `anchor`). This digest is the value that becomes a leaf in the daily Merkle tree.

---

## 3. Anchor Schema

A daily anchor is a JSON object published to the `causallayer-anchor-log` repository. It has the following structure:

```jsonc
{
  "anchorDate": "string", // YYYY-MM-DD
  "merkleRoot": "string", // Hex
  "leafCount": 0,
  "latestLedgerHash": "string", // Hex
  "coveredLedgerDates": ["string"],
  "otsStatus": "string", // e.g., "pending", "confirmed"
  "schemaVersion": "0.1",
  "signature": {
    "algorithm": "Ed25519",
    "publicKeyFingerprint": "string",
    "value": "string", // Base64
    "authoritative": true // True if signed by the production key
  },
  "payload": {
    "leaves": ["string"] // Array of certificate digests (hex)
  }
}
```

### 3.1. Merkle Tree Construction

The Merkle tree is constructed from the array of certificate digests (`payload.leaves`).

1. Each leaf is hashed: `leafHash = SHA256(UTF8(digestHex))`.
2. Internal nodes are formed by concatenating the left and right child hashes and hashing the result: `nodeHash = SHA256(leftHash || rightHash)`.
3. If a layer has an odd number of nodes, the last node is duplicated and concatenated with itself: `nodeHash = SHA256(lastHash || lastHash)`.
4. The process repeats until a single root hash remains.

### 3.2. Anchor Signature

The anchor signature is computed over the canonicalised anchor object, excluding the `signature` and `payload` fields. The algorithm is Ed25519 (RFC 8032).

---

## 4. Verification Procedure

To independently verify a CausalLayer attribution certificate:

1. **Canonicalise and Hash:** Canonicalise the certificate (excluding `signature` and `anchor`) and compute its SHA-256 digest.
2. **Fetch Anchor:** Retrieve the daily anchor corresponding to the certificate's `anchor.dailyAnchorDate` from the public `causallayer-anchor-log` repository.
3. **Verify Inclusion:** Confirm that the certificate's digest appears in the anchor's `payload.leaves` array at the index specified by `anchor.merkleLeafIndex`.
4. **Verify Merkle Root:** Recompute the Merkle root from `payload.leaves` and confirm it matches `merkleRoot`.
5. **Verify Anchor Signature:** Canonicalise the anchor (excluding `signature` and `payload`) and verify the Ed25519 signature against the canonical CausalLayer public key (identified by `signature.publicKeyFingerprint`).
6. **Verify Timestamp:** Retrieve the OpenTimestamps proof (`.ots` file) corresponding to the anchor and verify it against the Bitcoin blockchain using an independent OTS client.

If all steps succeed, the certificate is cryptographically proven to have been issued by CausalLayer, included in the public ledger, and timestamped no later than the Bitcoin block time.

---

## 5. Trust Model and Key Management

CausalLayer uses a single canonical Ed25519 keypair for authoritative signatures.

- The private key is held in offline custody and is never exposed to client environments or public repositories.
- The public key is published in the `causallayer-anchor-log` repository in PEM and JWK formats.
- The SHA-256 fingerprint of the public key's SPKI DER encoding is published in `fingerprint.txt`.

Verifiers MUST pin the canonical fingerprint and reject any anchor signed by an unknown key. Key rotations are additive, publicly documented via `KEY-ROTATION-{date}.md` post-mortems, and never silently rewrite history.

### 5.1. Dev-Mode Anchors

During development or when the production key is unavailable, CausalLayer may emit anchors signed by ephemeral test keys. These anchors will have `signature.authoritative: false` and a fingerprint that does not match the canonical production key. Verifiers MUST flag these as non-evidentiary test records.
