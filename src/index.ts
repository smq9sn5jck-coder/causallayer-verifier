/**
 * causallayer-verifier
 * 
 * Client-side verification for CausalCertificateV1 certificates.
 * Runs the same 7-check pipeline as the web verifier at faultkey.com/verify.
 * 
 * Checks:
 *   1. Schema validation
 *   2. Issuer trust (fetches .well-known registry or uses pinned fallback)
 *   3. Signature verification (Ed25519)
 *   4. Merkle tree integrity
 *   5. Hash consistency
 *   6. Recompute (optional — requires engine access)
 *   7. Anchor status (OpenTimestamps / Sigstore Rekor)
 * 
 * Trust model: Zero server trust. All checks run locally.
 * The only external fetch is the issuer's public key at a pinnable .well-known URL.
 */

import { createHash, verify as cryptoVerify } from "node:crypto";

// ─── Types ─────────────────────────────────────────────────────────────────
export type CheckStatus = "pass" | "fail" | "warn" | "pending" | "skipped";
export type OverallVerdict = "VERIFIED" | "VERIFIED_WITH_NOTES" | "FAILED";

export interface CheckResult {
  id: number;
  name: string;
  description: string;
  status: CheckStatus;
  detail: string;
  durationMs: number;
}

export interface VerificationResult {
  verdict: OverallVerdict;
  checks: CheckResult[];
  totalDurationMs: number;
  cert: CausalCertificateV1 | null;
}

export interface CausalCertificateV1 {
  cert_id: string;
  schema: string;
  version?: string;
  incident_id: string;
  timestamp: string;
  law_as_of: string;
  jurisdiction: string;
  issuer: {
    id: string;
    key_id: string;
    algorithm: string;
  };
  signature: string;
  merkle_root: string;
  request_hash: string;
  outputs: Record<string, any>;
  causal_chain: any[];
  regulatory_framework?: any;
  anchor?: any;
  [key: string]: any;
}

// ─── Canonicalization (RFC 8785 JCS) ────────────────────────────────────────
export function canonicalize(obj: any): string {
  if (obj === null || obj === undefined) return "null";
  if (typeof obj === "boolean" || typeof obj === "number") return JSON.stringify(obj);
  if (typeof obj === "string") return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalize).join(",") + "]";
  }
  const keys = Object.keys(obj).sort();
  const pairs = keys
    .filter((k) => obj[k] !== undefined)
    .map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k]));
  return "{" + pairs.join(",") + "}";
}

// ─── Hashing ────────────────────────────────────────────────────────────────
export function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

// ─── Merkle Tree ────────────────────────────────────────────────────────────
export function computeMerkleRoot(leaves: string[]): string {
  if (leaves.length === 0) return sha256Hex("");
  let level = leaves.map((l) => sha256Hex(l));
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      next.push(sha256Hex(left + right));
    }
    level = next;
  }
  return level[0];
}

// ─── Issuer Registry ────────────────────────────────────────────────────────
interface IssuerKey {
  key_id: string;
  alg: string;
  public_key_base64: string;
  status: string;
  valid_from: string;
}

interface IssuerRegistry {
  issuer_id: string;
  keys: IssuerKey[];
}

const PINNED_REGISTRY: IssuerRegistry = {
  issuer_id: "did:web:faultkey.com#scoring-engine",
  keys: [
    {
      key_id: "ed25519:demo-key-v1",
      alg: "ed25519",
      public_key_base64: "MCowBQYDK2VwAyEAx8WqJdPe0GXGBH1JrJCbN1IxPBXIyMqVDKzqMiXdSk=",
      status: "active",
      valid_from: "2024-01-01T00:00:00Z",
    },
    {
      key_id: "ed25519:prod-key-v1",
      alg: "ed25519",
      public_key_base64: "MCowBQYDK2VwAyEAKf7R3mZ9vNpL2xQ8hY6wJdT5eB1nC4oA0sF7gH2iJ3k=",
      status: "active",
      valid_from: "2026-05-01T00:00:00Z",
    },
  ],
};

const REGISTRY_URL = "https://faultkey.com/.well-known/causallayer-issuers.json";

async function fetchIssuerRegistry(): Promise<{ registry: IssuerRegistry; source: "remote" | "pinned" }> {
  let result: { registry: IssuerRegistry; source: "remote" | "pinned" };
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(REGISTRY_URL, { signal: controller.signal });
    clearTimeout(timeout);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    result = { registry: data as IssuerRegistry, source: "remote" };
  } catch {
    result = { registry: PINNED_REGISTRY, source: "pinned" };
  }
  return { ...result, registry: applyExtraIssuerKeys(result.registry) };
}

/**
 * Merge operator-provided issuer keys (env var CAUSALLAYER_ISSUER_KEYS, a JSON
 * array of IssuerKey) over the resolved registry. Lets keys be added or rotated
 * without a redeploy, and gives tests a seam to register a freshly generated
 * key. Extra keys override registry keys with the same key_id. Mirrors the
 * ISSUER_PUBLIC_KEYS override in faultkey-cert-worker.
 */
function applyExtraIssuerKeys(registry: IssuerRegistry): IssuerRegistry {
  const raw = (globalThis as any).process?.env?.CAUSALLAYER_ISSUER_KEYS;
  if (!raw) return registry;
  try {
    const extra = JSON.parse(raw) as IssuerKey[];
    if (!Array.isArray(extra) || extra.length === 0) return registry;
    const byId = new Map(registry.keys.map((k) => [k.key_id, k]));
    for (const k of extra) byId.set(k.key_id, k);
    return { ...registry, keys: Array.from(byId.values()) };
  } catch {
    return registry; // malformed override — ignore, keep the resolved registry
  }
}

// ─── Verification Pipeline ──────────────────────────────────────────────────
export async function verifyCertificate(input: string | CausalCertificateV1): Promise<VerificationResult> {
  const startTime = performance.now();
  const checks: CheckResult[] = [];
  let cert: CausalCertificateV1 | null = null;

  // Check 1: Schema validation
  const c1Start = performance.now();
  try {
    cert = typeof input === "string" ? JSON.parse(input) : input;
    if (cert === null || typeof cert !== "object" || Array.isArray(cert)) {
      throw new Error("Certificate must be a JSON object");
    }
    const required = ["cert_id", "schema", "incident_id", "timestamp", "issuer", "signature", "merkle_root", "outputs", "causal_chain"];
    const missing = required.filter((f) => !(f in (cert as any)));
    // Validate field types of untrusted input before any crypto/structural checks consume them.
    const typeErrors: string[] = [];
    if (cert!.issuer !== undefined && (typeof cert!.issuer !== "object" || cert!.issuer === null || Array.isArray(cert!.issuer))) typeErrors.push("issuer must be an object");
    if (cert!.signature !== undefined && typeof cert!.signature !== "string") typeErrors.push("signature must be a string");
    if (cert!.merkle_root !== undefined && typeof cert!.merkle_root !== "string") typeErrors.push("merkle_root must be a string");
    if (cert!.causal_chain !== undefined && !Array.isArray(cert!.causal_chain)) typeErrors.push("causal_chain must be an array");
    if (cert!.outputs !== undefined && (typeof cert!.outputs !== "object" || cert!.outputs === null || Array.isArray(cert!.outputs))) typeErrors.push("outputs must be an object");
    if (missing.length > 0) {
      checks.push({ id: 1, name: "Schema", description: "CausalCertificateV1 structure", status: "fail", detail: `Missing fields: ${missing.join(", ")}`, durationMs: performance.now() - c1Start });
    } else if (typeErrors.length > 0) {
      checks.push({ id: 1, name: "Schema", description: "CausalCertificateV1 structure", status: "fail", detail: `Invalid field types: ${typeErrors.join("; ")}`, durationMs: performance.now() - c1Start });
    } else if (cert!.schema !== "CausalCertificateV1") {
      checks.push({ id: 1, name: "Schema", description: "CausalCertificateV1 structure", status: "warn", detail: `Schema field is "${cert!.schema}" (expected "CausalCertificateV1")`, durationMs: performance.now() - c1Start });
    } else {
      checks.push({ id: 1, name: "Schema", description: "CausalCertificateV1 structure", status: "pass", detail: `All required fields present. Schema: ${cert!.schema}`, durationMs: performance.now() - c1Start });
    }
  } catch (e: any) {
    checks.push({ id: 1, name: "Schema", description: "CausalCertificateV1 structure", status: "fail", detail: `Parse error: ${e.message}`, durationMs: performance.now() - c1Start });
    return { verdict: "FAILED", checks, totalDurationMs: performance.now() - startTime, cert: null };
  }

  // Check 2: Issuer trust
  const c2Start = performance.now();
  const { registry, source } = await fetchIssuerRegistry();
  const keyId = cert!.issuer?.key_id;
  const matchedKey = registry.keys.find((k) => k.key_id === keyId);
  if (!matchedKey) {
    checks.push({ id: 2, name: "Issuer Trust", description: "Key registered in issuer registry", status: "fail", detail: `Key "${keyId}" not found in registry (source: ${source}). Known keys: ${registry.keys.map(k => k.key_id).join(", ")}`, durationMs: performance.now() - c2Start });
  } else if (matchedKey.status !== "active") {
    checks.push({ id: 2, name: "Issuer Trust", description: "Key registered in issuer registry", status: "warn", detail: `Key "${keyId}" found but status is "${matchedKey.status}" (source: ${source})`, durationMs: performance.now() - c2Start });
  } else {
    checks.push({ id: 2, name: "Issuer Trust", description: "Key registered in issuer registry", status: "pass", detail: `Key "${keyId}" is active (source: ${source}, valid from ${matchedKey.valid_from})`, durationMs: performance.now() - c2Start });
  }

  // Check 3: Signature verification
  const c3Start = performance.now();
  try {
    const signableFields = { ...cert };
    delete (signableFields as any).signature;
    delete (signableFields as any).anchor;
    const canonical = canonicalize(signableFields);
    const sigHex = cert!.signature;
    
    if (matchedKey) {
      // Validate algorithm agreement and signature encoding BEFORE attempting verification.
      // An Ed25519 signature is exactly 64 bytes = 128 hex chars; reject anything else
      // rather than letting Buffer.from(...,"hex") silently truncate malformed input.
      if (matchedKey.alg !== "ed25519" || cert!.issuer?.algorithm !== "ed25519") {
        checks.push({ id: 3, name: "Signature", description: "Ed25519 signature over canonical payload", status: "fail", detail: `Algorithm mismatch: registry key alg="${matchedKey.alg}", cert algorithm="${cert!.issuer?.algorithm}". Expected "ed25519".`, durationMs: performance.now() - c3Start });
      } else if (typeof sigHex !== "string" || !/^[0-9a-fA-F]{128}$/.test(sigHex)) {
        checks.push({ id: 3, name: "Signature", description: "Ed25519 signature over canonical payload", status: "fail", detail: `Signature is not a valid 128-character (64-byte) hex string.`, durationMs: performance.now() - c3Start });
      } else {
        const pubKeyDer = Buffer.from(matchedKey.public_key_base64, "base64");
        const sigBuf = Buffer.from(sigHex, "hex");
        // Ed25519 is a pure (non-prehashed) signature scheme: it has no digest
        // algorithm, so the streaming createVerify("Ed25519") API throws
        // "Invalid digest". The one-shot crypto.verify(null, ...) API is the
        // correct path for Ed25519/Ed448.
        const valid = cryptoVerify(null, Buffer.from(canonical), { key: pubKeyDer, format: "der", type: "spki" }, sigBuf);
        if (valid) {
          checks.push({ id: 3, name: "Signature", description: "Ed25519 signature over canonical payload", status: "pass", detail: `Signature verified against key ${keyId}. Canonical payload: ${canonical.length} bytes.`, durationMs: performance.now() - c3Start });
        } else {
          checks.push({ id: 3, name: "Signature", description: "Ed25519 signature over canonical payload", status: "fail", detail: `Signature INVALID for key ${keyId}. The certificate has been tampered with or was not signed by this key.`, durationMs: performance.now() - c3Start });
        }
      }
    } else {
      // No registered key matches the cert's key_id. A signature verifier must fail closed:
      // never accept a signature based on its length/format alone. We only acknowledge the
      // legacy demo hash-based signature when it EXACTLY matches the expected digest.
      const expectedSig = sha256Hex(cert!.incident_id + "PRIMARY_CONTRIBUTOR_AI_PROVIDER" + JSON.stringify(cert!.outputs));
      if (sigHex === expectedSig) {
        checks.push({ id: 3, name: "Signature", description: "Ed25519 signature over canonical payload", status: "warn", detail: `Demo mode: hash-based signature matched (no registered key to verify against). Not a cryptographic signature — for demonstration only.`, durationMs: performance.now() - c3Start });
      } else {
        checks.push({ id: 3, name: "Signature", description: "Ed25519 signature over canonical payload", status: "fail", detail: `Cannot verify: no registered key matches key_id "${keyId}" and the signature does not match the expected demo digest.`, durationMs: performance.now() - c3Start });
      }
    }
  } catch (e: any) {
    checks.push({ id: 3, name: "Signature", description: "Ed25519 signature over canonical payload", status: "fail", detail: `Verification error: ${e.message}`, durationMs: performance.now() - c3Start });
  }

  // Check 4: Merkle tree integrity
  const c4Start = performance.now();
  try {
    const chain = cert!.causal_chain || [];
    const leaves = chain.map((node: any) => canonicalize(node));
    const computed = computeMerkleRoot(leaves);
    const claimed = cert!.merkle_root;
    if (computed === claimed) {
      checks.push({ id: 4, name: "Merkle Tree", description: "Recompute Merkle root from causal chain", status: "pass", detail: `Computed root matches claimed root.\nRoot: ${computed}\nLeaves: ${leaves.length}`, durationMs: performance.now() - c4Start });
    } else {
      checks.push({ id: 4, name: "Merkle Tree", description: "Recompute Merkle root from causal chain", status: "fail", detail: `Merkle root MISMATCH.\nClaimed: ${claimed}\nComputed: ${computed}\nLeaves: ${leaves.length}\n\nThe causal chain has been modified after signing.`, durationMs: performance.now() - c4Start });
    }
  } catch (e: any) {
    checks.push({ id: 4, name: "Merkle Tree", description: "Recompute Merkle root from causal chain", status: "fail", detail: `Computation error: ${e.message}`, durationMs: performance.now() - c4Start });
  }

  // Check 5: Hash consistency
  const c5Start = performance.now();
  try {
    const inputPayload = canonicalize({
      incident_id: cert!.incident_id,
      timestamp: cert!.timestamp,
      jurisdiction: cert!.jurisdiction,
      law_as_of: cert!.law_as_of,
    });
    const computedRequestHash = sha256Hex(inputPayload);
    const claimedRequestHash = cert!.request_hash;
    if (computedRequestHash === claimedRequestHash) {
      checks.push({ id: 5, name: "Hash Consistency", description: "request_hash matches canonical inputs", status: "pass", detail: `Request hash verified.\nHash: ${computedRequestHash}`, durationMs: performance.now() - c5Start });
    } else {
      checks.push({ id: 5, name: "Hash Consistency", description: "request_hash matches canonical inputs", status: "fail", detail: `Request hash MISMATCH.\nClaimed: ${claimedRequestHash}\nComputed: ${computedRequestHash}\n\nInput fields may have been altered.`, durationMs: performance.now() - c5Start });
    }
  } catch (e: any) {
    checks.push({ id: 5, name: "Hash Consistency", description: "request_hash matches canonical inputs", status: "fail", detail: `Computation error: ${e.message}`, durationMs: performance.now() - c5Start });
  }

  // Check 6: Recompute (skipped in CLI — requires engine access)
  const c6Start = performance.now();
  checks.push({ id: 6, name: "Recompute", description: "Re-run scoring engine with same inputs", status: "skipped", detail: "Recomputation requires engine access. Use the web verifier at faultkey.com/verify (Scenario Reproduction mode) or the MCP endpoint to verify output reproducibility.", durationMs: performance.now() - c6Start });

  // Check 7: Anchor status
  const c7Start = performance.now();
  const anchor = cert!.anchor;
  if (!anchor) {
    checks.push({ id: 7, name: "Anchor", description: "OpenTimestamps / Sigstore Rekor proof", status: "warn", detail: "No anchor field present. Demo certificates are not anchored. Production certificates include OpenTimestamps and/or Sigstore Rekor proofs.", durationMs: performance.now() - c7Start });
  } else if (anchor.ots_proof || anchor.rekor_entry) {
    checks.push({ id: 7, name: "Anchor", description: "OpenTimestamps / Sigstore Rekor proof", status: "pass", detail: `Anchor present.\nOTS: ${anchor.ots_proof ? "yes" : "no"}\nRekor: ${anchor.rekor_entry ? "yes" : "no"}\nAnchored at: ${anchor.anchored_at || "unknown"}`, durationMs: performance.now() - c7Start });
  } else {
    checks.push({ id: 7, name: "Anchor", description: "OpenTimestamps / Sigstore Rekor proof", status: "warn", detail: `Anchor field present but no proof data found. Keys: ${Object.keys(anchor).join(", ")}`, durationMs: performance.now() - c7Start });
  }

  // Compute verdict
  const failCount = checks.filter((c) => c.status === "fail").length;
  const warnCount = checks.filter((c) => c.status === "warn").length;
  let verdict: OverallVerdict;
  if (failCount > 0) verdict = "FAILED";
  else if (warnCount > 0) verdict = "VERIFIED_WITH_NOTES";
  else verdict = "VERIFIED";

  return {
    verdict,
    checks,
    totalDurationMs: performance.now() - startTime,
    cert,
  };
}
