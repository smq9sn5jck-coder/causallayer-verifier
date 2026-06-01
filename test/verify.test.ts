import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { generateKeyPairSync, sign as edSign, type KeyObject } from "node:crypto";
import {
  canonicalize,
  sha256Hex,
  computeMerkleRoot,
  verifyCertificate,
  type CausalCertificateV1,
} from "../src/index.js";

// ─── Test fixtures ───────────────────────────────────────────────────────────
// We generate a real Ed25519 keypair, expose its public key through a mocked
// issuer registry, and sign a real certificate. This exercises the genuine
// signature / Merkle / hash-consistency paths end to end.

const KEY_ID = "ed25519:test-key-v1";
const ISSUER_ID = "did:web:faultkey.com#scoring-engine";

let publicKey: KeyObject;
let privateKey: KeyObject;
let pubKeyBase64: string;

function buildRegistry(overrides: Partial<{ status: string; key_id: string }> = {}) {
  return {
    issuer_id: ISSUER_ID,
    keys: [
      {
        key_id: overrides.key_id ?? KEY_ID,
        alg: "ed25519",
        public_key_base64: pubKeyBase64,
        status: overrides.status ?? "active",
        valid_from: "2024-01-01T00:00:00Z",
      },
    ],
  };
}

/** Mock global.fetch so the verifier's registry lookup returns our registry. */
function mockRegistry(registry: unknown, ok = true) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({
      ok,
      status: ok ? 200 : 500,
      json: async () => registry,
    })) as unknown as typeof fetch,
  );
}

/** Force the registry fetch to fail so the verifier falls back to its pinned set. */
function mockRegistryNetworkFailure() {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new Error("network down");
    }) as unknown as typeof fetch,
  );
}

/**
 * Build a fully valid, signed CausalCertificateV1. merkle_root and request_hash
 * are computed exactly as the verifier recomputes them, and the signature is a
 * real Ed25519 signature over the canonical signable payload.
 */
function buildValidCert(): CausalCertificateV1 {
  const causal_chain = [
    { node: "agent-a", role: "ai_provider", contribution: 0.6 },
    { node: "agent-b", role: "deployer", contribution: 0.4 },
  ];

  const base: Omit<CausalCertificateV1, "signature" | "merkle_root" | "request_hash"> = {
    cert_id: "cert_test_0001",
    schema: "CausalCertificateV1",
    version: "1.0.0",
    incident_id: "inc_test_0001",
    timestamp: "2026-05-01T12:00:00Z",
    law_as_of: "2026-05-01",
    jurisdiction: "EU",
    issuer: { id: ISSUER_ID, key_id: KEY_ID, algorithm: "ed25519" },
    outputs: { primary_contributor: "ai_provider", shares: { ai_provider: 0.6, deployer: 0.4 } },
    causal_chain,
  };

  const merkle_root = computeMerkleRoot(causal_chain.map((n) => canonicalize(n)));
  const request_hash = sha256Hex(
    canonicalize({
      incident_id: base.incident_id,
      timestamp: base.timestamp,
      jurisdiction: base.jurisdiction,
      law_as_of: base.law_as_of,
    }),
  );

  // Signature is computed over the canonical form of the cert MINUS the
  // signature and anchor fields — exactly what the verifier reconstructs.
  const signable = { ...base, merkle_root, request_hash };
  const canonical = canonicalize(signable);
  const signature = edSign(null, Buffer.from(canonical), privateKey).toString("hex");

  return { ...signable, signature } as CausalCertificateV1;
}

function statusOf(checks: { id: number; status: string }[], id: number) {
  return checks.find((c) => c.id === id)?.status;
}

beforeEach(() => {
  ({ publicKey, privateKey } = generateKeyPairSync("ed25519"));
  pubKeyBase64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");
  mockRegistry(buildRegistry());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ─── Pure helpers ─────────────────────────────────────────────────────────────
describe("canonicalize (RFC 8785-style JCS)", () => {
  it("sorts object keys deterministically regardless of insertion order", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it("recurses into nested objects and arrays", () => {
    expect(canonicalize({ z: [{ y: 1, x: 2 }], a: "s" })).toBe('{"a":"s","z":[{"x":2,"y":1}]}');
  });

  it("preserves array order (arrays are ordered, objects are not)", () => {
    expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
  });

  it("omits undefined-valued keys but keeps null", () => {
    expect(canonicalize({ a: undefined, b: null })).toBe('{"b":null}');
  });

  it("is stable across repeated calls (no nondeterminism)", () => {
    const obj = { foo: "bar", n: 42, arr: [1, { k: "v" }] };
    expect(canonicalize(obj)).toBe(canonicalize(obj));
  });
});

describe("sha256Hex", () => {
  it("matches the known SHA-256 of the empty string", () => {
    expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("produces a stable 64-char lowercase hex digest", () => {
    const d = sha256Hex("causallayer");
    expect(d).toMatch(/^[0-9a-f]{64}$/);
    expect(sha256Hex("causallayer")).toBe(d);
  });

  it("is sensitive to input changes", () => {
    expect(sha256Hex("a")).not.toBe(sha256Hex("b"));
  });
});

describe("computeMerkleRoot", () => {
  it("returns the empty-string hash for an empty leaf set", () => {
    expect(computeMerkleRoot([])).toBe(sha256Hex(""));
  });

  it("hashes a single leaf (no pairing) to sha256 of that leaf", () => {
    expect(computeMerkleRoot(["only"])).toBe(sha256Hex("only"));
  });

  it("duplicates the last leaf when a level has an odd count", () => {
    const h = (s: string) => sha256Hex(s);
    // three leaves: l0,l1,l2 -> [H(l0), H(l1), H(l2)] -> [H(H(l0)+H(l1)), H(H(l2)+H(l2))] -> root
    const l = ["a", "b", "c"];
    const lvl1 = l.map(h);
    const lvl2 = [h(lvl1[0] + lvl1[1]), h(lvl1[2] + lvl1[2])];
    expect(computeMerkleRoot(l)).toBe(h(lvl2[0] + lvl2[1]));
  });

  it("changes when any leaf changes (tamper-evidence)", () => {
    const a = computeMerkleRoot(["x", "y", "z"]);
    const b = computeMerkleRoot(["x", "y", "Z"]);
    expect(a).not.toBe(b);
  });

  it("is order-sensitive", () => {
    expect(computeMerkleRoot(["x", "y"])).not.toBe(computeMerkleRoot(["y", "x"]));
  });
});

// ─── Full verification pipeline ───────────────────────────────────────────────
describe("verifyCertificate — happy path", () => {
  it("VERIFIES a correctly signed certificate (no anchor → notes)", async () => {
    const cert = buildValidCert();
    const res = await verifyCertificate(cert);

    expect(statusOf(res.checks, 1)).toBe("pass"); // schema
    expect(statusOf(res.checks, 2)).toBe("pass"); // issuer trust
    expect(statusOf(res.checks, 3)).toBe("pass"); // signature  (regression guard for the Ed25519 fix)
    expect(statusOf(res.checks, 4)).toBe("pass"); // merkle
    expect(statusOf(res.checks, 5)).toBe("pass"); // hash consistency
    expect(statusOf(res.checks, 6)).toBe("skipped"); // recompute
    expect(statusOf(res.checks, 7)).toBe("warn"); // no anchor
    // One warn (anchor) and zero fails → VERIFIED_WITH_NOTES.
    expect(res.verdict).toBe("VERIFIED_WITH_NOTES");
  });

  it("accepts a string-encoded certificate as well as an object", async () => {
    const cert = buildValidCert();
    const res = await verifyCertificate(JSON.stringify(cert));
    expect(res.cert).not.toBeNull();
    expect(statusOf(res.checks, 3)).toBe("pass");
  });

  it("fully VERIFIES (no notes) when a valid anchor is present", async () => {
    const cert = buildValidCert();
    cert.anchor = { ots_proof: "deadbeef", anchored_at: "2026-05-02T00:00:00Z" };
    // Anchor is excluded from the signed payload, so the signature still holds.
    const res = await verifyCertificate(cert);
    expect(statusOf(res.checks, 7)).toBe("pass");
    expect(res.verdict).toBe("VERIFIED");
  });
});

describe("verifyCertificate — tamper & failure detection", () => {
  it("FAILS signature when a single signature byte is flipped", async () => {
    const cert = buildValidCert();
    const buf = Buffer.from(cert.signature, "hex");
    buf[0] ^= 0xff;
    cert.signature = buf.toString("hex");
    const res = await verifyCertificate(cert);
    expect(statusOf(res.checks, 3)).toBe("fail");
    expect(res.verdict).toBe("FAILED");
  });

  it("FAILS Merkle when the causal chain is modified after signing", async () => {
    const cert = buildValidCert();
    cert.causal_chain[0].contribution = 0.99; // tamper, but keep claimed merkle_root
    const res = await verifyCertificate(cert);
    expect(statusOf(res.checks, 4)).toBe("fail");
    // Signature also breaks because the chain is part of the signed payload.
    expect(statusOf(res.checks, 3)).toBe("fail");
    expect(res.verdict).toBe("FAILED");
  });

  it("FAILS hash consistency when an input field is altered post-signing", async () => {
    const cert = buildValidCert();
    cert.request_hash = sha256Hex("not-the-real-inputs");
    const res = await verifyCertificate(cert);
    expect(statusOf(res.checks, 5)).toBe("fail");
    expect(res.verdict).toBe("FAILED");
  });

  it("FAILS issuer trust when the signing key is not in the registry", async () => {
    mockRegistry(buildRegistry({ key_id: "ed25519:some-other-key" }));
    const cert = buildValidCert();
    const res = await verifyCertificate(cert);
    expect(statusOf(res.checks, 2)).toBe("fail");
    expect(res.verdict).toBe("FAILED");
  });

  it("WARNs issuer trust when the registered key is not active", async () => {
    mockRegistry(buildRegistry({ status: "revoked" }));
    const cert = buildValidCert();
    const res = await verifyCertificate(cert);
    expect(statusOf(res.checks, 2)).toBe("warn");
  });
});

describe("verifyCertificate — malformed input", () => {
  it("FAILS fast on unparseable JSON and returns a null cert", async () => {
    const res = await verifyCertificate("{ not json ]");
    expect(res.verdict).toBe("FAILED");
    expect(res.cert).toBeNull();
    expect(statusOf(res.checks, 1)).toBe("fail");
    // It should short-circuit: no later checks run.
    expect(res.checks).toHaveLength(1);
  });

  it("FAILS schema when required fields are missing", async () => {
    const res = await verifyCertificate({ schema: "CausalCertificateV1" } as unknown as CausalCertificateV1);
    expect(statusOf(res.checks, 1)).toBe("fail");
    expect(res.verdict).toBe("FAILED");
  });

  it("WARNs schema on an unexpected schema string but still runs the pipeline", async () => {
    const cert = buildValidCert();
    cert.schema = "CausalCertificateV2";
    const res = await verifyCertificate(cert);
    expect(statusOf(res.checks, 1)).toBe("warn");
  });
});

describe("verifyCertificate — registry resolution", () => {
  it("falls back to the pinned registry when the remote fetch fails", async () => {
    mockRegistryNetworkFailure();
    const cert = buildValidCert();
    const res = await verifyCertificate(cert);
    // Our generated key is unknown to the pinned registry → issuer trust fails,
    // but the pipeline still completes deterministically without throwing.
    expect(statusOf(res.checks, 2)).toBe("fail");
    expect(res.checks).toHaveLength(7);
  });

  it("trusts a key supplied via the CAUSALLAYER_ISSUER_KEYS env override", async () => {
    // Remote and pinned registries do NOT know our generated key. Supplying it
    // through the env override (the runtime key-rotation seam) must let issuer
    // trust AND signature verification pass — without a redeploy.
    mockRegistryNetworkFailure();
    process.env.CAUSALLAYER_ISSUER_KEYS = JSON.stringify([
      {
        key_id: KEY_ID,
        alg: "ed25519",
        public_key_base64: pubKeyBase64,
        status: "active",
        valid_from: "2020-01-01T00:00:00Z",
      },
    ]);
    try {
      const cert = buildValidCert();
      const res = await verifyCertificate(cert);
      expect(statusOf(res.checks, 2)).toBe("pass"); // issuer trust
      expect(statusOf(res.checks, 3)).toBe("pass"); // signature
    } finally {
      delete process.env.CAUSALLAYER_ISSUER_KEYS;
    }
  });

  it("ignores a malformed CAUSALLAYER_ISSUER_KEYS value", async () => {
    mockRegistryNetworkFailure();
    process.env.CAUSALLAYER_ISSUER_KEYS = "{ not valid json";
    try {
      const cert = buildValidCert();
      const res = await verifyCertificate(cert);
      // Malformed override is ignored → key still unknown → issuer trust fails,
      // and the pipeline does not throw.
      expect(statusOf(res.checks, 2)).toBe("fail");
      expect(res.checks).toHaveLength(7);
    } finally {
      delete process.env.CAUSALLAYER_ISSUER_KEYS;
    }
  });
});
