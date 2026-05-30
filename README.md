# causallayer-verifier

**Client-side verification for CausalCertificateV1 certificates.**

Runs the same 7-check pipeline as [faultkey.com/verify](https://faultkey.com/verify) (Tab C: Client-side, zero-trust). Zero server trust — all checks run locally.

## Install

```bash
npm install causallayer-verifier
# or run directly:
npx causallayer-verifier ./certificate.json
```

## CLI Usage

```bash
# Verify a certificate file
causallayer-verifier ./my-cert.json

# Read from stdin
cat cert.json | causallayer-verifier --stdin

# Pipe from API
curl -s https://mcp.faultkey.com/cert/abc123 | causallayer-verifier --stdin
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | VERIFIED — all checks pass |
| 1 | FAILED — one or more integrity checks failed |
| 2 | VERIFIED_WITH_NOTES — valid but with warnings (e.g., demo cert, unanchored) |

## Programmatic Usage

```typescript
import { verifyCertificate } from "causallayer-verifier";

const result = await verifyCertificate(jsonString);

console.log(result.verdict); // "VERIFIED" | "VERIFIED_WITH_NOTES" | "FAILED"
console.log(result.checks);  // Array of 7 check results
console.log(result.totalDurationMs); // Total verification time
```

## Verification Pipeline

| # | Check | What it does |
|---|-------|-------------|
| 1 | **Schema** | Validates CausalCertificateV1 structure and required fields |
| 2 | **Issuer Trust** | Fetches `.well-known/causallayer-issuers.json` and confirms key_id is registered + active |
| 3 | **Signature** | Ed25519 verification over RFC 8785 JCS-canonicalized payload |
| 4 | **Merkle Tree** | Recomputes SHA-256 Merkle root from causal_chain leaves |
| 5 | **Hash Consistency** | Verifies request_hash matches canonical input fields |
| 6 | **Recompute** | Skipped in CLI (requires engine access — use web verifier or MCP) |
| 7 | **Anchor** | Checks for OpenTimestamps / Sigstore Rekor proof presence |

## Trust Model

> **Litmus test:** Could a hostile party, with no API access and no trust in faultkey.com, reach the same verdict?

**Yes.** All checks run locally using Node.js `crypto` module. The only external fetch is the issuer's public key registry at a pinnable `.well-known` URL (with hardcoded fallback if unreachable).

### Three Surfaces, Identical Checks

| Surface | Command | Same pipeline? |
|---------|---------|---------------|
| Web | faultkey.com/verify → Tab C | ✓ |
| CLI | `npx causallayer-verifier` | ✓ |
| MCP | `verify_certificate` tool | ✓ |

## Canonicalization

Uses [RFC 8785 (JSON Canonicalization Scheme)](https://www.rfc-editor.org/rfc/rfc8785) for deterministic JSON serialization before hashing and signature verification. This ensures byte-identical representations regardless of key ordering or whitespace.

## Requirements

- Node.js >= 18.0.0 (uses `crypto.createVerify` with Ed25519 support)

## License

MIT
