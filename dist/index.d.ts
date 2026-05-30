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
export declare function canonicalize(obj: any): string;
export declare function sha256Hex(data: string): string;
export declare function computeMerkleRoot(leaves: string[]): string;
export declare function verifyCertificate(input: string | CausalCertificateV1): Promise<VerificationResult>;
