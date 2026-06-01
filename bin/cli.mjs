#!/usr/bin/env node
/**
 * causallayer-verifier CLI
 * 
 * Usage:
 *   npx causallayer-verifier ./certificate.json
 *   npx causallayer-verifier --stdin < cert.json
 *   echo '{"cert_id":...}' | npx causallayer-verifier --stdin
 * 
 * Runs the same 7-check verification pipeline as faultkey.com/verify (Tab C).
 * Zero server trust. All checks run locally.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyCertificate } from "../dist/index.js";

const PKG_VERSION = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8"),
).version;

const RESET = "\x1b[0m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";

function statusColor(status) {
  switch (status) {
    case "pass": return GREEN;
    case "fail": return RED;
    case "warn": return YELLOW;
    default: return DIM;
  }
}

function statusIcon(status) {
  switch (status) {
    case "pass": return "✓";
    case "fail": return "✗";
    case "warn": return "⚠";
    case "skipped": return "⏭";
    default: return "…";
  }
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes("--help") || args.includes("-h")) {
    console.log(`
${BOLD}causallayer-verifier${RESET} — Verify CausalCertificateV1 certificates

${BOLD}USAGE${RESET}
  causallayer-verifier <file.json>       Verify a certificate file
  causallayer-verifier --stdin           Read certificate from stdin
  causallayer-verifier --help            Show this help

${BOLD}CHECKS${RESET}
  1. Schema          CausalCertificateV1 structure validation
  2. Issuer Trust    Key registered in .well-known issuer registry
  3. Signature       Ed25519 over canonical (RFC 8785 JCS) payload
  4. Merkle Tree     Recompute root from causal chain leaves
  5. Hash            request_hash matches canonical inputs
  6. Recompute       (Skipped — requires engine access)
  7. Anchor          OpenTimestamps / Sigstore Rekor proof

${BOLD}TRUST MODEL${RESET}
  All checks run locally. The only external fetch is the issuer registry
  at faultkey.com/.well-known/causallayer-issuers.json (with pinned fallback).

${BOLD}EXAMPLES${RESET}
  $ causallayer-verifier ./my-cert.json
  $ curl -s https://faultkey.com/api/cert/abc123 | causallayer-verifier --stdin
  $ cat cert.json | causallayer-verifier --stdin

${BOLD}WEB EQUIVALENT${RESET}
  https://faultkey.com/verify → Tab C (Client-side, zero-trust)
`);
    process.exit(0);
  }

  let input;

  if (args.includes("--stdin")) {
    // Read from stdin
    const chunks = [];
    for await (const chunk of process.stdin) {
      chunks.push(chunk);
    }
    input = Buffer.concat(chunks).toString("utf8");
  } else if (args.length > 0) {
    const filePath = resolve(args[0]);
    try {
      input = readFileSync(filePath, "utf8");
    } catch (e) {
      console.error(`${RED}Error:${RESET} Cannot read file: ${filePath}`);
      console.error(e.message);
      process.exit(1);
    }
  } else {
    console.error(`${RED}Error:${RESET} No input provided.`);
    console.error(`Usage: causallayer-verifier <file.json> or causallayer-verifier --stdin`);
    process.exit(1);
  }

  console.log(`\n${BOLD}causallayer-verifier v${PKG_VERSION}${RESET}`);
  console.log(`${DIM}─────────────────────────────────────────${RESET}\n`);

  const result = await verifyCertificate(input);

  // Print checks
  for (const check of result.checks) {
    const color = statusColor(check.status);
    const icon = statusIcon(check.status);
    console.log(`  ${color}${icon}${RESET} ${BOLD}${check.id}. ${check.name}${RESET} ${DIM}(${check.durationMs.toFixed(1)}ms)${RESET}`);
    console.log(`    ${DIM}${check.description}${RESET}`);
    if (check.status === "fail" || check.status === "warn") {
      const lines = check.detail.split("\n");
      for (const line of lines) {
        console.log(`    ${color}${line}${RESET}`);
      }
    }
    console.log();
  }

  // Print verdict
  console.log(`${DIM}─────────────────────────────────────────${RESET}`);
  const verdictColor = result.verdict === "VERIFIED" ? GREEN : result.verdict === "FAILED" ? RED : YELLOW;
  console.log(`\n  ${verdictColor}${BOLD}${result.verdict}${RESET} ${DIM}(${result.totalDurationMs.toFixed(0)}ms total)${RESET}`);

  if (result.cert) {
    console.log(`  ${DIM}cert_id: ${result.cert.cert_id}${RESET}`);
    console.log(`  ${DIM}issuer:  ${result.cert.issuer?.id || "unknown"}${RESET}`);
  }

  const passCount = result.checks.filter(c => c.status === "pass").length;
  const failCount = result.checks.filter(c => c.status === "fail").length;
  const warnCount = result.checks.filter(c => c.status === "warn").length;
  console.log(`  ${DIM}${passCount} passed, ${failCount} failed, ${warnCount} warnings${RESET}\n`);

  // Exit code: 0 = verified, 1 = failed, 2 = verified with notes
  if (result.verdict === "FAILED") process.exit(1);
  if (result.verdict === "VERIFIED_WITH_NOTES") process.exit(2);
  process.exit(0);
}

main().catch((e) => {
  console.error(`${RED}Fatal:${RESET} ${e.message}`);
  process.exit(1);
});
