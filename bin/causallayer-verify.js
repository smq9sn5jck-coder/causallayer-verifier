#!/usr/bin/env node
/**
 * causallayer-verify — CLI for the causallayer-verifier library.
 *
 * Usage:
 *   causallayer-verify <anchor.json> [--key <public-key.pem>] [--json]
 *
 * If --key is omitted, looks for a sibling `public-key.pem` next to the
 * anchor file (matches the layout of causallayer-anchor-log). If --json
 * is set, the full verification report is printed as JSON instead of the
 * human-readable summary.
 *
 * Schemas supported:
 *   - causallayer.audit-batch.v1   (production)
 *   - schemaVersion 0.1            (legacy / dev-test)
 *
 * Exit codes:
 *   0   anchor verifies (all invariants pass)
 *   1   verification failed
 *   2   invalid usage / bad input
 */
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { verifyAnchor } = require("../lib/index");

function usage() {
  console.error(
    "usage: causallayer-verify <anchor.json> [--key <public-key.pem>] [--json]"
  );
  process.exit(2);
}

function parseArgs(argv) {
  const args = { file: null, key: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--key" || a === "-k") {
      args.key = argv[++i];
    } else if (a === "--json") {
      args.json = true;
    } else if (a === "--help" || a === "-h") {
      usage();
    } else if (!args.file) {
      args.file = a;
    } else {
      usage();
    }
  }
  if (!args.file) usage();
  return args;
}

function findDefaultKey(anchorPath) {
  // Walk up from the anchor file looking for a public-key.pem.
  let dir = path.dirname(anchorPath);
  for (let i = 0; i < 4; i++) {
    const candidate = path.join(dir, "public-key.pem");
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function fmt(ok) {
  return ok ? "OK  " : "FAIL";
}

function main() {
  const { file, key, json } = parseArgs(process.argv.slice(2));
  const anchorPath = path.resolve(file);
  if (!fs.existsSync(anchorPath)) {
    console.error(`error: anchor file not found: ${anchorPath}`);
    process.exit(2);
  }
  let record;
  try {
    record = JSON.parse(fs.readFileSync(anchorPath, "utf8"));
  } catch (e) {
    console.error(`error: anchor file is not valid JSON: ${e.message}`);
    process.exit(2);
  }

  const keyPath = key ? path.resolve(key) : findDefaultKey(anchorPath);
  if (!keyPath || !fs.existsSync(keyPath)) {
    console.error(
      `error: public key not found ${keyPath ? "at " + keyPath : ""}\n` +
        "       pass --key explicitly, or fetch from\n" +
        "       https://github.com/smq9sn5jck-coder/causallayer-anchor-log/blob/main/public-key.pem"
    );
    process.exit(2);
  }
  const pem = fs.readFileSync(keyPath, "utf8");

  let report;
  try {
    report = verifyAnchor(record, pem);
  } catch (e) {
    console.error(`error: ${e.message}`);
    process.exit(2);
  }

  if (json) {
    console.log(JSON.stringify(report, null, 2));
    const ok =
      report.allOk !== undefined
        ? report.allOk
        : report.merkleOk && report.signatureOk;
    process.exit(ok ? 0 : 1);
  }

  console.log(`anchor file  : ${anchorPath}`);
  console.log(`public key   : ${keyPath}`);
  console.log(`schema       : ${report.schema}`);

  if (report.schema === "causallayer.audit-batch.v1") {
    console.log(`leaf count   : ${report.leafCount}`);
    console.log(`body sha256  : ${fmt(report.bodyShaOk)}`);
    if (!report.bodyShaOk) {
      console.log(`               recomputed=${report.recomputedBodySha}`);
      console.log(`               claimed   =${report.claimedBodySha}`);
    }
    console.log(`merkle root  : ${fmt(report.merkleOk)}`);
    if (!report.merkleOk) {
      console.log(`               recomputed=${report.recomputedMerkleRoot}`);
      console.log(`               claimed   =${report.claimedMerkleRoot}`);
    }
    console.log(`pubkey fp    : ${fmt(report.fingerprintOk)}`);
    if (!report.fingerprintOk) {
      console.log(`               recomputed=${report.recomputedFingerprint}`);
      console.log(`               claimed   =${report.claimedFingerprint}`);
    }
    console.log(`ed25519 sig  : ${fmt(report.signatureOk)}  signed_field=${report.signedField}`);
  } else {
    console.log(`anchor date  : ${report.anchorDate ?? "n/a"}`);
    console.log(`leaf count   : ${report.leafCount}`);
    console.log(`merkle root  : ${fmt(report.merkleOk)}`);
    if (!report.merkleOk) {
      console.log(`               recomputed=${report.recomputedRoot}`);
      console.log(`               claimed   =${report.claimedRoot}`);
    }
    if (report.fingerprintOk !== null && report.fingerprintOk !== undefined) {
      console.log(`pubkey fp    : ${fmt(report.fingerprintOk)}`);
    }
    console.log(`ed25519 sig  : ${fmt(report.signatureOk)}`);
  }

  const otsPath = anchorPath + ".ots";
  if (fs.existsSync(otsPath)) {
    console.log(`ots proof    : present  (run: ots verify ${otsPath})`);
  } else {
    console.log("ots proof    : not yet attached (anchor may be < ~3h old)");
  }

  const allOk =
    report.allOk !== undefined
      ? report.allOk
      : report.merkleOk && report.signatureOk;
  process.exit(allOk ? 0 : 1);
}

main();
