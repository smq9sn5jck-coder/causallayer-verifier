#!/usr/bin/env node
/**
 * causallayer-verify — CLI for the causallayer-verifier library.
 *
 * Usage:
 *   causallayer-verify <anchor.json> [--key <public-key.pem>]
 *
 * If --key is omitted, looks for a sibling `public-key.pem` next to the
 * anchor file (matches the layout of causallayer-anchor-log).
 *
 * Exit codes:
 *   0   anchor verifies (Merkle + signature)
 *   1   verification failed
 *   2   invalid usage / bad input
 */
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { verifyAnchor } = require("../lib/index");

function usage() {
  console.error(
    "usage: causallayer-verify <anchor.json> [--key <public-key.pem>]"
  );
  process.exit(2);
}

function parseArgs(argv) {
  const args = { file: null, key: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--key" || a === "-k") {
      args.key = argv[++i];
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

function main() {
  const { file, key } = parseArgs(process.argv.slice(2));
  const anchorPath = path.resolve(file);
  if (!fs.existsSync(anchorPath)) {
    console.error(`error: anchor file not found: ${anchorPath}`);
    process.exit(2);
  }
  const record = JSON.parse(fs.readFileSync(anchorPath, "utf8"));

  const keyPath = key
    ? path.resolve(key)
    : path.resolve(path.dirname(anchorPath), "..", "public-key.pem");
  if (!fs.existsSync(keyPath)) {
    console.error(
      `error: public key not found at ${keyPath}\n` +
        "       pass --key explicitly, or fetch from\n" +
        "       https://faultkey.ai/.well-known/causallayer-cert/public-key.pem"
    );
    process.exit(2);
  }
  const pem = fs.readFileSync(keyPath, "utf8");

  const { merkleOk, signatureOk, recomputedRoot, claimedRoot } = verifyAnchor(
    record,
    pem
  );

  console.log(`anchor file  : ${anchorPath}`);
  console.log(`public key   : ${keyPath}`);
  console.log(`anchor date  : ${record.payload.anchorDate}`);
  console.log(`leaf count   : ${record.payload.leafCount}`);
  console.log(`merkle root  : ${merkleOk ? "OK  " : "FAIL"}`);
  if (!merkleOk) {
    console.log(`               recomputed=${recomputedRoot}`);
    console.log(`               claimed   =${claimedRoot}`);
  }
  console.log(`ed25519 sig  : ${signatureOk ? "OK  " : "FAIL"}  algo=${record.signatureAlgorithm}`);

  const otsPath = anchorPath + ".ots";
  if (fs.existsSync(otsPath)) {
    console.log(`ots proof    : present  (run: ots verify ${otsPath})`);
  } else {
    console.log("ots proof    : not yet attached (anchor may be < ~3h old)");
  }

  process.exit(merkleOk && signatureOk ? 0 : 1);
}

main();
