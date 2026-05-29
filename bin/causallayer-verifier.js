#!/usr/bin/env node
/**
 * causallayer-verifier — alias entry point.
 *
 * The historic binary name is `causallayer-verify` (see ./causallayer-verify.js).
 * This file exists so that `npx causallayer-verifier <args>` works as a single
 * command — matching the npm package name and the canonical command line we
 * publish in the README, on the website, and in social posts.
 *
 * It simply re-executes the canonical verifier in-process. No new logic.
 */
"use strict";
require("./causallayer-verify.js");
