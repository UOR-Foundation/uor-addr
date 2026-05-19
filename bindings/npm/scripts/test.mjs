// Smoke test for the transpiled npm package. Mints κ-labels for one
// input per realization and asserts each is a well-formed 71-byte
// ASCII sha256:<64hex>.
//
// The reference byte-for-byte κ-labels are pinned by the Rust
// cross-realization test suite (tests/all_realizations.rs); this test
// only confirms the npm package wires up to the same wasm component
// and the format-specific entry points are reachable.

import { existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const distEntry = resolve(__dirname, "..", "dist", "uor-addr.js");

if (!existsSync(distEntry)) {
  console.error("error: dist/ not built. run `npm run build` first.");
  process.exit(1);
}

const mod = await import(distEntry);
const kappa = mod.kappa ?? mod["uor:addr/kappa"] ?? mod;

const cases = [
  ["jsonAddress",     new TextEncoder().encode('{"foo":"bar"}')],
  ["sexpAddress",     new TextEncoder().encode("(a b c)")],
  ["xmlAddress",      new TextEncoder().encode("<root/>")],
  ["ringAddress",     new Uint8Array([0, 0x42])],
];

const KAPPA_LABEL_RE = /^sha256:[0-9a-f]{64}$/;
let failed = 0;

for (const [fnName, input] of cases) {
  const fn = kappa[fnName];
  if (typeof fn !== "function") {
    console.error(`fail: ${fnName} is not a function`);
    failed += 1;
    continue;
  }
  let result;
  try {
    result = fn(input);
  } catch (e) {
    console.error(`fail: ${fnName} threw: ${e.message}`);
    failed += 1;
    continue;
  }
  if (typeof result !== "string" || result.length !== 71 || !KAPPA_LABEL_RE.test(result)) {
    console.error(`fail: ${fnName} returned ${JSON.stringify(result)} (not a 71-byte sha256:<64hex>)`);
    failed += 1;
    continue;
  }
  console.log(`ok:   ${fnName} → ${result}`);
}

if (failed > 0) {
  console.error(`\n${failed} failure(s)`);
  process.exit(1);
}

console.log(`\nall ${cases.length} smoke tests passed`);
