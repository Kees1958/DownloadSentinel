#!/usr/bin/env node
"use strict";

// tools/gen-data-defaults.mjs
//
// Regenerates each extracted data module's compiled-in default
// (util/<Name>.default.js) from its single source of truth,
// data/<Name>.json.
//
// Why a generated *.default.js companion instead of importing the JSON
// directly: this is a vanilla, unbundled MV3 extension with no build step,
// and Node's own JSON-import syntax (import assertions / import attributes)
// has shifted across versions and isn't something the rest of this codebase
// relies on anywhere. Inlining the already-validated JSON as a plain JS
// object/array literal in a generated module keeps every consumer on the
// exact same `import { X } from "./X.js"` shape it already uses — no
// import-assertion/bundler complexity, and the file is still 100% derived
// from data/<Name>.json (hand-editing it is pointless; the next run of this
// script overwrites it).
//
// Usage:
//   node tools/gen-data-defaults.mjs
//
// Run this after hand-editing any data/<Name>.json (e.g. adding a
// brand domain or a shortener), and after `tools/update-lists.mjs` rewrites
// data/HostList.json.

import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

import { repoPaths } from "./repoPaths.mjs";

const { EXT_ROOT } = repoPaths(import.meta.url);
const DATA_DIR   = path.join(EXT_ROOT, "data");
const UTIL_DIR   = path.join(EXT_ROOT, "util");

// Every data-extracted module, in one place. Each entry's `name` must match
// both data/<name>.json and the exported `<name>Default` identifier that
// util/<name>.js imports from util/<name>.default.js.
// Export name suffix of every generated module (v3.5.5 — was "Default", an object literal).
const EXPORT_SUFFIX = "DefaultJson";

const MODULES = [
    "SuspiciousDomains",
    "SuspiciousTlds",
    "RiskyHostingSites",
    "HostList",
    "UrlShorteners",
    "PublicSuffixList",
    "TopSitesFilter",
    "Brands",
    "GovSuffixes", // used both at build time (tools/build-top-sites-filter.mjs) and, since v3.3.0 (item 17), at runtime via util/GovSuffixes.js (protection/LookalikeDomainCheck.js's gov-suffix exemption); see GovSuffixes.json's provenance note in gen-brands-data.mjs
    "PlatformSuffixes", // v3.3.0 (3P Matrix alignment item 1) — util/DomainAge.js
    "RdapCctlds",       // v3.3.0 (3P Matrix alignment item 1) — util/DomainAge.js
];

// Most modules' JSON is a plain array or a flat object — entry count is
// just its length/key-count (see the loop below). PublicSuffixList.json is
// the one exception: {rules, wildcardRules, exceptions}, three arrays under
// named keys. Declared here, in one place, rather than special-cased
// inline, so a future module with its own non-flat shape has an obvious
// spot to extend this.
const CUSTOM_COUNTERS = Object.freeze({
    PublicSuffixList: (parsed) =>
        `${parsed.rules.length} rules, ${parsed.wildcardRules.length} wildcard, ${parsed.exceptions.length} exceptions`,
    // TopSitesFilter.json is a serialized Bloom filter: {size, numHashes,
    // entryCount, falsePositiveRate, bitsBase64} — not a flat array/object,
    // so its "count" is the domain count the filter was built from, not a
    // key/array length (that would just report "5", the field count).
    TopSitesFilter: (parsed) =>
        `${parsed.entryCount} domains, ${parsed.size} bits, ${parsed.numHashes} hashes`,
});

for (const name of MODULES) {
    const jsonPath = path.join(DATA_DIR, `${name}.json`);
    const outPath  = path.join(UTIL_DIR, `${name}.default.js`);

    const raw = readFileSync(jsonPath, "utf8");
    const parsed = JSON.parse(raw); // validate it's real JSON before trusting it as a literal

    // v3.5.5 (3P Matrix 4.5.4 parity, perf P4): ONE JSON string literal, parsed by util/<name>.js on its first
    // lookup (util/LazyJson.js). A string costs almost nothing when the service worker evaluates its static
    // imports at every start; an object literal is built in full each time. Same format as 3P Matrix.
    const literal = JSON.stringify(JSON.stringify(parsed));

    const out = `"use strict";

/**
 * ${name}.default.js — GENERATED FILE. Do not hand-edit; run
 * \`node tools/gen-data-defaults.mjs\` to regenerate from the single source
 * of truth, data/${name}.json.
 *
 * This is the bundled/offline default: compiled into the reviewed CWS
 * package, so ${name} always has a safe starting value from first install
 * onward. v3.3.0 (3P Matrix alignment item 18) — this is the ONLY source
 * ${name} is ever loaded from; the remote-refresh mechanism that used to
 * sit in front of it (util/FilterDataLoader.js) was removed, so there is
 * no fetch/cache fallback chain to describe here anymore — just this file.
 *
 * Precompiled format (v3.5.5, = 3P Matrix 4.5.4): the data is ONE JSON string, parsed by
 * util/${name}.js on its first lookup (util/LazyJson.js) — never at service-worker start.
 *
 * Generated: ${new Date().toISOString()}
 */
export const ${name}${EXPORT_SUFFIX} = ${literal};
`;
    writeFileSync(outPath, out);
    const count = CUSTOM_COUNTERS[name]
        ? CUSTOM_COUNTERS[name](parsed)
        : `${Array.isArray(parsed) ? parsed.length : Object.keys(parsed).length} entries`;
    console.log(`  ${name}.default.js  ←  data/${name}.json  (${count})`);
}

console.log("\nAll data defaults regenerated.");
