#!/usr/bin/env node
"use strict";

// tools/check-derived-literals.mjs
//
// v3.2.0 (3P Matrix alignment §6) — process item ported from the 3P Matrix
// audit (Xplainer v10): a header/doc comment that states a PRECISE count
// derived from a data file (e.g. "539 keywords", "80,140 unique domains")
// is a literal that can silently drift out of sync with the data file it
// describes — nobody re-reads every comment when data/<Name>.json changes.
//
// This script checks the one place in this codebase where such counts are
// stated precisely and non-approximately: each extracted data module's own
// wrapper file (util/<Name>.js), comparing any exact "<N> entries/
// keywords/domains/rules/websites" phrase it finds against the live count in
// the corresponding data/<Name>.json (computed the same way
// tools/gen-data-defaults.mjs's own CUSTOM_COUNTERS does, so there is only
// ONE place "how do you count this module's entries" is decided).
//
// Deliberately narrow and advisory, like this project's other check-*.mjs
// scripts: an approximate count ("~540 entries", "~80K domains") is treated
// as intentionally loose and never flagged; only an exact, now-wrong number
// is worth a maintainer's attention. Never fails the build.
//
// Usage:
//   node tools/check-derived-literals.mjs

import { readFileSync, existsSync, readdirSync } from "node:fs";
import path from "node:path";

import { repoPaths } from "./repoPaths.mjs";

const { EXT_ROOT } = repoPaths(import.meta.url);
const DATA_DIR = path.join(EXT_ROOT, "data");
const UTIL_DIR = path.join(EXT_ROOT, "util");

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG — the exact-count phrase pattern and per-module counters, in one
// place. COUNTERS mirrors tools/gen-data-defaults.mjs's CUSTOM_COUNTERS: most
// modules are a flat array/object (length/key-count); the two with a
// non-flat JSON shape get their own counter.
// ─────────────────────────────────────────────────────────────────────────────
const CONFIG = Object.freeze({
    // "123", "1,234" or "12.3K" immediately followed by one of these nouns —
    // the "~"/"approx"/"roughly" prefixes are checked for and excluded
    // separately below, not baked into this pattern.
    COUNT_PHRASE_RE: /(\d[\d,]*)\s*-?\s*(?:entries|entry|keywords?|domains?|rules?|websites?|suffixes?)\b/gi,
    APPROX_PREFIX_RE: /(~|approx(?:imately)?|roughly|about)\s*$/i,
});

const DEFAULT_COUNTER = (parsed) => (Array.isArray(parsed) ? parsed.length : Object.keys(parsed).length);
const COUNTERS = Object.freeze({
    PublicSuffixList: (parsed) => parsed.rules.length,
    TopSitesFilter:   (parsed) => parsed.entryCount,
});

function moduleNames() {
    if (!existsSync(UTIL_DIR)) return [];
    return readdirSync(UTIL_DIR)
        .filter((f) => f.endsWith(".js") && !f.endsWith(".default.js"))
        .map((f) => f.slice(0, -3))
        .filter((name) => existsSync(path.join(DATA_DIR, `${name}.json`)));
}

function liveCount(name) {
    const parsed = JSON.parse(readFileSync(path.join(DATA_DIR, `${name}.json`), "utf8"));
    return (COUNTERS[name] || DEFAULT_COUNTER)(parsed);
}

function checkModule(name) {
    const filePath = path.join(UTIL_DIR, `${name}.js`);
    if (!existsSync(filePath)) return [];
    const text = readFileSync(filePath, "utf8");
    const actual = liveCount(name);

    const findings = [];
    CONFIG.COUNT_PHRASE_RE.lastIndex = 0;
    let m;
    while ((m = CONFIG.COUNT_PHRASE_RE.exec(text))) {
        const before = text.slice(Math.max(0, m.index - 15), m.index);
        if (CONFIG.APPROX_PREFIX_RE.test(before)) continue; // "~540 entries" — intentionally loose, skip

        const stated = Number(m[1].replace(/,/g, ""));
        if (stated !== actual) {
            const lineNo = text.slice(0, m.index).split("\n").length;
            findings.push({ name, lineNo, stated, actual, text: m[0] });
        }
    }
    return findings;
}

function main() {
    const names = moduleNames();
    const allFindings = names.flatMap(checkModule);

    if (allFindings.length === 0) {
        console.log(`Checked ${names.length} data module(s) — every stated exact count matches its data file.`);
        return;
    }

    console.log(`${allFindings.length} stale count(s) found — review by hand:\n`);
    for (const f of allFindings) {
        console.log(`  util/${f.name}.js:${f.lineNo} — says "${f.text}" but data/${f.name}.json currently has ${f.actual}`);
    }
}

main();
