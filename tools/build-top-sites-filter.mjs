#!/usr/bin/env node
"use strict";

// tools/build-top-sites-filter.mjs
//
// Regenerates data/TopSitesFilter.json — a compact Bloom filter
// answering "is this registrable domain one of the web's most popular
// sites?" Built from the Chrome UX Report (CrUX) top-1,000,000-site list
// (real Chrome user-traffic data, mirrored as CSV on GitHub by
// zakird/crux-top-lists), reduced to registrable domains (name.tld) via the
// same real Public Suffix List this codebase now uses elsewhere
// (util/PublicSuffixList.js) — not the old naive "last two labels" rule,
// which would have silently merged every multi-label-TLD site (co.uk,
// com.br, co.jp, ...) into the wrong bucket.
//
// This is the data half of the lookalike-domain check: a download URL whose
// host is a character-substitution away from a real top-1M name (see
// protection/FilenameUrlHeuristics.js's checkLookalikeTopSite) is
// a much stronger signal than an arbitrary hostname being "close" to
// nothing in particular.
//
// Why a Bloom filter and not a plain list: ~850K-950K unique registrable
// domains as raw strings would cost ~15-20MB; a Bloom filter at a 1%
// false-positive rate costs roughly 1-1.5MB (see CONFIG.FALSE_POSITIVE_RATE
// below) and NEVER false-negatives — if it says "not a top site", that is
// certain, which is exactly the property this check's design needs (it
// only ever treats a match as a signal to STRENGTHEN, never to clear, a
// suspicious URL — see the scoring note in FilenameUrlHeuristics.js).
//
// tools/ ↔ extension split (project convention — see update-lists.mjs,
// update-psl.mjs): this build-time script directly imports the extension
// runtime's own util/BloomFilter.js and util/PublicSuffixList.js modules
// (plain ES modules, no bundler needed under Node), so the exact same
// hashing code and suffix rules that built the filter are the ones that
// later query it — no risk of a hand-kept-in-sync second implementation
// drifting out of step.
//
// Usage:
//   node tools/build-top-sites-filter.mjs            — build from the cached raw CSV
//   node tools/build-top-sites-filter.mjs --fetch    — re-download the raw CSV.gz first

import { writeFileSync, readFileSync, mkdirSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { gunzipSync } from "node:zlib";
import path from "node:path";

import { repoPaths } from "./repoPaths.mjs";
import { recordBuiltFrom } from "./source-snapshots.mjs";   // v3.5.5 — which raw snapshot each list was built from
import { BloomFilter } from "../util/BloomFilter.js";
import { PublicSuffixList } from "../util/PublicSuffixList.js";

const { TOOLS_ROOT, EXT_ROOT } = repoPaths(import.meta.url);
// v3.5.5: Brands and GovSuffixes are read from their single source of truth (data/*.json) — the generated
// .default.js modules hold a precompiled JSON string since then (3P Matrix 4.5.4 format), not an importable array.
const readDataJson = (name) => JSON.parse(readFileSync(path.join(EXT_ROOT, "data", `${name}.json`), "utf8"));
const BrandsDefault      = readDataJson("Brands");
const GovSuffixesDefault = readDataJson("GovSuffixes");

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG — every magic number/path for this script gathered here, same
// project convention as tools/update-psl.mjs / tools/update-lists.mjs.
// ─────────────────────────────────────────────────────────────────────────────
const CONFIG = Object.freeze({
    SOURCE_URL: "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz",
    RAW_FILE_GZ: path.join(TOOLS_ROOT, "lists-raw", "crux-top-sites.csv.gz"),
    OUT_FILE: path.join(EXT_ROOT, "data", "TopSitesFilter.json"),
    GEN_DEFAULTS_SCRIPT: path.join(TOOLS_ROOT, "gen-data-defaults.mjs"),

    // The real CrUX export is ~1,000,000 rows / ~8-9MB gzipped; a response
    // far smaller than this means a CDN error page or truncated transfer,
    // not the real list — refuse to build from it (mirrors
    // update-psl.mjs's MIN_PLAUSIBLE_BYTES guard).
    MIN_PLAUSIBLE_GZ_BYTES: 1_000_000,

    // v3.2.0 (3P Matrix alignment §3): only the top 100,000 CrUX-ranked
    // sites are kept — not the full top-1M — unioned with every Brands.json
    // website and GovSuffixes.json suffix (together ~80,000 domains, down
    // from ~900,000, for a ~125KB filter instead of ~1.2MB). The CSV's rows
    // are already rank-ordered (CrUX ships them that way), so "first N data
    // rows" is "top N by rank" with no extra sort needed.
    RANK_CUTOFF: 100_000,

    // Lowered from the old full-list floor (100,000) to match the new,
    // much smaller target size — still high enough to catch a truncated/
    // malformed CSV (a real cut-to-100k build yields ~75-80K uniques after
    // dedup; anything drastically below that means something went wrong
    // upstream of the cutoff itself, e.g. a near-empty CSV).
    MIN_PLAUSIBLE_DOMAINS: 50_000,

    // Target false-positive rate for the built filter. 1% (not the
    // BloomFilter module's own stricter 0.1% default) is a deliberate
    // trade-off for THIS filter specifically — a 1% false positive here
    // only ever means "treat this as if it coincidentally resembled a
    // popular site", which this check already scores as a weak,
    // non-blocking signal (see protection/LookalikeDomainCheck.js) — so the
    // smaller, cheaper-to-ship filter is the better trade for this use case.
    FALSE_POSITIVE_RATE: 0.01,
});

const SHOULD_FETCH = process.argv.includes("--fetch");

// ── Guard — ensure the raw-list cache directory exists before any write ────
function ensureRawDir() {
    const dir = path.dirname(CONFIG.RAW_FILE_GZ);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

async function fetchRaw() {
    ensureRawDir();
    console.log("  fetching CrUX top-1M site list …");
    const response = await fetch(CONFIG.SOURCE_URL);
    if (!response.ok) {
        throw new Error(`fetch failed (HTTP ${response.status}) from ${CONFIG.SOURCE_URL}`);
    }
    const buf = Buffer.from(await response.arrayBuffer());
    if (buf.length < CONFIG.MIN_PLAUSIBLE_GZ_BYTES) {
        throw new Error(`response implausibly small (${buf.length} bytes) — refusing to use it`);
    }
    writeFileSync(CONFIG.RAW_FILE_GZ, buf);
}

function readRawCsv() {
    if (!existsSync(CONFIG.RAW_FILE_GZ)) {
        throw new Error(`no cached raw file at ${CONFIG.RAW_FILE_GZ} — run with --fetch first`);
    }
    const gz = readFileSync(CONFIG.RAW_FILE_GZ);
    if (gz.length < CONFIG.MIN_PLAUSIBLE_GZ_BYTES) {
        throw new Error(`cached raw file implausibly small (${gz.length} bytes)`);
    }
    return gunzipSync(gz).toString("utf8");
}

// ── Parse "origin,rank" CSV rows into a deduped Set of registrable domains ──
// e.g. "https://www.amazon.co.jp,1000" -> "amazon.co.jp". Uses the real
// Public Suffix List (not a fixed label count) so multi-label-TLD sites
// collapse to their correct registrable name rather than a shared,
// incorrect "co.jp"/"co.uk" bucket.
//
// v3.2.0 (3P Matrix alignment §3): stops after CONFIG.RANK_CUTOFF DATA rows
// (the CSV is already rank-ordered) rather than reading the whole ~1M-row
// file — this is what shrinks the filter from ~900K to ~80K domains.
function extractRegisteredDomains(csvText) {
    const domains = new Set();
    const lines = csvText.split("\n");
    let rowsRead = 0;

    for (let i = 1; i < lines.length && rowsRead < CONFIG.RANK_CUTOFF; i++) { // i=1: skip "origin,rank" header
        const line = lines[i].trim();
        if (!line) continue;
        rowsRead++;

        const commaIndex = line.lastIndexOf(",");
        if (commaIndex < 0) continue; // malformed row — skip rather than throw
        const originStr = line.slice(0, commaIndex);

        let hostname;
        try {
            hostname = new URL(originStr).hostname.toLowerCase();
        } catch {
            continue; // unparseable origin — skip
        }

        const registered = PublicSuffixList.getRegisteredDomain(hostname);
        if (registered) domains.add(registered);
    }

    return domains;
}

// ── Union every Brands.json website and GovSuffixes.json suffix into the
// domain set (v3.2.0, §3) — 76 of the 594 brand websites (smaller banks/
// post services) fall below the top-100k cutoff on their own, and the
// shared gov suffixes (gov.uk, gob.mx, ...) never appear in CrUX at all
// (CrUX ranks actual visited origins, not bare registration suffixes) but
// must still read as "a real, popular site" to LookalikeDomainCheck's
// test 1 — see GovSuffixes.js's header.
function addBrandAndGovDomains(domains) {
    let added = 0;
    for (const brand of BrandsDefault) {
        for (const d of brand.domains) {
            if (!domains.has(d)) { domains.add(d); added++; }
        }
    }
    for (const suffix of GovSuffixesDefault) {
        if (!domains.has(suffix)) { domains.add(suffix); added++; }
    }
    return added;
}

// ── Main ─────────────────────────────────────────────────────────────────
async function main() {
    if (SHOULD_FETCH) await fetchRaw();
    const csvText = readRawCsv();
    const domains = extractRegisteredDomains(csvText);
    const crUXCount = domains.size;
    const brandAndGovAdded = addBrandAndGovDomains(domains);

    // Guard (same spirit as update-psl.mjs/update-lists.mjs) — refuse to
    // compile an implausibly small result into the extension rather than
    // silently shipping a near-empty filter. Checked against the CrUX-only
    // count, before the brand/gov union — the union is a small, fixed-size
    // addition (~600 entries) and would mask a genuinely broken CSV parse.
    if (crUXCount < CONFIG.MIN_PLAUSIBLE_DOMAINS) {
        throw new Error(`parsed implausibly few unique domains (${crUXCount}) — refusing to write output`);
    }
    console.log(`  top-${CONFIG.RANK_CUTOFF} CrUX: ${crUXCount} unique registrable domains, ` +
                `+${brandAndGovAdded} brand/gov domains not already in that set`);

    const { size, numHashes } = BloomFilter.sizeFor(domains.size, CONFIG.FALSE_POSITIVE_RATE);
    const filter = BloomFilter.create(size, numHashes);
    for (const domain of domains) filter.add(domain);

    const data = {
        size,
        numHashes,
        entryCount: domains.size,
        falsePositiveRate: CONFIG.FALSE_POSITIVE_RATE,
        bitsBase64: filter.toBase64(),
    };

    writeFileSync(CONFIG.OUT_FILE, JSON.stringify(data) + "\n", "utf8");
    recordBuiltFrom("data/TopSitesFilter.json");
    console.log(`  TopSitesFilter.json written: ${domains.size} unique domains, ` +
                `${size} bits, ${numHashes} hashes, ${Math.round(data.bitsBase64.length / 1024)}KB base64`);

    execFileSync(process.execPath, [CONFIG.GEN_DEFAULTS_SCRIPT], { stdio: "inherit" });
}

main().catch((err) => {
    console.error(`build-top-sites-filter.mjs failed: ${err.message}`);
    process.exit(1);
});
