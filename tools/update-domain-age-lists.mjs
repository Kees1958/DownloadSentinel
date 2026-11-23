#!/usr/bin/env node
"use strict";

// tools/update-domain-age-lists.mjs
//
// v3.3.0 (3P Matrix alignment items 1 and 19) — regenerates the two small
// lists util/DomainAge.js consults to decide when an RDAP registration-age
// lookup cannot give a real answer (and should be skipped, not attempted
// and scored as a failure):
//
//   data/PlatformSuffixes.json — hosting-platform suffixes
//     (github.io, blogspot.com, ...) where the "registered domain" is
//     really a shared platform anyone can get a subdomain on. Derived from
//     the Public Suffix List's PRIVATE section — this project already
//     fetches and caches the full PSL for util/PublicSuffixList.js (see
//     tools/update-psl.mjs); this script reuses that same cached raw file
//     rather than fetching it a second time.
//
//   data/RdapCctlds.json — two-letter country-code TLDs that
//     actually run an RDAP service, per IANA's own RDAP bootstrap registry
//     (data.iana.org/rdap/dns.json — the same registry a browser's own
//     RDAP client would consult to find a TLD's RDAP server).
//
// Dev-time/build-time tool only (lives under tools/, not shipped in the CWS
// package) — same convention as tools/update-lists.mjs / update-psl.mjs.
// Registered in tools/data-sources.json with updateOn: "minor" — these
// lists change slowly (a new TLD, a newly-adopted RDAP service) and are
// re-fetched once per minor release, not on every build.
//
// Usage:
//   node tools/update-domain-age-lists.mjs            — regenerate from
//                                                        cached raw files
//   node tools/update-domain-age-lists.mjs --fetch    — re-download the
//                                                        IANA RDAP bootstrap
//                                                        registry first
//                                                        (the PSL raw file
//                                                        is shared with
//                                                        update-psl.mjs —
//                                                        run that with
//                                                        --fetch to refresh
//                                                        it instead)

import { writeFileSync, readFileSync, mkdirSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";

import { repoPaths } from "./repoPaths.mjs";
import { recordBuiltFrom } from "./source-snapshots.mjs";   // v3.5.5 — which raw snapshot each list was built from

const { TOOLS_ROOT, EXT_ROOT } = repoPaths(import.meta.url);

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG — every source URL / cache / output path for this script, in one
// place, same project convention as tools/update-psl.mjs.
// ─────────────────────────────────────────────────────────────────────────────
const CONFIG = Object.freeze({
    // Shared with tools/update-psl.mjs — not re-fetched here; refresh it via
    // `node update-psl.mjs --fetch` (in tools/) and re-run this script afterward.
    PSL_RAW_FILE: path.join(TOOLS_ROOT, "lists-raw", "public_suffix_list.dat"),

    RDAP_SOURCE_URL: "https://data.iana.org/rdap/dns.json",
    RDAP_RAW_FILE:   path.join(TOOLS_ROOT, "lists-raw", "iana-rdap-dns.json"),

    OUT_PLATFORM_SUFFIXES: path.join(EXT_ROOT, "data", "PlatformSuffixes.json"),
    OUT_RDAP_CCTLDS:       path.join(EXT_ROOT, "data", "RdapCctlds.json"),

    GEN_DEFAULTS_SCRIPT: path.join(TOOLS_ROOT, "gen-data-defaults.mjs"),

    // Guards against a truncated/malformed source silently producing a
    // near-empty list — same defensive-floor idea as update-psl.mjs's own
    // MIN_PLAUSIBLE_BYTES / rule-count check.
    MIN_PLAUSIBLE_PLATFORM_SUFFIXES: 1000,
    MIN_PLAUSIBLE_RDAP_CCTLDS:       30,

    CCTLD_RE: /^[a-z]{2}$/,
});

const SHOULD_FETCH = process.argv.includes("--fetch");

// ── Guard — ensure the raw-cache directory exists before any write ────────
function ensureRawDir() {
    const dir = path.dirname(CONFIG.RDAP_RAW_FILE);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

async function fetchRdapBootstrap() {
    ensureRawDir();
    console.log("  fetching IANA RDAP bootstrap registry …");
    const response = await fetch(CONFIG.RDAP_SOURCE_URL);
    if (!response.ok) {
        throw new Error(`fetch failed (HTTP ${response.status}) from ${CONFIG.RDAP_SOURCE_URL}`);
    }
    const text = await response.text();
    writeFileSync(CONFIG.RDAP_RAW_FILE, text, "utf8");
}

function readRdapBootstrap() {
    if (!existsSync(CONFIG.RDAP_RAW_FILE)) {
        throw new Error(`no cached raw file at ${CONFIG.RDAP_RAW_FILE} — run with --fetch first`);
    }
    return JSON.parse(readFileSync(CONFIG.RDAP_RAW_FILE, "utf8"));
}

function readPslRaw() {
    if (!existsSync(CONFIG.PSL_RAW_FILE)) {
        throw new Error(`no cached PSL raw file at ${CONFIG.PSL_RAW_FILE} — run ` +
            `\`node tools/update-psl.mjs --fetch\` first`);
    }
    return readFileSync(CONFIG.PSL_RAW_FILE, "utf8");
}

// ── Extract the PRIVATE DOMAINS section's rules from the raw PSL .dat ─────
// Same per-line format update-psl.mjs's parsePsl() already handles (plain
// rule / "*."-wildcard rule / "!"-exception), but this list only ever
// stores plain and wildcard rules verbatim (including the literal "*."
// prefix) — util/DomainAge.js's platformOf() matches against exactly that
// shape. The PSL's private section has never carried an exception rule in
// practice (nothing to carve back OUT of a platform-provider wildcard), so
// one appearing here is treated as a hand-maintained-data surprise worth
// surfacing, not silently dropped.
function parsePrivateSuffixes(pslText) {
    const beginMarker = "// ===BEGIN PRIVATE DOMAINS===";
    const endMarker   = "// ===END PRIVATE DOMAINS===";
    const beginIdx = pslText.indexOf(beginMarker);
    const endIdx   = pslText.indexOf(endMarker);
    if (beginIdx === -1 || endIdx === -1 || endIdx <= beginIdx) {
        throw new Error("could not locate PRIVATE DOMAINS section markers in the PSL raw file — format may have changed");
    }
    const section = pslText.slice(beginIdx + beginMarker.length, endIdx);

    const suffixes = [];
    for (const rawLine of section.split("\n")) {
        const line = rawLine.trim();
        if (!line || line.startsWith("//")) continue;
        if (line.startsWith("!")) {
            throw new Error(`unexpected exception rule "${line}" in PSL PRIVATE DOMAINS section — ` +
                `util/DomainAge.js's platformOf() has no exception handling; review before proceeding`);
        }
        suffixes.push(toAscii(line.toLowerCase()));
    }
    return [...new Set(suffixes)].sort();
}

// v3.5.0 — a rule as the browser's URL API reports host names: punycode
// (xn--…), never Unicode. Before, the 13 internationalized PRIVATE rules
// (e.g. "günstigbestellen.de", "биз.рус") were stored in Unicode and could
// never match a real hostname. A leading "*." wildcard is kept. Same
// conversion as 3P Matrix's update-domain-age-lists.mjs, so both builds of
// the shared list are identical.
const PSL_WILDCARD = "*.";
function toAscii(rule) {
    const wild = rule.startsWith(PSL_WILDCARD);
    const ascii = new URL(`http://${wild ? rule.slice(PSL_WILDCARD.length) : rule}/`).hostname;
    return wild ? PSL_WILDCARD + ascii : ascii;
}

// ── Extract two-letter ccTLDs that have at least one RDAP service listed ──
// dns.json's shape: { services: [ [ [tld, ...], [url, ...] ], ... ] } — a
// TLD counts as "has RDAP" the moment it appears in ANY service entry's
// TLD list, regardless of which URL scheme serves it.
function extractRdapCctlds(bootstrap) {
    if (!Array.isArray(bootstrap?.services)) {
        throw new Error("IANA RDAP bootstrap registry has an unexpected shape — no services array");
    }
    const cctlds = new Set();
    for (const [tlds] of bootstrap.services) {
        for (const tld of tlds || []) {
            const lower = String(tld).toLowerCase();
            if (CONFIG.CCTLD_RE.test(lower)) cctlds.add(lower);
        }
    }
    return [...cctlds].sort();
}

// ── Main ─────────────────────────────────────────────────────────────────
async function main() {
    if (SHOULD_FETCH) await fetchRdapBootstrap();

    const platformSuffixes = parsePrivateSuffixes(readPslRaw());
    if (platformSuffixes.length < CONFIG.MIN_PLAUSIBLE_PLATFORM_SUFFIXES) {
        throw new Error(`parsed implausibly few platform suffixes (${platformSuffixes.length}) — refusing to write output`);
    }
    writeFileSync(CONFIG.OUT_PLATFORM_SUFFIXES, JSON.stringify(platformSuffixes, null, 2) + "\n", "utf8");
    recordBuiltFrom("data/PlatformSuffixes.json");
    console.log(`  PlatformSuffixes.json written: ${platformSuffixes.length} entries`);

    const rdapCctlds = extractRdapCctlds(readRdapBootstrap());
    if (rdapCctlds.length < CONFIG.MIN_PLAUSIBLE_RDAP_CCTLDS) {
        throw new Error(`parsed implausibly few RDAP ccTLDs (${rdapCctlds.length}) — refusing to write output`);
    }
    writeFileSync(CONFIG.OUT_RDAP_CCTLDS, JSON.stringify(rdapCctlds, null, 2) + "\n", "utf8");
    recordBuiltFrom("data/RdapCctlds.json");
    console.log(`  RdapCctlds.json written: ${rdapCctlds.length} entries`);

    execFileSync(process.execPath, [CONFIG.GEN_DEFAULTS_SCRIPT], { stdio: "inherit" });
}

main().catch((err) => {
    console.error(`update-domain-age-lists.mjs failed: ${err.message}`);
    process.exit(1);
});
