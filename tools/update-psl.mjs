#!/usr/bin/env node
"use strict";

// tools/update-psl.mjs
//
// Regenerates data/PublicSuffixList.json — the real, authoritative
// list every browser uses internally to know where a hostname's registrable
// name ends and its public suffix (TLD, or ccTLD + category like "co.uk")
// begins. Replaces the naive "always take the last two labels" rule that
// UrlUtils.getRegisteredDomain() used before this, which was silently wrong
// for every multi-label suffix (co.uk, com.br, co.jp, ...) — see
// CHANGELOG.md for the investigation and measured error rate that led
// to this.
//
// Dev-time/build-time tool only (lives under tools/, not shipped in the CWS
// package) — same convention as tools/update-lists.mjs. The JSON it writes,
// data/PublicSuffixList.json, is the single source of truth
// util/PublicSuffixList.default.js's compiled-in default is generated from
// (this script calls tools/gen-data-defaults.mjs automatically at the end).
//
// Source: the official Public Suffix List (publicsuffix.org), mirrored on
// GitHub at publicsuffix/list — the same list Firefox/Chrome/every major
// browser ships internally. ~9,500 plain rules, ~300 wildcard rules, and a
// handful of exceptions; updated by that project as TLDs/registries change.
//
// Usage:
//   node tools/update-psl.mjs            — regenerate from the cached raw file
//   node tools/update-psl.mjs --fetch    — re-download the raw file first,
//                                           then regenerate
//
// Encoding note: the raw file mixes Unicode IDN labels (e.g. "한국") with
// plain ASCII ones, and real browsers always report a hostname's IDN labels
// in their ASCII/punycode form (e.g. "xn--3e0b707e") via the URL API — so
// every label here is run through node:url's domainToASCII before being
// stored, whether it started as Unicode or already-ASCII punycode. Without
// this step, ~460 IDN ccTLD-style rules would silently never match any real
// hostname at all.

import { writeFileSync, readFileSync, mkdirSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { domainToASCII } from "node:url";
import path from "node:path";

import { repoPaths } from "./repoPaths.mjs";
import { recordBuiltFrom } from "./source-snapshots.mjs";   // v3.5.5 — which raw snapshot each list was built from

const { TOOLS_ROOT, EXT_ROOT } = repoPaths(import.meta.url);

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG — source URL, cache/output paths. Every magic path/URL for this
// script gathered here, same project convention as tools/update-lists.mjs.
// ─────────────────────────────────────────────────────────────────────────────
const CONFIG = Object.freeze({
    SOURCE_URL:  "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat",
    RAW_FILE:    path.join(TOOLS_ROOT, "lists-raw", "public_suffix_list.dat"),
    OUT_FILE:    path.join(EXT_ROOT, "data", "PublicSuffixList.json"),
    GEN_DEFAULTS_SCRIPT: path.join(TOOLS_ROOT, "gen-data-defaults.mjs"),
    MIN_PLAUSIBLE_BYTES: 200_000, // the real file is ~330KB+; a CDN error page or empty body isn't
});

const SHOULD_FETCH = process.argv.includes("--fetch");

// ── Guard — ensure the raw-list cache directory exists before any write ────
function ensureRawDir() {
    const dir = path.dirname(CONFIG.RAW_FILE);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

async function fetchRaw() {
    ensureRawDir();
    console.log("  fetching Public Suffix List …");
    const response = await fetch(CONFIG.SOURCE_URL);
    if (!response.ok) {
        throw new Error(`fetch failed (HTTP ${response.status}) from ${CONFIG.SOURCE_URL}`);
    }
    const text = await response.text();
    if (text.length < CONFIG.MIN_PLAUSIBLE_BYTES) {
        throw new Error(`response implausibly small (${text.length} bytes) — refusing to use it`);
    }
    writeFileSync(CONFIG.RAW_FILE, text, "utf8");
}

function readRaw() {
    if (!existsSync(CONFIG.RAW_FILE)) {
        throw new Error(`no cached raw file at ${CONFIG.RAW_FILE} — run with --fetch first`);
    }
    const text = readFileSync(CONFIG.RAW_FILE, "utf8");
    if (text.length < CONFIG.MIN_PLAUSIBLE_BYTES) {
        throw new Error(`cached raw file implausibly small (${text.length} bytes)`);
    }
    return text;
}

// ── Parse the .dat format into three label arrays ──────────────────────────
// Format (one rule per line, "//"-prefixed comments, blank lines ignored):
//   example          — a plain rule: "example" itself is a public suffix
//   *.example        — a wildcard rule: any single label + ".example" is a
//                       public suffix (stored here as just "example")
//   !city.example     — an exception carving an exact name back OUT of a
//                       wildcard rule (stored here as "city.example")
// Every label is run through domainToASCII (see module header) so IDN rules
// match real, punycode-normalised browser hostnames.
function parsePsl(text) {
    const rules = [];
    const wildcardRules = [];
    const exceptions = [];

    for (const rawLine of text.split("\n")) {
        const line = rawLine.trim();
        if (!line || line.startsWith("//")) continue;

        let target = rules;
        let suffix = line;
        if (line.startsWith("!")) {
            target = exceptions;
            suffix = line.slice(1);
        } else if (line.startsWith("*.")) {
            target = wildcardRules;
            suffix = line.slice(2);
        }

        const ascii = domainToASCII(suffix);
        if (!ascii) continue; // malformed label — skip rather than store garbage
        target.push(ascii.toLowerCase());
    }

    return {
        rules:         [...new Set(rules)].sort(),
        wildcardRules: [...new Set(wildcardRules)].sort(),
        exceptions:    [...new Set(exceptions)].sort(),
    };
}

// ── Main ─────────────────────────────────────────────────────────────────
async function main() {
    if (SHOULD_FETCH) await fetchRaw();
    const text = readRaw();
    const data = parsePsl(text);

    // Guard (same spirit as update-lists.mjs's C13a) — a parse that yields
    // implausibly few rules means the source format changed or the fetch
    // returned something unexpected; refuse to compile that into the
    // extension rather than silently shipping a near-empty suffix list.
    if (data.rules.length < 5000) {
        throw new Error(`parsed implausibly few rules (${data.rules.length}) — refusing to write output`);
    }

    writeFileSync(CONFIG.OUT_FILE, JSON.stringify(data, null, 2) + "\n", "utf8");
    recordBuiltFrom("data/PublicSuffixList.json");
    console.log(`  PublicSuffixList.json written: ${data.rules.length} rules, ` +
                `${data.wildcardRules.length} wildcard rules, ${data.exceptions.length} exceptions`);

    execFileSync(process.execPath, [CONFIG.GEN_DEFAULTS_SCRIPT], { stdio: "inherit" });
}

main().catch((err) => {
    console.error(`update-psl.mjs failed: ${err.message}`);
    process.exit(1);
});
