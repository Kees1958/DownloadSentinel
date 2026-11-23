#!/usr/bin/env node
"use strict";

// tools/update-lists.mjs
//
// Regenerates data/HostList.json — the merged, deduplicated
// host-risk list described in the v2.7.0 heuristics plan (Step 1). This is a
// dev-time/build-time tool (lives under tools/, not shipped in the CWS
// package); the JSON it writes is data/HostList.json, the single
// source of truth util/HostList.js's compiled-in default is generated from
// (see tools/gen-data-defaults.mjs, which this script runs automatically at
// the end — so a plain `node tools/update-lists.mjs` regenerates both the
// JSON and util/HostList.default.js in one step). Nothing is fetched by the
// EXTENSION itself at CWS-review time from this script — this JSON is
// compiled into the bundled default and is the only copy the extension
// ever loads at runtime (v3.3.0, 3P Matrix alignment item 18, removed the
// runtime remote-fetch mechanism this script's output used to also feed).
//
// Sources merged (see tools/lists-raw/ for the cached raw snapshots this
// script reads by default):
//   1. HaGeZi "DynDNS"        — dynamic-DNS providers abused for phishing
//   2. HaGeZi "Badware Hoster" — free/hosting platforms with repeat abuse
//   3. Kees1958 "Suspicious websites" — free-hosting/script-hosting domains
//      (AdBlockPlus-format third-party-script-blocking rules; different
//      semantics from the other two — see KEES_SCORE below)
//
// Usage:
//   node tools/update-lists.mjs            — regenerate from cached raw files
//   node tools/update-lists.mjs --fetch    — re-download raw files first,
//                                             then regenerate
//
// An entry already present in data/SuspiciousDomains.json (exact or
// registered-domain match, via util/SuspiciousDomains.js's own lookup()) or
// data/RiskyHostingSites.json (respecting each entry's own
// exact/suffix match mode, via util/RiskyHostingSites.js's own lookup()) is
// EXCLUDED from the generated file — those modules already score it, usually
// with more nuance, and the plan's own ground rule is "existing entries win
// on overlap (no double counting)".

import { writeFileSync, readFileSync, mkdirSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";

import { repoPaths } from "./repoPaths.mjs";
import { recordBuiltFrom } from "./source-snapshots.mjs";   // v3.5.5 — which raw snapshot each list was built from
import { SuspiciousDomains } from "../util/SuspiciousDomains.js";
import { RiskyHostingSites } from "../util/RiskyHostingSites.js";

const { TOOLS_ROOT, REPO_ROOT, EXT_ROOT } = repoPaths(import.meta.url);
const RAW_DIR    = path.join(TOOLS_ROOT, "lists-raw");
const OUT_FILE   = path.join(EXT_ROOT, "data", "HostList.json");
const GEN_DEFAULTS_SCRIPT = path.join(TOOLS_ROOT, "gen-data-defaults.mjs");

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG — source URLs, per-list base risk scores, and output path.
// Per-list scores are 0-100 "risk value" entries, same convention as
// util/SuspiciousDomains.js's TABLE — NOT yet run through any combination
// logic (that's Step 3 / v2.9.0). A single hit from one of these lists alone
// should land in the "moderate" range, not "malicious" — see the heuristics
// plan, Step 1.
// ─────────────────────────────────────────────────────────────────────────────
const SOURCES = Object.freeze({
    HAGEZI_DYNDNS: {
        url:        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns-onlydomains.txt",
        rawFile:    "hagezi-dyndns.txt",
        tag:        "HaGeZi-DynDNS",
        score:      60,   // dynamic-DNS abuse — mid-range per plan ("~50-70 for dyndns/hoster")
    },
    HAGEZI_HOSTER: {
        url:        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/hoster-onlydomains.txt",
        rawFile:    "hagezi-hoster.txt",
        tag:        "HaGeZi-Hoster",
        score:      65,   // free/abused hosting providers — mid-range per plan
    },
    KEES_SUSPICIOUS: {
        url:        "https://raw.githubusercontent.com/Kees1958/W3C_annual_most_used_survey_blocklist/refs/heads/master/Suspicious%20websites.txt",
        rawFile:    "kees-suspicious.txt",
        tag:        "Kees-Suspicious",
        // Lower weight than the two HaGeZi lists: this list's own semantics
        // are "block third-party script/iframe loads from this domain", not
        // "this domain itself is malicious" — closer to "hosted on a free
        // platform" (per the heuristics plan's Step 1 note), hence the lower
        // end of the plan's suggested "~40-60 for Kees" range.
        score:      50,
    },
});

// ── CLI flag ──────────────────────────────────────────────────────────────
const SHOULD_FETCH = process.argv.includes("--fetch");

// ─────────────────────────────────────────────────────────────────────────────
// Guards — ensure the raw-list cache directory exists before any read/write.
// ─────────────────────────────────────────────────────────────────────────────
function ensureRawDir() {
    if (!existsSync(RAW_DIR)) mkdirSync(RAW_DIR, { recursive: true });
}

async function fetchRawLists() {
    ensureRawDir();
    for (const source of Object.values(SOURCES)) {
        const dest = path.join(RAW_DIR, source.rawFile);
        console.log(`  fetching ${source.tag} …`);
        const response = await fetch(source.url);
        if (!response.ok) {
            throw new Error(`${source.tag}: fetch failed (HTTP ${response.status}) from ${source.url}`);
        }
        const text = await response.text();
        // Guard (C13a) — a bad fetch (CDN error page, empty body) must never
        // silently compile into the generated list.
        if (text.length < 500) {
            throw new Error(`${source.tag}: response implausibly small (${text.length} bytes) — refusing to use it`);
        }
        writeFileSync(dest, text, "utf8");
    }
}

function readRaw(source) {
    const file = path.join(RAW_DIR, source.rawFile);
    if (!existsSync(file)) {
        throw new Error(`${source.tag}: no cached raw file at ${file} — run with --fetch first`);
    }
    const text = readFileSync(file, "utf8");
    if (text.length < 500) {
        throw new Error(`${source.tag}: cached raw file implausibly small (${text.length} bytes)`);
    }
    return text;
}

// ─────────────────────────────────────────────────────────────────────────────
// Parsers — one per raw format. Each returns a plain array of lowercase,
// de-whitespaced domain strings (duplicates within a single list allowed;
// deduplication across all three happens in buildMergedList()).
// ─────────────────────────────────────────────────────────────────────────────

// HaGeZi "onlydomains" format: one bare domain per line, "#"-prefixed comments.
function parseHageziOnlyDomains(text) {
    const domains = [];
    for (const rawLine of text.split("\n")) {
        const line = rawLine.trim();
        if (!line || line.startsWith("#")) continue;
        domains.push(line.toLowerCase());
    }
    return domains;
}

// Kees "Suspicious websites.txt" AdBlockPlus format:
//   ||<domain>^$script,subdocument,websocket,third-party
// Comment lines start with "!"; a header line is "[AdBlockPlus 3.0]"; one
// known regex-based rule (not a plain domain) is present and intentionally
// skipped — it doesn't fit this generated list's domain-only Set shape and
// carries no incremental information the plain-domain rules above it don't
// already cover for this list's purpose.
const KEES_RULE_RE = /^\|\|([a-z0-9.-]+)\^\$script,subdocument,websocket,third-party$/i;
function parseKeesSuspicious(text) {
    const domains = [];
    let skippedNonDomain = 0;
    for (const rawLine of text.split("\n")) {
        const line = rawLine.trim();
        if (!line || line.startsWith("!") || line.startsWith("[")) continue;
        const m = KEES_RULE_RE.exec(line);
        if (m) { domains.push(m[1].toLowerCase()); continue; }
        skippedNonDomain++;
    }
    if (skippedNonDomain > 0) {
        console.log(`  (Kees-Suspicious: skipped ${skippedNonDomain} non-plain-domain rule line(s))`);
    }
    return domains;
}

// ─────────────────────────────────────────────────────────────────────────────
// Overlap check against existing hand-curated modules — "existing entries
// win on overlap (no double counting)" (heuristics plan, Step 1).
// ─────────────────────────────────────────────────────────────────────────────
function registeredDomainOf(hostname) {
    const parts = hostname.split(".");
    return parts.length < 2 ? null : parts.slice(-2).join(".");
}

function isAlreadyCoveredBySuspiciousDomains(domain) {
    // SuspiciousDomains.lookup() itself checks full-hostname then
    // registered-domain, which is exactly the overlap we want to detect here.
    return SuspiciousDomains.lookup(domain) !== null;
}

function isAlreadyCoveredByRiskyHosting(domain) {
    return RiskyHostingSites.lookup(domain) !== null;
}

function isAlreadyCovered(domain) {
    return isAlreadyCoveredBySuspiciousDomains(domain) || isAlreadyCoveredByRiskyHosting(domain);
}

// ─────────────────────────────────────────────────────────────────────────────
// Merge — union across all three lists, worst (highest) score wins on a
// cross-list collision, source tags combined so each entry documents every
// list it actually appeared in.
// ─────────────────────────────────────────────────────────────────────────────
function buildMergedList(listResults) {
    // listResults: [{ sourceKey, domains: string[] }, ...]
    const merged = new Map(); // domain -> { score, sources: Set<string> }
    const stats  = {};        // sourceKey -> { total, new, alreadyCovered }

    for (const { sourceKey, domains } of listResults) {
        const source = SOURCES[sourceKey];
        let newCount = 0;
        let coveredCount = 0;

        for (const domain of domains) {
            if (isAlreadyCovered(domain)) { coveredCount++; continue; }

            newCount++;
            const existing = merged.get(domain);
            if (!existing) {
                merged.set(domain, { score: source.score, sources: new Set([source.tag]) });
            } else {
                existing.sources.add(source.tag);
                existing.score = Math.max(existing.score, source.score);
            }
        }

        stats[sourceKey] = { total: domains.length, new: newCount, alreadyCovered: coveredCount };
    }

    return { merged, stats };
}

// ─────────────────────────────────────────────────────────────────────────────
// Data generation — data/HostList.json. The lookup LOGIC that
// consumes this shape lives in util/HostList.js (hand-maintained, not
// generated) — this script's only job is the pure data.
// ─────────────────────────────────────────────────────────────────────────────
function buildHostListData(merged) {
    const entries = [...merged.entries()].sort(([a], [b]) => a.localeCompare(b));
    const data = {};
    for (const [domain, { score, sources }] of entries) {
        data[domain] = { score, source: [...sources].sort().join("+") };
    }
    return data;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────
async function main() {
    console.log("── tools/update-lists.mjs ──");

    if (SHOULD_FETCH) {
        console.log("Fetching raw lists …");
        await fetchRawLists();
    }

    console.log("Reading cached raw lists …");
    const dyndnsText = readRaw(SOURCES.HAGEZI_DYNDNS);
    const hosterText = readRaw(SOURCES.HAGEZI_HOSTER);
    const keesText   = readRaw(SOURCES.KEES_SUSPICIOUS);

    const dyndnsDomains = parseHageziOnlyDomains(dyndnsText);
    const hosterDomains = parseHageziOnlyDomains(hosterText);
    const keesDomains   = parseKeesSuspicious(keesText);

    // Guard (C13a) — verify parsed content structurally resembles what we
    // expect before compiling it into the extension. A near-empty parse
    // result from a format change upstream must fail loudly, not silently
    // ship a near-empty list.
    for (const [name, domains] of [["HaGeZi-DynDNS", dyndnsDomains], ["HaGeZi-Hoster", hosterDomains], ["Kees-Suspicious", keesDomains]]) {
        if (domains.length < 50) {
            throw new Error(`${name}: parsed only ${domains.length} domains — expected hundreds+. Refusing to generate (format may have changed upstream).`);
        }
    }

    console.log("Checking overlap against SuspiciousDomains.js / RiskyHostingSites.js …");
    const { merged, stats } = buildMergedList([
        { sourceKey: "HAGEZI_DYNDNS",    domains: dyndnsDomains },
        { sourceKey: "HAGEZI_HOSTER",    domains: hosterDomains },
        { sourceKey: "KEES_SUSPICIOUS",  domains: keesDomains },
    ]);

    console.log("\nResults:");
    for (const [key, s] of Object.entries(stats)) {
        console.log(`  ${SOURCES[key].tag.padEnd(16)} ${s.total} total  →  ${s.alreadyCovered} already covered  →  ${s.new} new`);
    }
    console.log(`  UNION (deduplicated, net new)   ${merged.size}`);

    const data = buildHostListData(merged);
    writeFileSync(OUT_FILE, JSON.stringify(data, null, 2) + "\n", "utf8");
    recordBuiltFrom("data/HostList.json");
    console.log(`\nWrote ${path.relative(REPO_ROOT, OUT_FILE)} (${merged.size} entries).`);

    // Keep util/HostList.default.js (the compiled-in fallback) in sync with
    // the JSON this just wrote — same as every other extracted data module.
    console.log("\nRegenerating compiled-in defaults (tools/gen-data-defaults.mjs) …");
    execFileSync(process.execPath, [GEN_DEFAULTS_SCRIPT], { stdio: "inherit" });
}

main().catch(err => {
    console.error(`\n✗ update-lists failed: ${err.message}`);
    process.exit(1);
});
