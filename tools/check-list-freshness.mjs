#!/usr/bin/env node
"use strict";

// tools/check-list-freshness.mjs
//
// v3.2.0 (3P Matrix alignment §5) — advisory, non-blocking freshness check
// over tools/data-sources.json, the register of every external data source
// this project's build-time tooling ingests (HaGeZi lists, Kees list, the
// Public Suffix List, CrUX top sites — see that file). For each registered
// source with a cached raw file, this script reports how old that cached
// copy is and flags anything past CONFIG.FRESHNESS_WARN_DAYS as due for a
// re-fetch.
//
// This is advisory only (unlike tools/update-lists.mjs/update-psl.mjs/
// build-top-sites-filter.mjs, which actually refresh the data): it never
// fetches anything itself and always exits 0, so it is safe to run — and to
// wire into tools/complete-check.mjs as a soft/warn-only step — on a normal
// dev machine with no network egress for these third-party hosts.
//
// Usage:
//   node tools/check-list-freshness.mjs

import { readFileSync, existsSync, statSync } from "node:fs";
import path from "node:path";

import { repoPaths } from "./repoPaths.mjs";
import { currentSnapshot } from "./source-snapshots.mjs";

const { TOOLS_ROOT } = repoPaths(import.meta.url);
const REGISTER_FILE = path.join(TOOLS_ROOT, "data-sources.json");

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG — the one staleness threshold this script applies, in one place.
// 180 days: every source in the register is described as "re-fetch per
// release", not on a fixed cadence of its own — six months is a generous
// upper bound past which a release has almost certainly gone stale
// regardless of this project's own release rhythm.
// ─────────────────────────────────────────────────────────────────────────────
const CONFIG = Object.freeze({
    FRESHNESS_WARN_DAYS: 180,
});

const MS_PER_DAY = 24 * 60 * 60 * 1000;
// v3.5.5 — exit codes: OK also covers "stale" (age is advisory); SNAPSHOT_MISMATCH is a hard failure.
const EXIT = Object.freeze({ OK: 0, SNAPSHOT_MISMATCH: 1 });

// v3.5.5 (3P Matrix 4.5.4 parity, `sameSnapshotAs`): a list must be built from the raw file that is cached now.
// builtFromSnapshot is written by the build tool (tools/source-snapshots.mjs recordBuiltFrom); a mismatch means the
// raw file was refreshed but the list was not rebuilt. Two sources sharing one raw file (PSL + its PRIVATE section)
// must both match it — so they cannot come from two different snapshots.
function checkSnapshot(source) {
    const now = currentSnapshot(source);
    if (now === null) return null;                                    // hand-curated or never fetched: covered above
    if (!source.builtFromSnapshot) {
        return `${source.name}: no builtFromSnapshot recorded — run \`node ${source.updateScript}\` (without --fetch) once`;
    }
    if (source.builtFromSnapshot !== now) {
        return `${source.name}: built from ${source.builtFromSnapshot}, but the cached raw file is ${now} — ` +
               `run \`node ${source.updateScript}\` (raw file refreshed, list not rebuilt)`;
    }
    return null;
}

function loadRegister() {
    if (!existsSync(REGISTER_FILE)) {
        throw new Error(`register not found at ${REGISTER_FILE}`);
    }
    const parsed = JSON.parse(readFileSync(REGISTER_FILE, "utf8"));
    if (!Array.isArray(parsed.sources)) {
        throw new Error(`${REGISTER_FILE} is malformed — expected a "sources" array`);
    }
    return parsed.sources;
}

// v3.3.0 (item 19) — a cadence suffix appended to the detail line whenever
// a source declares its own updateOn (see data-sources.json's schema-note);
// purely informational, never changes the fresh/stale/missing verdict
// itself, which stays keyed on CONFIG.FRESHNESS_WARN_DAYS for every source.
function cadenceSuffix(source) {
    return source.updateOn ? ` [updateOn: ${source.updateOn}]` : "";
}

function checkSource(source) {
    if (!source.rawFile) {
        return { name: source.name, status: "n/a", detail: `no cached raw file (hand-curated source)${cadenceSuffix(source)}` };
    }
    const rawPath = path.join(TOOLS_ROOT, source.rawFile);
    if (!existsSync(rawPath)) {
        return { name: source.name, status: "missing", detail: `never fetched — run \`node ${source.updateScript} --fetch\`${cadenceSuffix(source)}` };
    }
    const ageDays = Math.floor((Date.now() - statSync(rawPath).mtimeMs) / MS_PER_DAY);
    if (ageDays > CONFIG.FRESHNESS_WARN_DAYS) {
        return {
            name: source.name, status: "stale",
            detail: `${ageDays} days old (> ${CONFIG.FRESHNESS_WARN_DAYS}) — consider \`node ${source.updateScript} --fetch\`${cadenceSuffix(source)}`,
        };
    }
    return { name: source.name, status: "fresh", detail: `${ageDays} days old${cadenceSuffix(source)}` };
}

function main() {
    const sources = loadRegister();
    console.log(`Checked ${sources.length} registered data source(s) (threshold: ${CONFIG.FRESHNESS_WARN_DAYS} days):\n`);

    let staleCount = 0, missingCount = 0;
    for (const source of sources) {
        const result = checkSource(source);
        const marker = { fresh: "✓", stale: "⚠", missing: "⚠", "n/a": "·" }[result.status];
        console.log(`  ${marker} ${result.name} — ${result.detail}`);
        if (result.status === "stale") staleCount++;
        if (result.status === "missing") missingCount++;
    }

    console.log("");
    if (staleCount || missingCount) {
        console.log(`${staleCount} stale, ${missingCount} missing — advisory only, nothing blocked.`);
    } else {
        console.log("All cached sources are within the freshness window.");
    }

    const mismatches = sources.map(checkSnapshot).filter(Boolean);
    if (mismatches.length) {
        console.log(`\nSNAPSHOT MISMATCH (blocking):`);
        for (const m of mismatches) console.log(`  ✗ ${m}`);
        process.exitCode = EXIT.SNAPSHOT_MISMATCH;
    } else {
        console.log("Every list was built from the raw snapshot cached now.");
    }
}

main();
