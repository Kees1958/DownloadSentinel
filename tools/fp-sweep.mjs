#!/usr/bin/env node
"use strict";

// tools/fp-sweep.mjs
//
// Heuristics plan Step 0 (v2.7.0) — false-positive sweep.
//
// Scores every entry in tests/fixtures/fp-corpus.json through the exact same
// synchronous host-reputation signals BrowserProtection.checkHostReputation()
// uses (domain/TLD/HostList lookups, SketchyUrlCheck, MimeCheck, RiskyHosting,
// double-extension/script/launcher flags) and compares the result against the
// saved baseline (tests/fixtures/fp-baseline.json).
//
// Quad9 and RDAP are MOCKED per entry — this sweep runs fully offline, no
// live network calls, no live malware. Default mock: Quad9 ALLOWED, RDAP
// "no signal" (score 0, i.e. an established domain) — a corpus entry can
// override either via its own "mockQuad9"/"mockRdap" field when a specific
// scenario needs it.
//
// Hard gate (per the heuristics plan's own release table): every run must
// show NO knownGood entry crossing from its baseline warning level into a
// worse one, unless that specific entry carries "acceptedRegression": true
// and an "acceptedReason" string explaining why. stagingSynthetic entries are
// informational only in v2.7.0 (no new detection was added this step; they
// become a real gate once Step 2's staging checks land in v2.8.0).
//
// v3.4.0 (weight review) — three more gates, and the sweep is now a hard
// step of complete-check.mjs (it was never run by it before):
//   1. ABSOLUTE: an as-is knownGood entry at "Probably Suspicious" or worse
//      FAILS, baseline or not — the regression check alone had frozen two
//      such entries in. An entry can carry "acceptedRisk": true +
//      "acceptedReason" to be listed instead of failing (explicit decision).
//   2. VARIANTS: every knownGood entry is also scored as if (a) its extension
//      was hidden at download start (the obfuscation signal — e.g. vendor
//      CDN links like go.microsoft.com/fwlink, which a static corpus entry
//      could never express) and (b) fetched over plain HTTP. A variant at
//      "Probably Malicious" FAILS; "Probably Suspicious" is listed only.
//      With the pre-v3.4.0 weights, 11 legit installers reached Malicious.
//   3. The R1/R4 inputs (visible extension, extensionless binary) are passed
//      exactly as BrowserProtection.checkHostReputation() gets them.
//
// v3.5.0 — FLOWS (corpus "flows"): complete download journeys (referrer,
// redirect, domain age, extension hidden at start), each scored at every FP
// reduction level with VirusTotal unknown, exactly as background.js scales it
// (ScoringEngineV2.scaleHostScoreForUnknownVt). Gates (FLOW_GATES below):
//   expect "quiet" (legit) — below Probably Suspicious at HIGH and MEDIUM,
//                            never Probably Malicious at LOW (NONE: listed only)
//   expect "flag"  (attack) — Probably Suspicious or worse, or always-warned
//                            (R1), at MEDIUM, LOW and NONE (HIGH: listed only)
//
// Usage:
//   node tools/fp-sweep.mjs              — run the sweep against the saved baseline
//   node tools/fp-sweep.mjs --update     — (re)write the baseline from the current run

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";
import { repoPaths } from "./repoPaths.mjs";

import { FilenameAnalysis } from "../util/FilenameAnalysis.js";
import { UrlUtils } from "../util/UrlUtils.js";
import { SuspiciousDomains } from "../util/SuspiciousDomains.js";
import { SuspiciousTlds } from "../util/SuspiciousTlds.js";
import { RiskyHostingSites } from "../util/RiskyHostingSites.js";
import { HostList } from "../util/HostList.js";
import { SketchyUrlCheck } from "../protection/SketchyUrlCheck.js";
import { MimeCheck } from "../protection/MimeCheck.js";
import { ScoringEngineV2 } from "../protection/ScoringEngineV2.js";
import { DownloadShape } from "../util/DownloadShape.js";
import { WarnPolicy } from "../protection/WarnPolicy.js";   // v3.5.2 — window shown yes/no

const { TOOLS_ROOT: ROOT } = repoPaths(import.meta.url);   // v3.6.0 layout: tools/ holds tests/fixtures/
const CORPUS_FILE   = path.join(ROOT, "tests", "fixtures", "fp-corpus.json");
const BASELINE_FILE = path.join(ROOT, "tests", "fixtures", "fp-baseline.json");

const SHOULD_UPDATE = process.argv.includes("--update");

// ── Warning-level ranking — must match ScoringEngineV2's own tier order so
// "did this get worse" is a simple integer comparison. ──────────────────────
const LEVEL_RANK = Object.freeze({
    "Probably Safe":          0,
    "Probably Inconclusive":  1,
    "Probably Suspicious":    2,
    "Probably Malicious":     3,
});

// ── Default mocks (per-entry overridable) — no live network calls. ─────────
// v3.4.0 — scenario variants each knownGood entry is also scored under.
const VARIANT = Object.freeze({
    AS_IS:       "as-is",
    HIDDEN_EXT:  "extension hidden at download start",
    PLAIN_HTTP:  "fetched over plain HTTP",
});
// Worst level allowed per variant before the sweep FAILS (exclusive).
const GATE_RANK = Object.freeze({
    [VARIANT.AS_IS]:      LEVEL_RANK["Probably Suspicious"],   // known-good must stay below Suspicious
    [VARIANT.HIDDEN_EXT]: LEVEL_RANK["Probably Malicious"],    // variants: never Malicious
    [VARIANT.PLAIN_HTTP]: LEVEL_RANK["Probably Malicious"],
});
const REVIEW_RANK = LEVEL_RANK["Probably Suspicious"];          // variants at/above this are listed

// v3.5.0 — flow gates per FP reduction level: [lowest allowed rank, highest allowed rank]
// (inclusive); null = that level is only listed, never gated.
const FP_LEVELS = Object.freeze(["HIGH", "MEDIUM", "LOW", "NONE"]);
const FLOW_GATES = Object.freeze({
    quiet: Object.freeze({
        HIGH:   [LEVEL_RANK["Probably Safe"], LEVEL_RANK["Probably Inconclusive"]],
        MEDIUM: [LEVEL_RANK["Probably Safe"], LEVEL_RANK["Probably Inconclusive"]],
        LOW:    [LEVEL_RANK["Probably Safe"], LEVEL_RANK["Probably Suspicious"]],
        // NONE = "count everything in full, ×2 when VT is unknown" by design, so a
        // legit download may reach Malicious there (e.g. an HTTP mirror) — listed only.
        NONE:   null,
    }),
    flag: Object.freeze({
        HIGH:   null,
        MEDIUM: [LEVEL_RANK["Probably Suspicious"], LEVEL_RANK["Probably Malicious"]],
        LOW:    [LEVEL_RANK["Probably Suspicious"], LEVEL_RANK["Probably Malicious"]],
        NONE:   [LEVEL_RANK["Probably Suspicious"], LEVEL_RANK["Probably Malicious"]],
    }),
});
const VT_UNKNOWN = true; // flows are scored as background.js does when VirusTotal has no verdict

const DEFAULT_MOCK_QUAD9 = Object.freeze({ status: "ALLOWED" });
const DEFAULT_MOCK_RDAP  = Object.freeze({ score: 0, label: "established domain (mocked)" });

/**
 * Score one corpus entry using exactly the synchronous signals
 * BrowserProtection.checkHostReputation() would use — Quad9/RDAP mocked.
 */
function toPlainHttp(u) {
    return u.replace(/^https:\/\//i, "http://");
}

function scoreEntry(entry, variant = VARIANT.AS_IS, fpLevel = null) {
    const http        = variant === VARIANT.PLAIN_HTTP;
    const url         = http ? toPlainHttp(entry.url) : entry.url;
    const originalUrl = http ? toPlainHttp(entry.originalUrl ?? entry.url) : (entry.originalUrl ?? url);
    const filename     = entry.filename ?? "";
    const mime         = entry.mime ?? "";
    const totalBytes   = entry.totalBytes ?? 0;

    const classified = FilenameAnalysis.classifyDownload(url, originalUrl, filename, mime);
    // Not a monitored file type at all — Download Sentinel would never have
    // scored this download in the first place. Report as a pass-through.
    if (!classified) {
        return { classification: "Not monitored", score: 0, breakdown: [] };
    }
    const { ext, fileType, isScript, isLinuxLauncher } = classified;
    const shape = DownloadShape.contextOf(classified); // v3.4.0 — R1/R4 inputs, as in checkHostReputation()

    const finalHostname = UrlUtils.getHostname(url);
    const finalTld      = UrlUtils.getTld(finalHostname);

    const domainHit   = SuspiciousDomains.lookup(finalHostname);
    const tldHit       = SuspiciousTlds.lookup(finalTld);
    const hostListHit  = HostList.lookup(finalHostname);
    const sketchyUrl    = SketchyUrlCheck.check(url);
    const mimeResult    = MimeCheck.checkMime(ext || shape.visibleExt || "", mime || "");
    const sizeResult    = MimeCheck.checkSize(totalBytes || 0);
    const riskyHosting  = RiskyHostingSites.lookup(finalHostname);
    const doubleExt     = FilenameAnalysis.getDoubleExtension(filename);

    const quad9 = entry.mockQuad9 ?? DEFAULT_MOCK_QUAD9;
    const rdap  = entry.mockRdap  ?? DEFAULT_MOCK_RDAP;

    // v2.11.0 — Step 5 filename/URL heuristics (RLO, padded double extension,
    // brand homoglyph, URL shortener, referrer mismatch) run INSIDE
    // evaluateHostReputation() itself (see ScoringEngineV2.js), keyed off
    // `filename`/`referrer` below — no separate call needed here, just pass
    // the corpus entry's fields through same as BrowserProtection does.
    const referrer = entry.referrer ?? null;

    const evaluation = ScoringEngineV2.evaluateHostReputation({
        quad9, rdap,
        domainHit, tldHit, hostListHit,
        sketchyUrl, mimeResult, sizeResult, riskyHosting,
        url, originalUrl, fileType, isScript, doubleExt, isLinuxLauncher,
        filename, referrer,
        isUnknownBinary: shape.isUnknownBinary,
        fpLevel,                                       // v3.5.0 — FP-level strategy (null = default)
        // onCreated-vs-onChanged signal: null for the as-is entry; the
        // HIDDEN_EXT variant (v3.4.0) asks the real builder what it would
        // report had nothing been visible at the start.
        obfuscation: variant === VARIANT.HIDDEN_EXT ? FilenameAnalysis.getObfuscationSignal(null, ext) : null,
    });

    // v3.5.6 — scored as background.js does when VirusTotal does not know the file
    // (the worst case: small signals stack on a dubious source; ScoringEngineV2.hostVerdict).
    const verdict = ScoringEngineV2.hostVerdict(evaluation, VT_UNKNOWN);
    return {
        classification: verdict.classification,
        score:          verdict.score,
        breakdown:       verdict.breakdown.map(b => `${b.source}: ${b.score}`),
        entries:         verdict.breakdown,                    // v3.5.2 — raw entries for WarnPolicy
    };
}

// v3.5.0 — one flow at one FP level, with background.js's VT-unknown scaling.
function scoreFlow(flow, fpLevel) {
    const r = scoreEntry(flow, flow.hiddenExt ? VARIANT.HIDDEN_EXT : VARIANT.AS_IS, fpLevel);
    if (r.classification === "Not monitored") return { ...r, alwaysWarn: false };
    const { scaled } = ScoringEngineV2.scaleHostScoreForUnknownVt(r.score, fpLevel, VT_UNKNOWN);
    const clamped = Math.max(-100, Math.min(100, scaled));
    const classified = FilenameAnalysis.classifyDownload(flow.url, flow.originalUrl ?? flow.url, flow.filename ?? "", flow.mime ?? "");
    const alwaysWarn = DownloadShape.mustAlwaysWarn(classified);
    // v3.5.2 — would the warning WINDOW open? (background.js: R1 always-warn, then WarnPolicy)
    const window = alwaysWarn || WarnPolicy.downloadDecision({ combinedScore: clamped, fpLevel, entries: r.entries }).warn;
    return { ...r, score: clamped, classification: ScoringEngineV2.classifyByScore(clamped), alwaysWarn, window };
}

// Returns the number of gate failures; prints one row per flow.
function reportFlows(flows) {
    let failures = 0;
    console.log(`\nflows (${flows.length}) — score per FP level with VirusTotal unknown; W = warning window opens, · = quiet; ✗ = gate failed:`);
    console.log(`  ${"flow".padEnd(40)} ${FP_LEVELS.map(l => l.padStart(12)).join("")}`);
    for (const flow of flows) {
        const cells = FP_LEVELS.map(level => {
            const r = scoreFlow(flow, level);
            const rank = LEVEL_RANK[r.classification] ?? 0;
            const gate = FLOW_GATES[flow.expect]?.[level];
            const warned = flow.expect === "flag" && r.alwaysWarn;
            // v3.5.2 — an attack flow must also get a WINDOW wherever it is gated (Medium, Low, None)
            const windowOk = flow.expect !== "flag" || !gate || r.window;
            const pass = (!gate || warned || (rank >= gate[0] && rank <= gate[1])) && windowOk;
            if (!pass) failures++;
            const tag = r.classification === "Not monitored" ? "n/m" : r.classification.replace("Probably ", "").slice(0, 5);
            return `${pass ? " " : "✗"}${String(r.score).padStart(4)} ${tag.padEnd(5)}${r.window ? "W" : "·"}`;
        });
        console.log(`  ${(flow.expect === "flag" ? "⚠ " : "  ") + flow.id.padEnd(38)}${cells.join(" ")}`);
    }
    return failures;
}

function loadCorpus() {
    if (!existsSync(CORPUS_FILE)) {
        throw new Error(`corpus file not found: ${path.relative(ROOT, CORPUS_FILE)}`);
    }
    return JSON.parse(readFileSync(CORPUS_FILE, "utf8"));
}

function loadBaseline() {
    if (!existsSync(BASELINE_FILE)) return null;
    return JSON.parse(readFileSync(BASELINE_FILE, "utf8"));
}

function buildResults(corpus) {
    const results = { knownGood: {}, stagingSynthetic: {} };
    for (const entry of corpus.knownGood)       results.knownGood[entry.url]       = scoreEntry(entry);
    for (const entry of corpus.stagingSynthetic) results.stagingSynthetic[entry.url] = scoreEntry(entry);
    return results;
}

function main() {
    console.log("── tools/fp-sweep.mjs — false-positive sweep (heuristics plan Step 0) ──\n");

    const corpus  = loadCorpus();
    const results = buildResults(corpus);

    if (SHOULD_UPDATE || !existsSync(BASELINE_FILE)) {
        writeFileSync(BASELINE_FILE, JSON.stringify(results, null, 2) + "\n", "utf8");
        console.log(`Baseline written: ${path.relative(ROOT, BASELINE_FILE)}`);
        console.log(`  knownGood: ${corpus.knownGood.length} entries`);
        console.log(`  stagingSynthetic: ${corpus.stagingSynthetic.length} entries`);
        return;
    }

    const baseline = loadBaseline();
    let regressions = 0;
    let improvements = 0;

    console.log(`knownGood corpus (${corpus.knownGood.length} entries) — must not regress:`);
    for (const entry of corpus.knownGood) {
        const current  = results.knownGood[entry.url];
        const previous  = baseline.knownGood[entry.url];
        const currRank  = LEVEL_RANK[current.classification] ?? 99;
        const prevRank  = previous ? (LEVEL_RANK[previous.classification] ?? 99) : 0;

        if (!previous) {
            console.log(`  + NEW   ${entry.url}\n          → ${current.classification} (${current.score})`);
            continue;
        }
        if (currRank > prevRank) {
            if (entry.acceptedRegression) {
                console.log(`  ~ OK (accepted)  ${entry.url}`);
                console.log(`          ${previous.classification} → ${current.classification} — ${entry.acceptedReason || "(no reason given)"}`);
            } else {
                console.log(`  ✗ REGRESSION  ${entry.url}`);
                console.log(`          ${previous.classification} (${previous.score}) → ${current.classification} (${current.score})`);
                console.log(`          breakdown: ${current.breakdown.join(", ") || "(none)"}`);
                regressions++;
            }
        } else if (currRank < prevRank) {
            console.log(`  ✓ improved  ${entry.url}: ${previous.classification} → ${current.classification}`);
            improvements++;
        }
    }

    // ── v3.4.0 gate 1: absolute level for as-is knownGood entries ──────────
    let absoluteFailures = 0;
    console.log(`\nknownGood absolute gate — as-is must stay below Probably Suspicious:`);
    for (const entry of corpus.knownGood) {
        const current = results.knownGood[entry.url];
        if ((LEVEL_RANK[current.classification] ?? 0) < GATE_RANK[VARIANT.AS_IS]) continue;
        if (entry.acceptedRisk) {
            console.log(`  ~ accepted  ${current.classification} (${current.score})  ${entry.url}`);
            console.log(`          ${entry.acceptedReason || "(no reason given)"}`);
        } else {
            console.log(`  ✗ TOO HIGH  ${current.classification} (${current.score})  ${entry.url}`);
            console.log(`          breakdown: ${current.breakdown.join(", ") || "(none)"}`);
            absoluteFailures++;
        }
    }

    // ── v3.4.0 gate 2: scenario variants (never Malicious) ─────────────────
    let variantFailures = 0;
    for (const variant of [VARIANT.HIDDEN_EXT, VARIANT.PLAIN_HTTP]) {
        console.log(`\nknownGood variant "${variant}" — Malicious fails, Suspicious is listed for review:`);
        for (const entry of corpus.knownGood) {
            const r = scoreEntry(entry, variant);
            const rank = LEVEL_RANK[r.classification] ?? 0;
            if (rank < REVIEW_RANK) continue;
            const failing = rank >= GATE_RANK[variant];
            if (failing) variantFailures++;
            console.log(`  ${failing ? "✗ FAIL  " : "· review"}  ${r.classification} (${r.score})  ${entry.url}  [${r.breakdown.join(", ")}]`);
        }
    }

    const flowFailures = reportFlows(corpus.flows || []);

    console.log(`\nstagingSynthetic corpus (${corpus.stagingSynthetic.length} entries) — informational only, no gate yet (see heuristics plan Step 3 / v2.9.0):`);
    for (const entry of corpus.stagingSynthetic) {
        const current = results.stagingSynthetic[entry.url];
        console.log(`  ${current.classification.padEnd(22)} (${String(current.score).padStart(4)})  ${entry.url}`);
    }

    console.log();
    if (absoluteFailures > 0 || variantFailures > 0 || flowFailures > 0) {
        console.log(`✗ fp-sweep FAILED — ${absoluteFailures} knownGood entries at Suspicious or worse, ${variantFailures} variant scores at Malicious, ${flowFailures} flow gate(s) failed. Lower the responsible weight, or mark an as-is entry "acceptedRisk" with an "acceptedReason".`);
        process.exit(1);
    }
    if (regressions > 0) {
        console.log(`✗ fp-sweep FAILED — ${regressions} unexplained knownGood regression(s). Run with --update to accept, or add "acceptedRegression"/"acceptedReason" to the corpus entry if the new signal is correct.`);
        process.exit(1);
    }
    console.log(`✓ fp-sweep passed — no unexplained knownGood regressions (${improvements} improved).`);
}

main();
