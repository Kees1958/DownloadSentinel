"use strict";

// v3.5.4 — util/ActiveThreatHosts.js (active-threat delivery floor, ported
// from 3P Matrix 4.5.1 tools/test-download-active-threat.mjs — same 8 cases,
// plus the DS additions: original-link fallback, verdict/label re-derivation,
// hard-rule passthrough, guards). Expected values come from the module's own
// CONFIG and ScoringEngineV2, never typed.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { ActiveThreatHosts } from "../../util/ActiveThreatHosts.js";
import { ScoringEngineV2 } from "../../protection/ScoringEngineV2.js";

const { CONFIG } = ActiveThreatHosts;
const FLOOR = CONFIG.FLOOR_SCORE;
const MILD = -5;                          // a weak pre-existing signal, milder than the floor
const PLATFORM = { score: MILD, label: "Hosted on a platform where anyone can publish", source: CONFIG.PLATFORM_SOURCE };
// v3.5.5: a signal about the FILE or the sender (not the host) — the platform row is left out with a hit.
const FILE_SIGNAL = { score: -10, label: "Link opened from a webmail or chat page", source: "MessageOrigin" };

// Stand-in for a BrowserProtection.checkHostReputation() result.
function dsResult(score, breakdown = [], extra = {}) {
    return { score, breakdown, classification: ScoringEngineV2.classifyByScore(score), label: "",
             hardRuleApplied: null, ...extra };
}
const hasSource = (r, src) => r.breakdown.some(e => e.source === src);

describe("ActiveThreatHosts — ported 3P Matrix cases", () => {
    test("1. non-campaign download: result object untouched", () => {
        const input = dsResult(MILD, [PLATFORM]);
        assert.equal(ActiveThreatHosts.applyFloor(input, "https://example.com/setup.exe"), input);
    });
    test("2. CDN host + delivery extension: floored, entry added", () => {
        const out = ActiveThreatHosts.applyFloor(dsResult(MILD, [PLATFORM]),
            "https://raw.githubusercontent.com/user/repo/main/payload.zip");
        assert.equal(out.score, FLOOR);
        assert.ok(hasSource(out, CONFIG.SOURCE));
    });
    test("3. CDN host, non-delivery extension: untouched", () => {
        const input = dsResult(MILD, [PLATFORM]);
        assert.equal(ActiveThreatHosts.applyFloor(input, "https://raw.githubusercontent.com/user/repo/main/README.md"), input);
    });
    test("4. github.com /releases/download/ .exe: floored", () => {
        const out = ActiveThreatHosts.applyFloor(dsResult(MILD, [PLATFORM]),
            "https://github.com/user/repo/releases/download/v1/tool.exe");
        assert.equal(out.score, FLOOR);
    });
    test("5. Download ZIP shape, sole signal: disclaimer present, explained, score 0", () => {
        const out = ActiveThreatHosts.applyFloor(dsResult(0, []),
            "https://github.com/user/repo/archive/refs/heads/main.zip");
        const note = out.breakdown.find(e => e.source === CONFIG.NOTE_SOURCE);
        assert.ok(note);
        assert.equal(note.explained, true);
        assert.equal(note.score, CONFIG.NOTE_SCORE);
    });
    test("6. Download ZIP shape, corroborated: disclaimer suppressed", () => {
        const out = ActiveThreatHosts.applyFloor(dsResult(FILE_SIGNAL.score, [FILE_SIGNAL]),
            "https://github.com/user/repo/archive/refs/heads/main.zip");
        assert.equal(out.score, FLOOR);
        assert.equal(hasSource(out, CONFIG.NOTE_SOURCE), false);
    });
    test("7. gitlab.com /-/raw/ .exe: floored", () => {
        const out = ActiveThreatHosts.applyFloor(dsResult(-15, [PLATFORM]),
            "https://gitlab.com/user/repo/-/raw/main/payload.exe");
        assert.equal(out.score, FLOOR);
    });
    test("8. floor never raises an already-worse score", () => {
        const worse = FLOOR - 20;
        const out = ActiveThreatHosts.applyFloor(dsResult(worse, [{ score: worse, label: "w", source: "RiskyHosting" }]),
            "https://github.com/user/repo/releases/download/v1/tool.exe");
        assert.equal(out.score, worse);
    });
});

describe("ActiveThreatHosts — DownloadSentinel additions", () => {
    test("github.com browsing UI (no shape) is never a hit, even with a delivery extension", () => {
        assert.equal(ActiveThreatHosts.match("github.com", "/user/repo/blob/main/tool.exe"), null);
    });
    test("original link decides when the final CDN URL has no extension", () => {
        const out = ActiveThreatHosts.applyFloor(dsResult(MILD, [PLATFORM]), [
            "https://release-assets.githubusercontent.com/github-production-release-asset/1/abc?sig=x",
            "https://github.com/user/repo/releases/download/v1/tool.exe",
        ]);
        assert.equal(out.score, FLOOR);
    });
    test("verdict and count label re-derived from the floored score", () => {
        const out = ActiveThreatHosts.applyFloor(dsResult(0, []), "https://raw.githubusercontent.com/u/r/main/a.ps1");
        assert.equal(out.classification, ScoringEngineV2.classifyByScore(FLOOR));
        assert.match(out.label, new RegExp(`^1 heuristic risk signal detected — ${out.classification.toLowerCase()}$`));
    });
    test("hard rule (e.g. DNS-blocked) keeps its own verdict and label", () => {
        const hard = dsResult(-100, [], { hardRuleApplied: "Blocked by DNS", label: "Blocked by DNS",
                                          classification: "Probably Malicious" });
        const out = ActiveThreatHosts.applyFloor(hard, "https://raw.githubusercontent.com/u/r/main/a.zip");
        assert.equal(out.label, hard.label);
        assert.equal(out.classification, hard.classification);
        assert.equal(out.score, hard.score);
    });
    test("input is never mutated; extra result fields survive", () => {
        const input = dsResult(MILD, [PLATFORM], { dnsChecks: [{ status: "ALLOWED" }] });
        const snapshot = JSON.stringify(input);
        const out = ActiveThreatHosts.applyFloor(input, "https://codeload.github.com/u/r/zip/a.zip");
        assert.equal(JSON.stringify(input), snapshot);
        assert.deepEqual(out.dnsChecks, input.dnsChecks);
    });
    // ── v3.5.5 (3P Matrix 4.5.8) ──────────────────────────────────────────
    test("v3.5.5: platform row left out with a hit (one fact, one signal)", () => {
        const out = ActiveThreatHosts.applyFloor(dsResult(MILD, [PLATFORM]), "https://raw.githubusercontent.com/u/r/main/a.zip");
        assert.equal(hasSource(out, CONFIG.PLATFORM_SOURCE), false);
        assert.equal(hasSource(out, CONFIG.SOURCE), true);
    });
    test("v3.5.5: no hit → platform row untouched", () => {
        const input = dsResult(MILD, [PLATFORM]);
        assert.equal(ActiveThreatHosts.applyFloor(input, "https://raw.githubusercontent.com/u/r/main/a.js"), input);
    });
    test("v3.5.5: label is the engine's own heuristicLabel()", () => {
        const out = ActiveThreatHosts.applyFloor(dsResult(0, []), "https://raw.githubusercontent.com/u/r/main/a.zip");
        assert.equal(out.label, ScoringEngineV2.heuristicLabel(1, out.classification));
    });
    test("v3.5.5: real engine + floor — no 'halved' platform line next to the malware line", () => {
        const url = "https://raw.githubusercontent.com/u/r/refs/heads/main/tool.zip";
        const ds = ScoringEngineV2.evaluateHostReputation({
            rdap: { status: "UNKNOWN", score: 0 }, domainHit: null, tldHit: null, sketchyUrl: { score: 0, signals: [] },
            mimeResult: { neutral: true, score: 0 }, sizeResult: { exceeds: false, score: 0 },
            riskyHosting: { host: "raw.githubusercontent.com", score: -10, label: "Download hosted on risky file sharing platform (raw.githubusercontent.com)" },
            url, fileType: "archive" });
        assert.ok(ds.breakdown.some(e => e.source === CONFIG.PLATFORM_SOURCE), "precondition: engine adds the platform row");
        const out = ActiveThreatHosts.applyFloor(ds, url);
        assert.equal(out.breakdown.some(e => e.source === CONFIG.PLATFORM_SOURCE), false);
        assert.equal(out.score, FLOOR);
        assert.equal(out.classification, ScoringEngineV2.classifyByScore(FLOOR));
    });
    test("guards: null result, blob:/data:/garbage URLs, uppercase host", () => {
        assert.equal(ActiveThreatHosts.applyFloor(null, "blob:https://github.com/x"), null);
        assert.equal(ActiveThreatHosts.applyFloor(null, "not a url"), null);
        assert.equal(ActiveThreatHosts.applyFloor(null, [null, undefined]), null);
        assert.equal(ActiveThreatHosts.applyFloor(null, "https://RAW.GitHubUserContent.com/u/r/a.ZIP").score, FLOOR);
    });
});
