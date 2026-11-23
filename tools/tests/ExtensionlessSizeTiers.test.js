"use strict";

// v3.5.5 — Check 26 size tiers (ported from 3P Matrix 4.5.6 + 4.5.8, its tools/test-large-binary.mjs).
// An extensionless generic binary from a file-sharing host (RiskyHostingSites) scores
//   ≥ LARGE_EXTENSIONLESS_BINARY_MIN_BYTES (32 MB)  → LARGE_EXTENSIONLESS_BINARY_SCORE
//   ≥ HUGE_EXTENSIONLESS_BINARY_MIN_BYTES  (650 MB, = VT_MAX_BYTES) → HUGE_EXTENSIONLESS_BINARY_SCORE,
//     which REPLACES Check 7 (SizeCheck) for that file — one fact, one signal.
// Every expected value is read from SCORING_CONFIG / MimeCheck — nothing typed here.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { ScoringEngineV2, SCORING_CONFIG } from "../../protection/ScoringEngineV2.js";
import { MimeCheck } from "../../protection/MimeCheck.js";
import { RiskyHostingSites } from "../../util/RiskyHostingSites.js";

const SOURCE = "ExtensionlessBinary";
const SIZE_SOURCE = "SizeCheck";
const FILE_HOST = "cdn.discordapp.com";                      // the real case (3P Matrix 4.5.6)
const risky = RiskyHostingSites.lookup(FILE_HOST);
const LARGE = SCORING_CONFIG.LARGE_EXTENSIONLESS_BINARY_MIN_BYTES;
const HUGE = SCORING_CONFIG.HUGE_EXTENSIONLESS_BINARY_MIN_BYTES;
const ONE_MB = SCORING_CONFIG.BYTES_PER_MB;
const C = ScoringEngineV2.Classification;

const base = { rdap: { status: "UNKNOWN", score: 0 }, domainHit: null, tldHit: null, sketchyUrl: { score: 0, signals: [] },
               mimeResult: { neutral: true, score: 0 }, url: `https://${FILE_HOST}/attachments/1/2/d717ab737d`,
               fileType: "unknown-binary", isUnknownBinary: true };
const run = (bytes, extra = {}) => ScoringEngineV2.evaluateHostReputation({
    ...base, riskyHosting: risky, totalBytes: bytes, sizeResult: MimeCheck.checkSize(bytes), ...extra });
const entry = (r) => r.breakdown.find(b => b.source === SOURCE) || {};
const has = (r, src) => r.breakdown.some(b => b.source === src);

describe("Check 26 size tiers (v3.5.5)", () => {
    test("precondition: the real-case host is a file-sharing host", () => assert.ok(risky));
    test("one VirusTotal limit: huge tier starts at MimeCheck's VT_MAX_BYTES", () => {
        assert.equal(HUGE, MimeCheck.VT_MAX_BYTES);
        assert.equal(HUGE, SCORING_CONFIG.VT_MAX_BYTES);
    });
    test("tiers get heavier with size", () => {
        assert.ok(SCORING_CONFIG.LARGE_EXTENSIONLESS_BINARY_SCORE < SCORING_CONFIG.EXTENSIONLESS_BINARY_SCORE);
        assert.ok(SCORING_CONFIG.HUGE_EXTENSIONLESS_BINARY_SCORE < SCORING_CONFIG.LARGE_EXTENSIONLESS_BINARY_SCORE);
    });
    test("size unknown (0) → normal signal (re-scored at completion)", () =>
        assert.equal(entry(run(0)).score, SCORING_CONFIG.EXTENSIONLESS_BINARY_SCORE));
    test("just below the large limit → normal signal", () =>
        assert.equal(entry(run(LARGE - 1)).score, SCORING_CONFIG.EXTENSIONLESS_BINARY_SCORE));
    test("at the large limit → large signal, Probably Suspicious", () => {
        const r = run(LARGE);
        assert.equal(entry(r).score, SCORING_CONFIG.LARGE_EXTENSIONLESS_BINARY_SCORE);
        assert.equal(r.classification, C.PROBABLY_SUSPICIOUS);
    });
    test("just below the huge limit → large signal", () =>
        assert.equal(entry(run(HUGE - 1)).score, SCORING_CONFIG.LARGE_EXTENSIONLESS_BINARY_SCORE));
    test("at the huge limit → huge signal", () =>
        assert.equal(entry(run(HUGE)).score, SCORING_CONFIG.HUGE_EXTENSIONLESS_BINARY_SCORE));
    test("above the huge limit → huge signal, no separate SizeCheck row", () => {
        const r = run(HUGE + ONE_MB);
        assert.equal(entry(r).score, SCORING_CONFIG.HUGE_EXTENSIONLESS_BINARY_SCORE);
        assert.equal(has(r, SIZE_SOURCE), false);
    });
    test("huge scores worse than large, still Probably Suspicious alone", () => {
        const huge = run(HUGE + ONE_MB), large = run(LARGE);
        assert.ok(huge.score < large.score);
        assert.equal(huge.classification, C.PROBABLY_SUSPICIOUS);
    });
    test("huge but not from a file-sharing host → normal signal, SizeCheck kept", () => {
        const r = run(HUGE + ONE_MB, { riskyHosting: null });
        assert.equal(entry(r).score, SCORING_CONFIG.EXTENSIONLESS_BINARY_SCORE);
        assert.equal(has(r, SIZE_SOURCE), true);
    });
    test("a file with an extension: SizeCheck kept, no Check 26", () => {
        const r = run(HUGE + ONE_MB, { isUnknownBinary: false, fileType: "executable" });
        assert.equal(has(r, SIZE_SOURCE), true);
        assert.equal(has(r, SOURCE), false);
    });
});
