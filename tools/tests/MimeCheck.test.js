"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { SCORING_CONFIG } from "../../protection/ScoringEngineV2.js";
import { MimeCheck } from "../../protection/MimeCheck.js";

describe("MimeCheck.checkMime", () => {
    test("consistent extension/MIME pair scores 0", () => {
        const r = MimeCheck.checkMime("exe", "application/x-msdownload");
        assert.equal(r.consistent, true);
        assert.equal(r.score, 0);
    });
    test("genuine mismatch scores MIME_MISMATCH_SCORE", () => {
        const r = MimeCheck.checkMime("exe", "image/jpeg");
        assert.equal(r.consistent, false);
        assert.equal(r.score, SCORING_CONFIG.MIME_MISMATCH_SCORE);
    });
    test("application/octet-stream is neutral", () => {
        const r = MimeCheck.checkMime("exe", "application/octet-stream");
        assert.equal(r.neutral, true);
        assert.equal(r.score, 0);
    });
    test("v2.9.0 bug fix: text/plain for a script extension is neutral, same as any other extension", () => {
        // Previously scored a special -20 "possible misconfiguration" penalty
        // here — but text/plain is the single most common Content-Type raw
        // script hosting (raw.githubusercontent.com and virtually every
        // install-one-liner CDN) actually uses for .sh/.ps1/etc., not a sign
        // of misconfiguration. Under pre-v2.9.0 "worst signal wins" this was
        // invisible (ScriptFormat's -25 always dominated); Step 3's
        // combination logic let it stack and wrongly push ordinary install
        // scripts into a worse warning tier — caught by the fp-sweep
        // known-good gate. See CHANGELOG.
        const r = MimeCheck.checkMime("ps1", "text/plain");
        assert.equal(r.neutral, true);
        assert.equal(r.score, 0);
    });
    test("text/plain for a non-script extension is neutral", () => {
        const r = MimeCheck.checkMime("txt", "text/plain");
        assert.equal(r.neutral, true);
        assert.equal(r.score, 0);
    });
    test("v2.9.0 bug fix: .js served as application/javascript is consistent, not a mismatch", () => {
        // application/javascript was missing from DangerousMimes.MIME_TO_EXTS
        // entirely, despite being one of the most common real-world
        // Content-Types for .js (jsdelivr, unpkg, and many other CDNs send
        // exactly this) — every such file was wrongly flagged as a -60
        // "genuine mismatch". See CHANGELOG.
        const r = MimeCheck.checkMime("js", "application/javascript");
        assert.equal(r.consistent, true);
        assert.equal(r.score, 0);
    });
    test("strips MIME parameters before comparing", () => {
        const r = MimeCheck.checkMime("exe", "application/x-msdownload; charset=binary");
        assert.equal(r.consistent, true);
    });
    test("missing extension or MIME is unevaluable", () => {
        assert.equal(MimeCheck.checkMime("", "image/jpeg").neutral, true);
        assert.equal(MimeCheck.checkMime("exe", "").neutral, true);
    });
    test("unmapped extension is unevaluable, not a false mismatch", () => {
        const r = MimeCheck.checkMime("xyzabc", "application/octet-stream");
        assert.equal(r.neutral, true);
        assert.equal(r.score, 0);
    });
});

describe("MimeCheck.checkSize", () => {
    test("under the VT limit does not exceed", () => {
        const r = MimeCheck.checkSize(10 * 1024 * 1024);
        assert.equal(r.exceeds, false);
        assert.equal(r.score, 0);
    });
    test("over the VT limit (650 MB) exceeds and penalizes", () => {
        const r = MimeCheck.checkSize(700 * 1024 * 1024);
        assert.equal(r.exceeds, true);
        assert.equal(r.score, -20);
    });
    test("unknown size (0/null/negative) is treated as unknown, not exceeding", () => {
        assert.equal(MimeCheck.checkSize(0).exceeds, false);
        assert.equal(MimeCheck.checkSize(null).exceeds, false);
        assert.equal(MimeCheck.checkSize(-5).exceeds, false);
    });
});
