"use strict";

// v3.5.2 — protection/WarnPolicy.js (window or quiet: thresholds per FP level +
// exceptions per check), DeliveryPatterns.brandOnPlatform (moved from
// 3P Matrix), Check 28 PlatformBrand for downloads, APP.RDAP_* constants.
// Expected values are derived from the constants, never typed.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { WarnPolicy } from "../../protection/WarnPolicy.js";
import { ScoringEngineV2, SCORING_CONFIG } from "../../protection/ScoringEngineV2.js";
import { RdapProtection } from "../../protection/RdapProtection.js";
import { DeliveryPatterns } from "../../util/DeliveryPatterns.js";
import { SuspiciousDomains } from "../../util/SuspiciousDomains.js";
import { APP } from "../../util/AppConstants.js";

const { CHECK, EXCEPTION, CONFIG } = WarnPolicy;
const FP_LEVELS = Object.keys(CONFIG.DOWNLOAD_WARN_FROM);
const e = (source, score, extra = {}) => ({ source, score, label: source, ...extra });
const decide = (combinedScore, fpLevel, entries = [], vtMalicious = 0) =>
    WarnPolicy.downloadDecision({ combinedScore, fpLevel, entries, vtMalicious });

describe("WarnPolicy — download thresholds per FP level", () => {
    test("at the threshold warns, one point milder is quiet; None always warns", () => {
        for (const level of FP_LEVELS) {
            const from = CONFIG.DOWNLOAD_WARN_FROM[level];
            if (from === null) {
                assert.equal(decide(0, level).warn, true, level);
                continue;
            }
            assert.equal(decide(from, level).warn, true, `${level} at ${from}`);
            assert.equal(decide(from + 1, level).warn, false, `${level} at ${from + 1}`);
        }
    });
    test("thresholds get stricter from High to Low (more windows at lower FP reduction)", () => {
        const { HIGH, MEDIUM, LOW } = CONFIG.DOWNLOAD_WARN_FROM;
        assert.ok(HIGH < MEDIUM && MEDIUM < LOW);
    });
    test("an unknown FP level falls back to the default level", () => {
        const from = CONFIG.DOWNLOAD_WARN_FROM[CONFIG.DEFAULT_FP_LEVEL];
        assert.equal(decide(from, "BOGUS").threshold, from);
    });
});

describe("WarnPolicy — exceptions always warn, at every level", () => {
    const quietScore = SCORING_CONFIG.SCORE_CEILING;   // a score no threshold reaches
    const cases = [
        [EXCEPTION.KNOWN_BAD,     [e("DnsThreat", SCORING_CONFIG.DNS_BLOCKED_SCORE)], 0],
        [EXCEPTION.KNOWN_BAD,     [], CONFIG.VT_FLAGGED_MIN],
        [EXCEPTION.IMPERSONATION, [e("LookalikeDomain", SCORING_CONFIG.LOOKALIKE_SITE_SCORE)], 0],
        [EXCEPTION.IMPERSONATION, [e("PlatformBrand", SCORING_CONFIG.LOOKALIKE_SITE_SCORE)], 0],
        [EXCEPTION.FILE_ITSELF,   [e("ScriptFormat", SCORING_CONFIG.SCRIPT_FORMAT_SCORE)], 0],
        [EXCEPTION.FILE_ITSELF,   [e("ExtensionlessBinary", SCORING_CONFIG.EXTENSIONLESS_BINARY_SCORE)], 0],
        [EXCEPTION.FILE_ITSELF,   [e("MimeCheck", SCORING_CONFIG.MIME_MISMATCH_SCORE)], 0],
        [EXCEPTION.LURE_ROUTE,    [e("MessageOrigin", SCORING_CONFIG.MESSAGE_ORIGIN_SCORE)], 0],
        [EXCEPTION.YOUNG_DOMAIN,  [e("RDAP", APP.RDAP_YOUNG_SCORE)], 0],
    ];
    for (const [exception, entries, vt] of cases) {
        test(`${exception} (${entries[0]?.source ?? "VirusTotal"})`, () => {
            for (const level of FP_LEVELS) {
                const d = decide(quietScore, level, entries, vt);
                assert.equal(d.warn, true, level);
                if (CONFIG.DOWNLOAD_WARN_FROM[level] !== null) assert.ok(d.exceptions.includes(exception), level);
            }
        });
    }
});

describe("WarnPolicy — what is NOT an exception", () => {
    test("route quirks alone (CDN/referrer/HTTP/hidden extension) are left to the threshold", () => {
        const route = [e("ReferrerMismatch", SCORING_CONFIG.REFERRER_MISMATCH_SCORE), e("ProtocolCheck", SCORING_CONFIG.HTTP_PENALTY),
                       e("HiddenExtension", SCORING_CONFIG.OBFUSCATION_UNKNOWN_SCORE)];
        assert.deepEqual(WarnPolicy.exceptionsFound(CHECK.DOWNLOAD, route), []);
    });
    test("a moderately new domain is not 'very new'", () => {
        assert.deepEqual(WarnPolicy.exceptionsFound(CHECK.DOWNLOAD, [e("RDAP", APP.RDAP_RECENT_SCORE)]), []);
    });
    test("explained entries never count (DeliveryContext)", () => {
        const explained = [e("MessageOrigin", 0, { explained: true, rawScore: SCORING_CONFIG.MESSAGE_ORIGIN_SCORE })];
        assert.deepEqual(WarnPolicy.exceptionsFound(CHECK.DOWNLOAD, explained), []);
    });
    test("site check: only known bad and impersonation — file/route/age exceptions do not apply", () => {
        const all = [e("ScriptFormat", SCORING_CONFIG.SCRIPT_FORMAT_SCORE), e("MessageOrigin", SCORING_CONFIG.MESSAGE_ORIGIN_SCORE),
                     e("RDAP", APP.RDAP_YOUNG_SCORE)];
        assert.deepEqual(WarnPolicy.exceptionsFound(CHECK.SITE, all), []);
        assert.deepEqual(WarnPolicy.exceptionsFound(CHECK.SITE, [e("LookalikeDomain", SCORING_CONFIG.LOOKALIKE_SITE_SCORE)]),
                         [EXCEPTION.IMPERSONATION]);
    });
    test("siteDecision: threshold from the caller; no threshold given = always", () => {
        const { HIGH, MEDIUM, LOW } = CONFIG.DOWNLOAD_WARN_FROM;   // any three ordered thresholds will do
        assert.equal(WarnPolicy.siteDecision({ score: MEDIUM, threshold: HIGH, entries: [] }).warn, false);
        assert.equal(WarnPolicy.siteDecision({ score: MEDIUM, threshold: LOW, entries: [] }).warn, true);
        assert.equal(WarnPolicy.siteDecision({ score: MEDIUM, entries: [] }).warn, true);   // no threshold = always
    });
    test("windowHint: the level's threshold, formatted by the caller; None says always", () => {
        for (const level of FP_LEVELS) {
            const from = CONFIG.DOWNLOAD_WARN_FROM[level];
            const hint = WarnPolicy.windowHint(level, String);
            assert.equal(hint, from === null ? CONFIG.WINDOW_HINT.ALWAYS
                                             : CONFIG.WINDOW_HINT.FROM_SCORE.replace(CONFIG.WINDOW_HINT.SCORE_TOKEN, String(from)), level);
        }
        assert.equal(WarnPolicy.windowHint("BOGUS"), "");
    });
    test("every exception has a plain-language text", () => {
        for (const ex of Object.values(EXCEPTION)) assert.ok(WarnPolicy.exceptionText(ex).length > 0, ex);
    });
});

describe("brand on an open platform — shared library (v3.5.2)", () => {
    test("brandOnPlatform: impersonation yes, org page and ordinary sites no", () => {
        assert.deepEqual(DeliveryPatterns.brandOnPlatform("paypal-login.vercel.app", "vercel.app"), { keyword: "paypal" });
        assert.equal(DeliveryPatterns.brandOnPlatform("microsoft.github.io", "github.io"), null);
        assert.deepEqual(DeliveryPatterns.brandOnPlatform("microsoft-support.github.io", "github.io"), { keyword: "microsoft" });
        assert.equal(DeliveryPatterns.brandOnPlatform("my-blog.github.io", "github.io"), null);
        assert.equal(DeliveryPatterns.brandOnPlatform("paypal.com", "vercel.app"), null);
    });
    test("open platforms are dev hosting only — dynamic DNS is not softened", () => {
        assert.equal(DeliveryPatterns.isOpenPlatform("vercel.app"), true);
        assert.equal(DeliveryPatterns.isOpenPlatform("duckdns.org"), false);
    });
    test("Check 28: a download from paypal-login.vercel.app gets PlatformBrand and an impersonation exception", () => {
        const host = "paypal-login.vercel.app";
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: { score: 0, label: "" }, domainHit: SuspiciousDomains.lookup(host),
            tldHit: null, hostListHit: null, sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: `https://${host}/invoice.exe`, fileType: "executable", filename: "invoice.exe", fpLevel: "MEDIUM" });
        const pb = r.breakdown.find(b => b.source === "PlatformBrand");
        assert.equal(pb?.score, SCORING_CONFIG.LOOKALIKE_SITE_SCORE);
        assert.ok(WarnPolicy.exceptionsFound(CHECK.DOWNLOAD, r.breakdown).includes(EXCEPTION.IMPERSONATION));
    });
});

describe("RDAP age constants (single source, v3.5.2)", () => {
    test("scoreAge uses APP's cut-points and scores", () => {
        assert.equal(RdapProtection.scoreAge(APP.RDAP_YOUNG_DAYS).score, APP.RDAP_YOUNG_SCORE);
        assert.equal(RdapProtection.scoreAge(APP.RDAP_YOUNG_DAYS + 1).score, APP.RDAP_RECENT_SCORE);
        assert.equal(RdapProtection.scoreAge(APP.RDAP_RECENT_DAYS + 1).score, 0);
        assert.equal(RdapProtection.scoreAge(null).score, APP.RDAP_NO_DATE_SCORE);
    });
});
