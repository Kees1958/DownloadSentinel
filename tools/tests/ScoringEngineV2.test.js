"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { ScoringEngineV2, SCORING_CONFIG } from "../../protection/ScoringEngineV2.js";

describe("ScoringEngineV2.classifyByScore", () => {
    test("boundary cases map to the documented tiers", () => {
        assert.equal(ScoringEngineV2.classifyByScore(30), ScoringEngineV2.Classification.PROBABLY_SAFE);
        assert.equal(ScoringEngineV2.classifyByScore(29), ScoringEngineV2.Classification.PROBABLY_QUESTIONABLE);
        assert.equal(ScoringEngineV2.classifyByScore(-30), ScoringEngineV2.Classification.PROBABLY_QUESTIONABLE);
        assert.equal(ScoringEngineV2.classifyByScore(-31), ScoringEngineV2.Classification.PROBABLY_SUSPICIOUS);
        assert.equal(ScoringEngineV2.classifyByScore(-60), ScoringEngineV2.Classification.PROBABLY_SUSPICIOUS);
        assert.equal(ScoringEngineV2.classifyByScore(-61), ScoringEngineV2.Classification.PROBABLY_MALICIOUS);
    });
});

describe("ScoringEngineV2.evaluate (VT axis)", () => {
    test("hard rule: 5+ malicious detections is always Probably Malicious", () => {
        const r = ScoringEngineV2.evaluate({ stats: { malicious: 5, suspicious: 0, harmless: 10 } });
        assert.equal(r.classification, ScoringEngineV2.Classification.PROBABLY_MALICIOUS);
        assert.ok(r.hardRuleApplied);
    });

    test("hard rule: 10+ suspicious detections is always Probably Malicious", () => {
        const r = ScoringEngineV2.evaluate({ stats: { malicious: 0, suspicious: 10, harmless: 5 } });
        assert.equal(r.classification, ScoringEngineV2.Classification.PROBABLY_MALICIOUS);
    });

    test("clean file, old and well-established, scores in the safe range", () => {
        const oneYearAgo = Math.floor(Date.now() / 1000) - 365 * 86400;
        const r = ScoringEngineV2.evaluate({
            stats: { malicious: 0, suspicious: 0, harmless: 60, undetected: 10 },
            firstSubmissionDate: oneYearAgo
        });
        assert.equal(r.classification, ScoringEngineV2.Classification.PROBABLY_SAFE);
        assert.equal(r.confidence, "High");
    });

    test("clean but brand new (< 7 days) does not get the ABC consensus bonus", () => {
        const twoDaysAgo = Math.floor(Date.now() / 1000) - 2 * 86400;
        const withBonus = ScoringEngineV2.evaluate({
            stats: { malicious: 0, suspicious: 0, harmless: 60 },
            firstSubmissionDate: Math.floor(Date.now() / 1000) - 365 * 86400
        });
        const tooNew = ScoringEngineV2.evaluate({
            stats: { malicious: 0, suspicious: 0, harmless: 60 },
            firstSubmissionDate: twoDaysAgo
        });
        assert.equal(withBonus.breakdown.detection.abcLabel, "A");
        assert.equal(tooNew.breakdown.detection.abcLabel, null);
    });

    test("no data at all (unknown to VT) does not crash and yields a neutral-ish result", () => {
        const r = ScoringEngineV2.evaluate();
        assert.equal(typeof r.score, "number");
        assert.equal(r.confidence, "Low");
    });

    test("score is clamped to the documented [-100, 100] range", () => {
        const r = ScoringEngineV2.evaluate({
            stats: { malicious: 0, suspicious: 0, harmless: 100 },
            firstSubmissionDate: Math.floor(Date.now() / 1000) - 1000 * 86400
        });
        assert.ok(r.score <= 100 && r.score >= -100);
    });
});

describe("ScoringEngineV2.evaluateHostReputation", () => {
    test("DNS threat-intel block is always Probably Malicious regardless of other signals", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "BLOCKED" }],
            rdap: null, domainHit: null, tldHit: null, sketchyUrl: null,
            mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://evil.example/malware.exe"
        });
        assert.equal(r.classification, ScoringEngineV2.Classification.PROBABLY_MALICIOUS);
        assert.ok(r.hardRuleApplied);
    });

    test("no signals at all reports Probably Safe with an empty breakdown", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }],
            rdap: null, domainHit: null, tldHit: null, sketchyUrl: null,
            mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://example.com/file.exe"
        });
        assert.equal(r.classification, ScoringEngineV2.Classification.PROBABLY_SAFE);
        assert.deepEqual(r.breakdown, []);
    });

    test("IP-address host is flagged (IPv4)", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "http://203.0.113.5/file.exe"
        });
        assert.ok(r.breakdown.some(b => b.source === "IpAddressCheck"));
    });

    test("IPv6 literal host is also flagged", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "http://[2001:db8::1]/file.exe"
        });
        assert.ok(r.breakdown.some(b => b.source === "IpAddressCheck"));
    });

    test("HTTP-only penalty fires only when a configured DNS check ALLOWED the domain", () => {
        const allowed = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "http://example.com/file.exe"
        });
        assert.ok(allowed.breakdown.some(b => b.source === "ProtocolCheck"));

        const unknown = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "UNKNOWN" }], rdap: null, domainHit: null, tldHit: null,
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "http://example.com/file.exe"
        });
        assert.ok(!unknown.breakdown.some(b => b.source === "ProtocolCheck"));
    });

    test("HTTPS-to-HTTP downgrade is detected independently of the HTTP-only check", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "UNKNOWN" }], rdap: null, domainHit: null, tldHit: null,
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "http://example.com/file.exe",
            originalUrl: "https://example.com/file.exe"
        });
        assert.ok(r.breakdown.some(b => b.source === "ProtocolDowngrade"));
    });

    test("embedded URL credentials are detected via parsed fields, not string matching", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://user:pass@evil.example/file.exe"
        });
        assert.ok(r.breakdown.some(b => b.source === "UrlCredentials"));
    });

    test("an '@' inside an encoded path segment does not false-positive as credentials", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://example.com/user%40handle/file.exe"
        });
        assert.ok(!r.breakdown.some(b => b.source === "UrlCredentials"));
    });

    test("double-extension chain and script format both surface in the breakdown", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://example.com/invoice.pdf.exe",
            doubleExt: { decoy: ".pdf", dangerous: "exe", repeatedDots: false },
            isScript: true
        });
        assert.ok(r.breakdown.some(b => b.source === "DoubleExtension" && b.score === SCORING_CONFIG.DOUBLE_EXTENSION_SCORE));
        assert.ok(r.breakdown.some(b => b.source === "ScriptFormat" && b.score === SCORING_CONFIG.SCRIPT_FORMAT_SCORE));
    });

    test("suspicious domain-list hit is scaled from the 0-100 input score", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null,
            domainHit: { score: 100, matchedDomain: "evil.example" },
            tldHit: null, sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://evil.example/file.exe"
        });
        const hit = r.breakdown.find(b => b.source === "DomainList");
        assert.ok(hit);
        assert.equal(hit.score, SCORING_CONFIG.HOST_DOMAIN_BASE_SCORE); // 100% of base
    });

    test("v2.7.0: HostList hit is scaled from the 0-100 input score, same pattern as DomainList", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            hostListHit: { score: 60, matchedDomain: "evil-dyndns.example", source: "HaGeZi-DynDNS" },
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://evil-dyndns.example/file.exe"
        });
        const hit = r.breakdown.find(b => b.source === "HostList");
        assert.ok(hit);
        assert.equal(hit.score, Math.round((60 / 100) * SCORING_CONFIG.HOST_LIST_BASE_SCORE));
    });

    test("v2.7.0: HostList hit alone stays in the moderate range, not malicious", () => {
        // Per the heuristics plan, Step 1: "a list hit alone stays moderate;
        // it becomes decisive only combined with other signals (Step 3)".
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            hostListHit: { score: 60, matchedDomain: "evil-dyndns.example", source: "HaGeZi-DynDNS" },
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://evil-dyndns.example/file.exe"
        });
        assert.notEqual(r.classification, ScoringEngineV2.Classification.PROBABLY_MALICIOUS);
    });

    test("v2.7.0: no HostList hit contributes nothing (absence is a no-op)", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            hostListHit: null,
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://example.com/file.exe"
        });
        assert.ok(!r.breakdown.some(b => b.source === "HostList"));
    });

    test("v2.8.0: StagingKeywords hit is scaled from the 0-100 input score, same pattern as DomainList", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            stagingKeywords: { score: 70, signals: ["Lure word group: PIRACY (+35)"] },
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://free-host.example.net/keygen.exe"
        });
        const hit = r.breakdown.find(b => b.source === "StagingKeywords");
        assert.ok(hit);
        assert.equal(hit.score, Math.round((70 / 100) * SCORING_CONFIG.HOST_STAGING_BASE));
    });

    test("v2.8.0: StagingKeywords hit alone stays in the moderate range, not malicious", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            stagingKeywords: { score: 70, signals: ["Lure word group: PIRACY (+35)"] },
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://free-host.example.net/keygen.exe"
        });
        assert.notEqual(r.classification, ScoringEngineV2.Classification.PROBABLY_MALICIOUS);
    });

    test("v2.8.0: a zero-score StagingKeywords result (no signals) contributes nothing", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            stagingKeywords: { score: 0, signals: [] },
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://example.com/file.exe"
        });
        assert.ok(!r.breakdown.some(b => b.source === "StagingKeywords"));
    });

    test("v2.8.0: no StagingKeywords result contributes nothing (absence is a no-op)", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            stagingKeywords: null,
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://example.com/file.exe"
        });
        assert.ok(!r.breakdown.some(b => b.source === "StagingKeywords"));
    });

    test("v2.8.0: StagingFormat HIGH tier scores exactly SCORING_CONFIG.STAGING_FORMAT_HIGH", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            stagingFormat: { tier: "HIGH", label: "test label", source: "StagingFormat" },
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://example.com/file.xll"
        });
        const hit = r.breakdown.find(b => b.source === "StagingFormat");
        assert.ok(hit);
        assert.equal(hit.score, SCORING_CONFIG.STAGING_FORMAT_HIGH);
    });

    test("v2.8.0: StagingFormat CONTAINER_SMALL tier scores exactly SCORING_CONFIG.STAGING_CONTAINER_SMALL", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            stagingFormat: { tier: "CONTAINER_SMALL", label: "test label", source: "StagingFormat" },
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://example.com/file.iso"
        });
        const hit = r.breakdown.find(b => b.source === "StagingFormat");
        assert.ok(hit);
        assert.equal(hit.score, SCORING_CONFIG.STAGING_CONTAINER_SMALL);
    });

    test("v2.8.0: no StagingFormat result contributes nothing (absence is a no-op)", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            stagingFormat: null,
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://example.com/file.exe"
        });
        assert.ok(!r.breakdown.some(b => b.source === "StagingFormat"));
    });

    test("blob: URL host is correctly unwrapped for the IP-address and credentials checks", () => {
        // Regression test: these checks used to read parsedUrl.hostname
        // directly, which is "" for blob: URLs — silently disabling the
        // IP-host check and blanking the credentials-check label for any
        // blob: download. Now routed through UrlUtils.getHostname().
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null,
            sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "blob:http://203.0.113.5/deadbeef-1234-1234-1234-123456789012"
        });
        assert.ok(r.breakdown.some(b => b.source === "IpAddressCheck"));
    });

    test("v2.9.0: two independent signals from different families combine to a worse score than either alone", () => {
        const domainOnly = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null,
            domainHit: { score: 100, matchedDomain: "evil.example" },
            tldHit: null, sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://evil.example/malware.ps1", isScript: true
        });
        const combined = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null,
            domainHit: { score: 100, matchedDomain: "evil.example" },
            tldHit: null, sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://evil.example/malware.ps1"
        });
        // domainOnly also sets isScript (a second family, FILE_FORMAT) —
        // its combined score must be more negative than domainHit alone.
        assert.ok(domainOnly.score < combined.score);
        assert.equal(domainOnly.label, `2 heuristic risk signals detected — ${domainOnly.classification.toLowerCase()}`);
    });

    test("v2.9.0: RDAP no longer folds additively into a simultaneous DomainList hit — it is its own breakdown entry at its raw (undoubled) score", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: { score: -30, label: "registered 10 days ago" },
            domainHit: { score: 100, matchedDomain: "evil.example" },
            tldHit: null, sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://evil.example/file.exe"
        });
        const domainEntry = r.breakdown.find(b => b.source === "DomainList");
        const rdapEntry    = r.breakdown.find(b => b.source === "RDAP");
        assert.ok(domainEntry);
        assert.equal(domainEntry.score, SCORING_CONFIG.HOST_DOMAIN_BASE_SCORE); // no +rdapAdditive fold-in any more
        assert.ok(rdapEntry);
        assert.equal(rdapEntry.score, -30); // raw, not doubled — doubling only applies when RDAP is alone
    });

    test("v2.9.0: RDAP alone (no other signal) is still doubled, same as pre-v2.9.0 standalone behavior", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: { score: -30, label: "registered 10 days ago" },
            domainHit: null, tldHit: null, sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://new-domain.example/file.exe"
        });
        assert.equal(r.score, -60); // -30 * 2
    });

    test("v2.9.0: DNS threat-intel hard rule still short-circuits combination entirely, even with other signals present", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "BLOCKED" }], rdap: null,
            domainHit: { score: 100, matchedDomain: "evil.example" },
            tldHit: null, sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://evil.example/malware.exe", isScript: true
        });
        assert.equal(r.score, -100);
        assert.equal(r.classification, ScoringEngineV2.Classification.PROBABLY_MALICIOUS);
        assert.ok(r.hardRuleApplied);
    });

    test("v2.9.0: single-family label text is unchanged from v2.8.0 (no 'combined' wording)", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null,
            domainHit: { score: 100, matchedDomain: "evil.example" },
            tldHit: null, sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://evil.example/file.exe"
        });
        assert.ok(!r.label.includes("combined"));
    });
});

describe("ScoringEngineV2.evaluateHostReputation — v2.11.0 filename/URL heuristics", () => {
    const baseParams = () => ({
        dnsChecks: [{ status: "ALLOWED" }], rdap: null,
        domainHit: null, tldHit: null, sketchyUrl: null,
        mimeResult: null, sizeResult: null, riskyHosting: null,
    });

    test("RLO character in filename produces a RloObfuscation breakdown entry", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            ...baseParams(),
            url: "https://example.com/invoice.exe",
            filename: "invoice‮gpj.exe",
        });
        const entry = r.breakdown.find(b => b.source === "RloObfuscation");
        assert.ok(entry);
        assert.equal(entry.score, SCORING_CONFIG.RLO_SCORE);
    });

    test("padded double extension produces a PaddedDoubleExtension breakdown entry", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            ...baseParams(),
            url: "https://example.com/invoice.exe",
            filename: "Invoice_PDF____________________.exe",
        });
        const entry = r.breakdown.find(b => b.source === "PaddedDoubleExtension");
        assert.ok(entry);
        assert.equal(entry.score, SCORING_CONFIG.PADDED_DOUBLE_EXTENSION_SCORE);
    });

    // v3.2.0 (3P Matrix alignment §1): BrandHomoglyph is replaced by the
    // unified LookalikeDomain check — same "rn → m" bigram substitution
    // ("arnazon" → "amazon"), now produced by LookalikeDomainCheck.js and
    // reported under source "LookalikeDomain" / LOOKALIKE_BRAND_SCORE.
    test("look-alike brand host produces a LookalikeDomain breakdown entry", () => {
        // Not "arnazon.com": that exact string is a known, accepted
        // Bloom-filter false positive against the rebuilt top-100K+brand/gov
        // TopSitesFilter (test 1 — "the host itself is popular" — short-
        // circuits before the imitation checks even run). "vvellsfargo.com"
        // (vv->w) avoids the coincidence and still exercises the same
        // questionable-bigram path.
        const r = ScoringEngineV2.evaluateHostReputation({
            ...baseParams(),
            url: "https://vvellsfargo.com/invoice.exe",
        });
        const entry = r.breakdown.find(b => b.source === "LookalikeDomain");
        assert.ok(entry);
        assert.equal(entry.score, SCORING_CONFIG.LOOKALIKE_BRAND_SCORE);
    });

    test("the real brand domain is never flagged as a look-alike", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            ...baseParams(),
            url: "https://www.amazon.com/invoice.exe",
        });
        assert.equal(r.breakdown.find(b => b.source === "LookalikeDomain"), undefined);
    });

    test("a URL-shortener host produces a mild UrlShortener breakdown entry", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            ...baseParams(),
            url: "https://bit.ly/invoice.exe",
        });
        const entry = r.breakdown.find(b => b.source === "UrlShortener");
        assert.ok(entry);
        assert.equal(entry.score, SCORING_CONFIG.URL_SHORTENER_SCORE);
    });

    test("a mismatched referrer produces a weak ReferrerMismatch breakdown entry", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            ...baseParams(),
            url: "https://cdn.other-example.net/invoice.exe",
            referrer: "https://totally-unrelated-site.example/page",
        });
        const entry = r.breakdown.find(b => b.source === "ReferrerMismatch");
        assert.ok(entry);
        assert.equal(entry.score, SCORING_CONFIG.REFERRER_MISMATCH_SCORE);
    });

    test("no referrer supplied → no ReferrerMismatch entry, no crash (defensive null handling)", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            ...baseParams(),
            url: "https://example.com/invoice.exe",
        });
        assert.equal(r.breakdown.find(b => b.source === "ReferrerMismatch"), undefined);
    });

    test("none of the five heuristics fire on a completely clean download", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            ...baseParams(),
            url: "https://example.com/invoice.exe",
            filename: "invoice.exe",
            referrer: "https://example.com/download-page",
        });
        for (const source of ["RloObfuscation", "PaddedDoubleExtension", "LookalikeDomain", "UrlShortener", "ReferrerMismatch"]) {
            assert.equal(r.breakdown.find(b => b.source === source), undefined, `unexpected ${source} entry`);
        }
        assert.equal(r.classification, ScoringEngineV2.Classification.PROBABLY_SAFE);
    });
});

describe("ScoringEngineV2.evaluateHostReputation — Check 10b: RiskyHosting solo mitigation", () => {
    const baseParams = () => ({
        dnsChecks: [{ status: "ALLOWED" }], rdap: null,
        domainHit: null, tldHit: null, sketchyUrl: null,
        mimeResult: null, sizeResult: null,
    });

    test("RiskyHosting alone (nothing else at all) is halved", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            ...baseParams(),
            riskyHosting: { score: -25, label: "Hosted on a known free/risky hosting platform" },
            url: "https://downloads.sourceforge.net/project/x/x.exe",
        });
        const entry = r.breakdown.find(b => b.source === "RiskyHosting");
        assert.ok(entry);
        assert.equal(entry.score, Math.round(-25 / SCORING_CONFIG.RISKY_HOSTING_SOLO_DIVISOR));
        assert.match(entry.label, /halved/);
    });

    test("a weak signal below the stacking floor (e.g. dots/hyphens) does NOT block the halving", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            ...baseParams(),
            sketchyUrl: { score: -3, label: "Excessive use of dots and hyphens" },
            riskyHosting: { score: -25, label: "Hosted on a known free/risky hosting platform" },
            url: "https://downloads.sourceforge.net/project/x-y-z/x.exe",
        });
        const entry = r.breakdown.find(b => b.source === "RiskyHosting");
        assert.equal(entry.score, Math.round(-25 / SCORING_CONFIG.RISKY_HOSTING_SOLO_DIVISOR));
    });

    test("a signal at or above the stacking floor (e.g. a MIME mismatch) blocks the halving", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            ...baseParams(),
            mimeResult: { score: -40, ext: "exe", mime: "text/plain" },
            riskyHosting: { score: -25, label: "Hosted on a known free/risky hosting platform" },
            url: "https://downloads.sourceforge.net/project/x/x.exe",
        });
        const entry = r.breakdown.find(b => b.source === "RiskyHosting");
        assert.equal(entry.score, -25); // full strength — not halved
        assert.ok(!entry.label.includes("halved"));
    });

    test("no RiskyHosting entry at all does not throw or add a phantom entry", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            ...baseParams(),
            riskyHosting: null,
            url: "https://example.com/invoice.exe",
        });
        assert.equal(r.breakdown.find(b => b.source === "RiskyHosting"), undefined);
    });
});

describe("ScoringEngineV2.evaluateHostReputation — v3.0.6: two-of-three DNS checks", () => {
    test("either configured check reporting BLOCKED is a hard rule, and the label names which provider", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [
                { status: "ALLOWED", provider: "quad9", providerLabel: "Quad9" },
                { status: "BLOCKED", provider: "controld", providerLabel: "Control D (malware)" },
            ],
            rdap: null, domainHit: null, tldHit: null, sketchyUrl: null,
            mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://evil.example/malware.exe"
        });
        assert.equal(r.classification, ScoringEngineV2.Classification.PROBABLY_MALICIOUS);
        assert.ok(r.hardRuleApplied.includes("Control D (malware)"));
    });

    test("both checks ALLOWED — RDAP/HTTP gating still fires (dnsResolved is true)", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [
                { status: "ALLOWED", provider: "quad9", providerLabel: "Quad9" },
                { status: "ALLOWED", provider: "controld", providerLabel: "Control D (malware)" },
            ],
            rdap: null, domainHit: null, tldHit: null, sketchyUrl: null,
            mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "http://example.com/file.exe"
        });
        assert.ok(r.breakdown.some(b => b.source === "ProtocolCheck"));
    });

    test("first check UNKNOWN, second ALLOWED — still counts as resolved (at least one ALLOWED is enough)", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [
                { status: "UNKNOWN", provider: "quad9", providerLabel: "Quad9" },
                { status: "ALLOWED", provider: "controld", providerLabel: "Control D (malware)" },
            ],
            rdap: null, domainHit: null, tldHit: null, sketchyUrl: null,
            mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "http://example.com/file.exe"
        });
        assert.ok(r.breakdown.some(b => b.source === "ProtocolCheck"));
    });

    test("a SKIPPED entry (second check set to None) is ignored, not treated as a resolved/blocked signal", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [
                { status: "ALLOWED", provider: "quad9", providerLabel: "Quad9" },
                { status: "SKIPPED", provider: "none", providerLabel: null },
            ],
            rdap: null, domainHit: null, tldHit: null, sketchyUrl: null,
            mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "http://example.com/file.exe"
        });
        assert.ok(r.breakdown.some(b => b.source === "ProtocolCheck")); // the one real ALLOWED check still gates it open
        // never a hard rule from the SKIPPED slot: the HTTP signal alone decides
        // (expectation derived from the constant — v3.4.0 weight review changed it)
        assert.equal(r.score, SCORING_CONFIG.HTTP_PENALTY);
        assert.equal(r.classification, ScoringEngineV2.classifyByScore(SCORING_CONFIG.HTTP_PENALTY));
    });

    test("neither check ALLOWED (both UNKNOWN) — RDAP/HTTP gating stays closed, matching the old single-Quad9-UNKNOWN behavior", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [
                { status: "UNKNOWN", provider: "quad9", providerLabel: "Quad9" },
                { status: "UNKNOWN", provider: "controld", providerLabel: "Control D (malware)" },
            ],
            rdap: null, domainHit: null, tldHit: null, sketchyUrl: null,
            mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "http://example.com/file.exe"
        });
        assert.ok(!r.breakdown.some(b => b.source === "ProtocolCheck"));
    });

    test("legacy single `quad9` param still works unchanged (backward compatibility)", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            quad9: { status: "BLOCKED" },
            rdap: null, domainHit: null, tldHit: null, sketchyUrl: null,
            mimeResult: null, sizeResult: null, riskyHosting: null,
            url: "https://evil.example/malware.exe"
        });
        assert.equal(r.classification, ScoringEngineV2.Classification.PROBABLY_MALICIOUS);
    });
});

describe("ScoringEngineV2.evaluateFromAnalysisResults", () => {
    test("composes getRawStats + filterResults + evaluate and returns all three", () => {
        const results = {
            "BitDefender": { category: "malicious" },
            "Kaspersky":   { category: "harmless" }
        };
        const r = ScoringEngineV2.evaluateFromAnalysisResults(results, "NONE", null);
        assert.ok(r.eval);
        assert.ok(r.raw);
        assert.ok(r.filtered);
        assert.equal(r.raw.malicious, 1);
        assert.equal(r.filtered.malicious, 1); // NONE level does no filtering
        assert.equal(typeof r.eval.score, "number");
    });

    test("matches calling the three steps manually (no behavior change from the pre-extraction version)", () => {
        const results = { "Sophos": { category: "suspicious" }, "ESET-NOD32": { category: "harmless" } };
        const combined = ScoringEngineV2.evaluateFromAnalysisResults(results, "HIGH", 1000000000);
        // manual equivalent
        const manualEval = ScoringEngineV2.evaluate({
            stats: { malicious: 0, suspicious: 1, harmless: 1, undetected: 0 },
            rawStats: { malicious: 0, suspicious: 1, harmless: 1, undetected: 0 },
            firstSubmissionDate: 1000000000,
            fpLevel: "HIGH"
        });
        assert.equal(combined.eval.score, manualEval.score);
        assert.equal(combined.eval.classification, manualEval.classification);
    });
});
