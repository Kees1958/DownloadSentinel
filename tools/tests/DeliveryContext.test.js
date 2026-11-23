"use strict";

// v3.5.0 — util/DeliveryPatterns.js + protection/DeliveryContext.js:
// recognised delivery patterns ("explained"), the weak-signal cluster, the
// established-site credit, and the per-FP-level strategy. Pure modules.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { DeliveryPatterns } from "../../util/DeliveryPatterns.js";
import { DeliveryContext } from "../../protection/DeliveryContext.js";
import { CombinationScoring } from "../../protection/CombinationScoring.js";
import { ScoringEngineV2, SCORING_CONFIG } from "../../protection/ScoringEngineV2.js";

const CCLEANER = "https://bits.avcdn.net/productfamily_CCLEANER7/insttype_FREE/x";
const sig = (source, score, label = source) => ({ source, score, label });
const sources = (list) => list.map(e => e.source);

describe("DeliveryPatterns — anchors that cannot be faked by a name", () => {
    test("vendor-owned delivery hosts are recognised on whole labels", () => {
        assert.match(DeliveryPatterns.vendorOf(CCLEANER), /Gen Digital/);
        assert.equal(DeliveryPatterns.vendorOf("https://download.visualstudio.microsoft.com/x/vs.exe"), "Microsoft");
        assert.equal(DeliveryPatterns.vendorOf("https://evilavcdn.net/x"), null);          // not a label boundary
        assert.equal(DeliveryPatterns.vendorOf("https://avcdn.net.evil.top/x"), null);     // vendor name as a prefix
    });
    test("keywords never count: cdn / download / update in a name prove nothing", () => {
        for (const u of ["https://cdn-ccleaner-update.top/x", "https://download-microsoft.com/x", "https://cdn.example.com/x"]) {
            assert.equal(DeliveryPatterns.vendorOf(u), null, u);
        }
    });
    test("user-content hosts of the same companies are never vendor hosts", () => {
        for (const u of [
            "https://cdn.discordapp.com/attachments/1/2/x.exe", "https://media.discordapp.net/attachments/1/2/x.exe",
            "https://raw.githubusercontent.com/a/b/main/x.ps1", "https://objects.githubusercontent.com/x",
            "https://drive.usercontent.google.com/download?id=1", "https://storage.googleapis.com/b/x.exe",
            "https://acct.blob.core.windows.net/c/x.exe", "https://d111111abcdef8.cloudfront.net/x.exe",
        ]) assert.equal(DeliveryPatterns.vendorOf(u), null, u);
    });
    test("every vendor table entry is a bare host, never a keyword or pattern", () => {
        for (const v of DeliveryPatterns.TABLES.VENDOR_DELIVERY) {
            for (const h of v.hosts) assert.match(h, /^[a-z0-9-]+(\.[a-z0-9-]+)+$/, `${v.vendor}: ${h}`);
        }
    });
    test("message origins: chat paths only, not a vendor's own download page", () => {
        assert.equal(DeliveryPatterns.messageOriginOf("https://discord.com/channels/1/2"), "Discord chat");
        assert.equal(DeliveryPatterns.messageOriginOf("https://discord.com/download"), null);
        assert.equal(DeliveryPatterns.messageOriginOf("https://mail.google.com/mail/u/0/"), "Gmail");
        assert.equal(DeliveryPatterns.messageOriginOf("https://nam12.safelinks.protection.outlook.com/?url=x"), "Outlook Safe Links");
    });
    test("same company: matched on host labels (PSL platform suffixes too), relation only", () => {
        assert.equal(DeliveryPatterns.sameCompany("discord.com", "cdn.discordapp.com"), true);
        assert.equal(DeliveryPatterns.sameCompany("github.com", "objects.githubusercontent.com"), true);
        assert.equal(DeliveryPatterns.sameCompany("www.ccleaner.com", "bits.avcdn.net"), true);
        assert.equal(DeliveryPatterns.sameCompany("discord.com", "raw.githubusercontent.com"), false);
        assert.equal(DeliveryPatterns.sameCompany("notdiscord.com", "cdn.discordapp.com"), false);   // label boundary
        assert.equal(DeliveryPatterns.sameCompany("evil.github.io", "raw.githubusercontent.com"), false);
        assert.equal(DeliveryPatterns.sameCompany("unknown.example", "unknown.example"), false);    // unknown is never "same company"
    });
    test("mirror networks and platform download links", () => {
        assert.equal(DeliveryPatterns.mirrorNetworkOf("https://get.videolan.org/vlc/3.0.21/win64/vlc.exe"), "VideoLAN mirrors");
        assert.equal(DeliveryPatterns.platformDownloadLinkOf("https://sourceforge.net/projects/sevenzip/files/latest/download"), "SourceForge");
        assert.equal(DeliveryPatterns.platformDownloadLinkOf("https://sourceforge.net/projects/sevenzip/"), null);
    });
});

describe("DeliveryContext.apply — EXPLAIN", () => {
    test("CCleaner: referrer + hidden extension are explained at MEDIUM, shown at 0 with a reason", () => {
        const { scoring, display } = DeliveryContext.apply({
            results: [sig("ReferrerMismatch", -12), sig("HiddenExtension", -20)], url: CCLEANER, fpLevel: "MEDIUM" });
        assert.deepEqual(scoring, []);
        assert.ok(display.every(e => e.explained && e.score === 0 && /normal for Gen Digital/.test(e.label) && e.rawLabel === e.source));
        assert.deepEqual(display.map(e => e.rawScore), [-12, -20]);
    });
    test("nothing is explained at LOW / NONE — everything counts", () => {
        for (const fpLevel of ["LOW", "NONE"]) {
            const { scoring } = DeliveryContext.apply({ results: [sig("ReferrerMismatch", -12), sig("HiddenExtension", -20)], url: CCLEANER, fpLevel });
            assert.deepEqual(sources(scoring).sort(), ["HiddenExtension", "ReferrerMismatch"], fpLevel);
        }
    });
    test("any WHO problem blocks every vendor explanation", () => {
        const { scoring } = DeliveryContext.apply({
            results: [sig("ReferrerMismatch", -12), sig("HiddenExtension", -20), sig("RDAP", -30)], url: CCLEANER, fpLevel: "HIGH" });
        assert.ok(sources(scoring).includes("HiddenExtension"));
        assert.ok(sources(scoring).includes("ReferrerMismatch"));
    });
    test("WHAT the file is is never explained (a mismatch on a vendor host still counts)", () => {
        const { scoring } = DeliveryContext.apply({ results: [sig("MimeCheck", -45)], url: CCLEANER, fpLevel: "HIGH" });
        assert.deepEqual(sources(scoring), ["MimeCheck"]);
    });
    test("SourceForge's own link explains the hidden extension, but its risky-host score stays", () => {
        const { scoring } = DeliveryContext.apply({
            results: [sig("RiskyHosting", -25), sig("HiddenExtension", -20)],
            url: "https://downloads.sourceforge.net/project/sevenzip/7-Zip/24.08/7z2408-x64.exe",
            originalUrl: "https://sourceforge.net/projects/sevenzip/files/latest/download", fpLevel: "MEDIUM" });
        assert.deepEqual(sources(scoring), ["RiskyHosting"]);
    });
    test("a platform link does NOT excuse other WHO problems (young domain)", () => {
        const { scoring } = DeliveryContext.apply({
            results: [sig("RiskyHosting", -25), sig("RDAP", -30), sig("HiddenExtension", -20)],
            url: "https://downloads.sourceforge.net/x.exe", originalUrl: "https://sourceforge.net/projects/x/files/latest/download", fpLevel: "MEDIUM" });
        assert.ok(sources(scoring).includes("HiddenExtension"));
    });
    test("HTTPS→HTTP downgrade is explained only when the chain starts at a mirror network; plain HTTP still counts", () => {
        const { scoring } = DeliveryContext.apply({
            results: [sig("ProtocolDowngrade", -35), sig("ProtocolCheck", -25)],
            url: "http://ftp.snt.utwente.nl/pub/vlc.exe", originalUrl: "https://get.videolan.org/vlc/vlc.exe", fpLevel: "MEDIUM" });
        assert.deepEqual(sources(scoring), ["ProtocolCheck"]);
        const other = DeliveryContext.apply({ results: [sig("ProtocolDowngrade", -35)],
            url: "http://evil.example/x.exe", originalUrl: "https://bit.ly/x", fpLevel: "MEDIUM" });
        assert.deepEqual(sources(other.scoring), ["ProtocolDowngrade"]);
    });
    test("input array and entries are never mutated", () => {
        const results = [sig("ReferrerMismatch", -12)];
        DeliveryContext.apply({ results, url: CCLEANER, fpLevel: "MEDIUM" });
        assert.equal(results.length, 1);
        assert.equal(results[0].score, -12);
        assert.equal(results[0].explained, undefined);
    });
});

describe("DeliveryContext.apply — CLUSTER", () => {
    const trio = () => [sig("RDAP", -10), sig("ReferrerMismatch", -12), sig("MessageOrigin", -10)];
    const unknownHost = "https://download-center-app.com/files/get.php?id=1";

    test("three weak oddities from different families add up at MEDIUM", () => {
        const { scoring } = DeliveryContext.apply({ results: trio(), url: unknownHost, fpLevel: "MEDIUM" });
        const c = scoring.find(e => e.source === "WeakSignalCluster");
        assert.ok(c);
        assert.equal(c.score, -32);
        assert.deepEqual(c.meta.members.sort(), ["MessageOrigin", "RDAP", "ReferrerMismatch"]);
    });
    test("thresholds follow the strategy: HIGH needs 4, LOW needs 2", () => {
        assert.equal(DeliveryContext.apply({ results: trio(), url: unknownHost, fpLevel: "HIGH" })
            .scoring.some(e => e.source === "WeakSignalCluster"), false);
        const two = [sig("RDAP", -10), sig("ReferrerMismatch", -12)];
        assert.equal(DeliveryContext.apply({ results: two, url: unknownHost, fpLevel: "MEDIUM" })
            .scoring.some(e => e.source === "WeakSignalCluster"), false);
        assert.equal(DeliveryContext.apply({ results: two, url: unknownHost, fpLevel: "LOW" })
            .scoring.find(e => e.source === "WeakSignalCluster")?.score, -22);
    });
    test("two weak signals in ONE family are one oddity, not two", () => {
        const sameFamily = [sig("ReferrerMismatch", -12), sig("UrlShortener", -14), sig("RDAP", -10)]; // both URL_SHAPE
        assert.equal(DeliveryContext.apply({ results: sameFamily, url: unknownHost, fpLevel: "MEDIUM" })
            .scoring.some(e => e.source === "WeakSignalCluster"), false);
    });
    test("a family whose worst member is strong is not 'weak' and is not re-counted", () => {
        const r = [sig("ReferrerMismatch", -12), sig("SketchyUrl", -30), sig("RDAP", -10), sig("MessageOrigin", -10)];
        const c = DeliveryContext.apply({ results: r, url: unknownHost, fpLevel: "MEDIUM" }).scoring.find(e => e.source === "WeakSignalCluster");
        assert.equal(c, undefined); // URL_SHAPE is strong (−30) → weak families: HOST_AGE, ORIGIN = 2 < 3
    });
    test("open upload platform: one fewer needed (Discord exe: risky host + 2 weak → cluster at MEDIUM)", () => {
        const r = [sig("RiskyHosting", -20), sig("ReferrerMismatch", -12), sig("MessageOrigin", -10)];
        const c = DeliveryContext.apply({ results: r, url: "https://cdn.discordapp.com/attachments/1/2/x.exe", fpLevel: "MEDIUM" })
            .scoring.find(e => e.source === "WeakSignalCluster");
        assert.equal(c?.score, -22);
        assert.equal(c.meta.openPlatform, true);
    });
    test("the cluster sum is floored", () => {
        const many = [sig("RDAP", -14), sig("ReferrerMismatch", -14), sig("MessageOrigin", -14), sig("TldList", -14), sig("RiskyHosting", -14)];
        const c = DeliveryContext.apply({ results: many, url: unknownHost, fpLevel: "LOW" }).scoring.find(e => e.source === "WeakSignalCluster");
        assert.equal(c.score, DeliveryContext.CONFIG.WEAK_CLUSTER_FLOOR);
    });
    test("explained signals never feed the cluster", () => {
        const r = [sig("ReferrerMismatch", -12), sig("MessageOrigin", -10), sig("UrlShortener", -14)];
        assert.equal(DeliveryContext.apply({ results: r, url: CCLEANER, fpLevel: "MEDIUM" })
            .scoring.some(e => e.source === "WeakSignalCluster"), false);
    });
});

describe("DeliveryContext.creditFor", () => {
    const base = { url: "https://www.python.org/ftp/x.exe", isHttps: true, dnsResolved: true, isTopSite: true, fpLevel: "MEDIUM" };
    test("established top site with only route quirks gets the credit", () => {
        const c = DeliveryContext.creditFor({ ...base, scoring: [sig("ReferrerMismatch", -12)] });
        assert.equal(c?.score, DeliveryContext.CONFIG.ESTABLISHED_SITE_CREDIT);
    });
    test("no credit with any WHO or WHAT signal, without HTTPS/DNS/top-site, or at LOW/NONE", () => {
        assert.equal(DeliveryContext.creditFor({ ...base, scoring: [sig("MimeCheck", -45)] }), null);
        assert.equal(DeliveryContext.creditFor({ ...base, scoring: [sig("RDAP", -10)] }), null);
        assert.equal(DeliveryContext.creditFor({ ...base, scoring: [], isHttps: false }), null);
        assert.equal(DeliveryContext.creditFor({ ...base, scoring: [], dnsResolved: false }), null);
        assert.equal(DeliveryContext.creditFor({ ...base, scoring: [], isTopSite: false }), null);
        assert.equal(DeliveryContext.creditFor({ ...base, scoring: [], fpLevel: "LOW" }), null);
    });
});

describe("integration — evaluateHostReputation with the context step", () => {
    const params = (extra) => ({
        dnsChecks: [{ status: "ALLOWED" }], rdap: { score: 0, label: "established" },
        domainHit: null, tldHit: null, hostListHit: null, sketchyUrl: null, mimeResult: null, sizeResult: null, riskyHosting: null,
        fileType: "executable", filename: "ccsetup.exe", ...extra,
    });
    test("the screenshot case: CCleaner at MEDIUM is Probably Safe — same company, hidden extension explained", () => {
        const r = ScoringEngineV2.evaluateHostReputation(params({
            url: CCLEANER, referrer: "https://www.ccleaner.com/ccleaner/download", fpLevel: "MEDIUM",
            obfuscation: { type: "UNKNOWN_REVEALED", confirmedExt: "exe", fromCategory: "none", toCategory: "executable" } }));
        assert.equal(r.score, 0);
        assert.equal(r.classification, ScoringEngineV2.Classification.PROBABLY_SAFE);
        assert.deepEqual(r.breakdown.filter(b => b.explained).map(b => b.source), ["HiddenExtension"]);
        assert.equal(r.breakdown.some(b => b.source === "ReferrerMismatch"), false); // ccleaner.com ↔ avcdn.net: one company
    });
    test("Discord attachment .exe from a chat (the 2026-10-24 screenshot): no false referrer signal, C7 fires, −35", () => {
        const r = ScoringEngineV2.evaluateHostReputation(params({
            url: "https://cdn.discordapp.com/attachments/1/2/Nitro_Generator.exe", referrer: "https://discord.com/channels/1061/1077",
            riskyHosting: { score: -20, label: "Download hosted on risky file sharing platform (cdn.discordapp.com)" }, fpLevel: "MEDIUM" }));
        assert.equal(r.breakdown.some(b => b.source === "ReferrerMismatch"), false);
        assert.equal(r.breakdown.find(b => b.source === "RiskyHosting").score, -20);       // corroborated → not halved
        assert.ok(CombinationScoring.combineHostResults(r.breakdown).firedRules.includes("C7"));
        assert.equal(r.score, -35);
        assert.equal(r.classification, ScoringEngineV2.Classification.PROBABLY_SUSPICIOUS);
    });
    test("C7 needs BOTH a file-sharing host and a chat/webmail origin", () => {
        const host = [{ source: "RiskyHosting", score: -20, label: "x" }, { source: "SketchyUrl", score: -30, label: "y" }];
        assert.ok(!CombinationScoring.combineHostResults(host).firedRules.includes("C7"));
        const chat = [{ source: "MessageOrigin", score: -10, label: "x" }, { source: "SketchyUrl", score: -30, label: "y" }];
        assert.ok(!CombinationScoring.combineHostResults(chat).firedRules.includes("C7"));
    });
    test("same download at LOW keeps both signals", () => {
        const r = ScoringEngineV2.evaluateHostReputation(params({
            url: CCLEANER, referrer: "https://www.ccleaner.com/", fpLevel: "LOW",
            obfuscation: { type: "UNKNOWN_REVEALED", confirmedExt: "exe", fromCategory: "none", toCategory: "executable" } }));
        assert.equal(r.score, SCORING_CONFIG.OBFUSCATION_UNKNOWN_SCORE);
    });
    test("a webmail referrer adds the MessageOrigin signal (ORIGIN family, a ROUTE question)", () => {
        const r = ScoringEngineV2.evaluateHostReputation(params({ url: "https://x.example/a.exe", referrer: "https://mail.google.com/mail/u/0/" }));
        const m = r.breakdown.find(b => b.source === "MessageOrigin");
        assert.equal(m?.score, SCORING_CONFIG.MESSAGE_ORIGIN_SCORE);
        assert.equal(CombinationScoring.questionOf("MessageOrigin"), CombinationScoring.QUESTION.ROUTE);
    });
    test("young domain + extension hidden until landing still fires rule C2", () => {
        const r = ScoringEngineV2.evaluateHostReputation(params({
            url: "https://get-secure-update.top/dl/1", rdap: { score: -30, label: "5 days" },
            obfuscation: { type: "UNKNOWN_REVEALED", confirmedExt: "exe", fromCategory: "none", toCategory: "executable" } }));
        const combined = CombinationScoring.combineHostResults(r.breakdown);
        assert.ok(combined.firedRules.includes("C2"), combined.firedRules.join(","));
    });
    test("every source the engine can produce has a family (or is the post-combination credit)", () => {
        for (const s of ["HiddenExtension", "MessageOrigin", "WeakSignalCluster", "ExtensionlessBinary"]) {
            assert.ok(CombinationScoring.FAMILY_MAP[s], s);
        }
    });
});
