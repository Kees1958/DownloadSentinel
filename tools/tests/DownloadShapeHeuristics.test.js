"use strict";

// v3.4.0 — heuristics R1 (extensionless generic binary), R2 (risky host,
// reached through R1) and R4 (visible extension vs MIME type).
// Pure-module tests plus one checkHostReputation() run with the network
// stubbed to fail (DNS/RDAP then report "unknown", which scores neutral).

import { test, describe, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { FilenameAnalysis } from "../../util/FilenameAnalysis.js";
import { DangerousMimes } from "../../util/DangerousMimes.js";
import { MimeCheck } from "../../protection/MimeCheck.js";
import { ScoringEngineV2, SCORING_CONFIG } from "../../protection/ScoringEngineV2.js";
import { CombinationScoring } from "../../protection/CombinationScoring.js";
import { BrowserProtection } from "../../protection/BrowserProtection.js";
import { APP } from "../../util/AppConstants.js";
import { DownloadShape } from "../../util/DownloadShape.js";

const { FILE_TYPE } = FilenameAnalysis;

// The URLhaus sample that started this (2026-10-24): Discord CDN attachment,
// no extension in the path, served as application/octet-stream.
const DISCORD_URL = "https://cdn.discordapp.com/attachments/1561097940687265932/1561098130198495273/6962f1be0c?ex=6add066e&is=6adbb4ee&hm=a5064184";
const OCTET = "application/octet-stream";

function classify(url, filename, mime, rawUrl = url) {
    return FilenameAnalysis.classifyDownload(url, rawUrl, filename, mime);
}

describe("FilenameAnalysis.getVisibleExt", () => {
    test("ordinary extensions are visible", () => {
        assert.equal(FilenameAnalysis.getVisibleExt("report.PDF"), "pdf");
        assert.equal(FilenameAnalysis.getVisibleExt("data.json"), "json");
        assert.equal(FilenameAnalysis.getVisibleExt("clip.mp4"), "mp4");
    });
    test("no dot, a version number or a dashed tail is not an extension", () => {
        assert.equal(FilenameAnalysis.getVisibleExt("6962f1be0c"), null);
        assert.equal(FilenameAnalysis.getVisibleExt("tool-v1.2"), null);
        assert.equal(FilenameAnalysis.getVisibleExt("rg-14.1.0-x86_64-unknown-linux-musl"), null);
        assert.equal(FilenameAnalysis.getVisibleExt(""), null);
    });
});

describe("R1 — extensionless generic binary is monitored", () => {
    test("the Discord sample is classified UNKNOWN_BINARY", () => {
        const r = classify(DISCORD_URL, "", OCTET);
        assert.ok(r, "must be monitored");
        assert.equal(r.fileType, FILE_TYPE.UNKNOWN_BINARY);
        assert.equal(r.isUnknownBinary, true);
        assert.equal(r.ext, null);
        assert.equal(r.visibleExt, null);
    });
    test("every GENERIC_BINARY_MIMES entry triggers it, case and parameters ignored", () => {
        for (const mime of DangerousMimes.GENERIC_BINARY_MIMES) {
            const r = classify("https://example.com/f/abc123", "abc123", mime.toUpperCase() + "; charset=binary");
            assert.equal(r?.fileType, FILE_TYPE.UNKNOWN_BINARY, mime);
        }
    });
    test("a Linux release binary with a dashed name is monitored too (warn, never block)", () => {
        const url = "https://github.com/x/y/releases/download/v1/tool-linux-amd64";
        assert.equal(classify(url, "tool-linux-amd64", OCTET)?.fileType, FILE_TYPE.UNKNOWN_BINARY);
    });
    test("an unnamed URL of an ordinary file is NOT monitored once its name is visible", () => {
        assert.equal(classify("https://cdn.example.com/a1b2c3", "clip.mp4", OCTET), null);
        assert.equal(classify("https://example.com/files/clip.mp4", "", OCTET), null);
    });
    test("an unknown MIME at onCreated never triggers R1 (late entry decides later)", () => {
        assert.equal(classify(DISCORD_URL, "", ""), null);
    });
    test("a specific, non-generic MIME without extension is not R1", () => {
        assert.equal(classify("https://example.com/x/abc", "abc", "image/png"), null);
    });
    test("an extension anywhere (filename, final or original URL) prevents R1", () => {
        assert.equal(classify("https://example.com/dl?id=1", "notes.txt", OCTET), null);
        assert.equal(classify("https://example.com/redirect", "", OCTET, "https://example.com/notes.txt"), null);
    });
    test("a dangerous extension stays EXECUTABLE (R1 only covers the extensionless case)", () => {
        const r = classify("https://example.com/setup.exe", "setup.exe", OCTET);
        assert.equal(r.fileType, FILE_TYPE.EXECUTABLE);
        assert.equal(r.isUnknownBinary, false);
    });
});

describe("R4 — visible extension vs MIME type", () => {
    test("invoice.pdf served as an executable type keeps the visible extension for MimeCheck", () => {
        const r = classify("https://example.com/invoice.pdf", "invoice.pdf", "application/x-msdownload");
        assert.equal(r.fileType, FILE_TYPE.EXECUTABLE);
        assert.equal(r.ext, null);
        assert.equal(r.visibleExt, "pdf");
        assert.equal(MimeCheck.checkMime(r.ext || r.visibleExt, r.mime).score, SCORING_CONFIG.MIME_MISMATCH_SCORE);
    });
    test("invoice.pdf served as an archive type is now monitored as ARCHIVE", () => {
        const r = classify("https://example.com/invoice.pdf", "invoice.pdf", "application/zip");
        assert.equal(r?.fileType, FILE_TYPE.ARCHIVE);
        assert.equal(r.isMimeArchive, true);
        assert.equal(MimeCheck.checkMime(r.visibleExt, r.mime).consistent, false);
    });
    test("an archive MIME that matches the visible extension adds nothing new", () => {
        const r = classify("https://example.com/b.zip", "b.zip", "application/zip");
        assert.equal(r.isArchive, true);
        assert.equal(r.isMimeArchive, false);
    });
    test("zip-based formats served as application/zip are not a mismatch (fp-sweep wheel case)", () => {
        assert.equal(classify("https://files.pythonhosted.org/p/requests-2.32.3-py3-none-any.whl",
            "requests-2.32.3-py3-none-any.whl", "application/zip"), null);
        assert.equal(classify("https://example.com/report.docx", "report.docx", "application/x-zip-compressed"), null);
        assert.equal(classify("https://example.com/book.epub", "book.epub", "application/zip"), null);
        assert.equal(MimeCheck.checkMime("docx", "application/zip").consistent, true);
    });
    test("ARCHIVE_MIMES is derived from the MIME table (zip in, pdf out)", () => {
        assert.ok(DangerousMimes.ARCHIVE_MIMES.has("application/zip"));
        assert.ok(!DangerousMimes.ARCHIVE_MIMES.has("application/pdf"));
    });
    test("generic labels are neutral in MimeCheck — force-download no longer a false mismatch", () => {
        assert.equal(MimeCheck.checkMime("exe", "application/force-download").neutral, true);
        assert.equal(MimeCheck.checkMime("exe", "binary/octet-stream").neutral, true);
        assert.equal(MimeCheck.checkMime("sh", "text/plain").neutral, true);
    });
});

describe("Check 26 — ExtensionlessBinary in the host score", () => {
    const baseParams = () => ({
        dnsChecks: [{ status: "ALLOWED" }], rdap: null,
        domainHit: null, tldHit: null, sketchyUrl: null,
        mimeResult: null, sizeResult: null, riskyHosting: null,
        url: DISCORD_URL,
    });

    test("adds its own breakdown entry with the configured score", () => {
        const r = ScoringEngineV2.evaluateHostReputation({ ...baseParams(), fileType: FILE_TYPE.UNKNOWN_BINARY, isUnknownBinary: true });
        const entry = r.breakdown.find(b => b.source === "ExtensionlessBinary");
        assert.ok(entry);
        assert.equal(entry.score, SCORING_CONFIG.EXTENSIONLESS_BINARY_SCORE);
    });
    test("absent when the flag is off (older callers unchanged)", () => {
        const r = ScoringEngineV2.evaluateHostReputation({ ...baseParams() });
        assert.equal(r.breakdown.find(b => b.source === "ExtensionlessBinary"), undefined);
    });
    test("belongs to the FILE_DECEPTION family and is strong enough to stack", () => {
        assert.equal(CombinationScoring.FAMILY_MAP.ExtensionlessBinary, "FILE_DECEPTION");
        assert.ok(SCORING_CONFIG.EXTENSIONLESS_BINARY_SCORE <= CombinationScoring.CONFIG.STACK_MIN_SIGNAL);
    });
    test("with a Discord risky-host hit, the risky host is NOT halved and both combine", () => {
        const discord = { score: -20, label: "Download hosted on risky file sharing platform (cdn.discordapp.com)" };
        const solo = ScoringEngineV2.evaluateHostReputation({ ...baseParams(), riskyHosting: { ...discord } });
        const both = ScoringEngineV2.evaluateHostReputation({ ...baseParams(), riskyHosting: { ...discord }, fileType: FILE_TYPE.UNKNOWN_BINARY, isUnknownBinary: true });
        assert.equal(solo.breakdown.find(b => b.source === "RiskyHosting").score, -10); // halved when alone
        assert.equal(both.breakdown.find(b => b.source === "RiskyHosting").score, -20); // corroborated → full
        assert.ok(both.score < solo.score, `${both.score} should be worse than ${solo.score}`);
    });
    test("the always-warn switch is declared (default on)", () => {
        assert.equal(APP.EXTENSIONLESS_BINARY_ALWAYS_WARN, true);
    });
});

describe("DownloadShape — onChanged decisions shared by DS and 3P Matrix", () => {
    const { OUTCOME } = DownloadShape;
    function r1Record(extra = {}) {
        const c = classify(DISCORD_URL, "", OCTET);
        return { url: DISCORD_URL, originalUrl: DISCORD_URL, mime: c.mime, fileType: c.fileType,
                 visibleExt: c.visibleExt, isUnknownBinary: c.isUnknownBinary, lateEntry: false, ...extra };
    }

    test("still extensionless at completion → KEEP (R1 stays)", () => {
        assert.equal(DownloadShape.reevaluate(r1Record(), "6962f1be0c").outcome, OUTCOME.KEEP);
    });
    test("confirmed name is an ordinary file → RELEASE (no warning)", () => {
        assert.equal(DownloadShape.reevaluate(r1Record(), "holiday.mp4").outcome, OUTCOME.RELEASE);
    });
    test("confirmed name reveals an executable → BECAME_KNOWN with the new type", () => {
        const r = DownloadShape.reevaluate(r1Record(), "setup.exe");
        assert.equal(r.outcome, OUTCOME.BECAME_KNOWN);
        assert.equal(r.classified.fileType, FILE_TYPE.EXECUTABLE);
        assert.equal(r.classified.isUnknownBinary, false);
    });
    test("non-R1 and late-entry records are never touched", () => {
        assert.equal(DownloadShape.reevaluate({ fileType: FILE_TYPE.EXECUTABLE }, "x.mp4").outcome, OUTCOME.KEEP);
        assert.equal(DownloadShape.reevaluate(r1Record({ lateEntry: true }), "x.mp4").outcome, OUTCOME.KEEP);
        assert.equal(DownloadShape.reevaluate(null, "x").outcome, OUTCOME.KEEP);
    });
    test("mustAlwaysWarn follows the switch and the R1 flag only", () => {
        assert.equal(DownloadShape.mustAlwaysWarn(r1Record()), APP.EXTENSIONLESS_BINARY_ALWAYS_WARN);
        assert.equal(DownloadShape.mustAlwaysWarn({ isUnknownBinary: false }), false);
        assert.equal(DownloadShape.mustAlwaysWarn(null), false);
    });
    test("contextOf copies only the fields checkHostReputation needs", () => {
        assert.deepEqual(DownloadShape.contextOf({ visibleExt: "pdf", isUnknownBinary: 0, fpLevel: "LOW", other: 1 }),
                         { visibleExt: "pdf", isUnknownBinary: false, fpLevel: "LOW" });
        assert.deepEqual(DownloadShape.contextOf(undefined), { visibleExt: null, isUnknownBinary: false, fpLevel: null });
    });
});

describe("checkHostReputation — downloadContext end to end (network stubbed to fail)", () => {
    let originalFetch;
    beforeEach(() => {
        originalFetch = globalThis.fetch;
        globalThis.fetch = async () => { throw new Error("offline (test)"); };
    });
    afterEach(() => {
        if (originalFetch === undefined) delete globalThis.fetch;
        else globalThis.fetch = originalFetch;
    });

    test("the Discord sample gets ExtensionlessBinary + RiskyHosting", async () => {
        const c = classify(DISCORD_URL, "", OCTET);
        const r = await BrowserProtection.checkHostReputation(
            DISCORD_URL, c.fileType, c.ext, c.mime, 0, DISCORD_URL, c.isScript, null, null, false,
            "", false, null, { first: APP.DNS_NONE, second: APP.DNS_NONE },
            DownloadShape.contextOf(c));
        const sources = r.breakdown.map(b => b.source);
        assert.ok(sources.includes("ExtensionlessBinary"), sources.join(","));
        assert.ok(sources.includes("RiskyHosting"), sources.join(","));
        assert.ok(r.score < 0);
    });
    test("invoice.pdf as an executable type gets the MimeCheck mismatch (R4)", async () => {
        const url = "https://example.com/invoice.pdf";
        const c = classify(url, "invoice.pdf", "application/x-msdownload");
        const r = await BrowserProtection.checkHostReputation(
            url, c.fileType, c.ext, c.mime, 0, url, c.isScript, null, null, false,
            "invoice.pdf", false, null, { first: APP.DNS_NONE, second: APP.DNS_NONE },
            DownloadShape.contextOf(c));
        const mime = r.breakdown.find(b => b.source === "MimeCheck");
        assert.ok(mime, r.breakdown.map(b => b.source).join(","));
        assert.equal(mime.score, SCORING_CONFIG.MIME_MISMATCH_SCORE);
    });
});
