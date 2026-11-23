"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { FilenameUrlHeuristics } from "../../protection/FilenameUrlHeuristics.js";

const {
    checkRlo,
    checkPaddedDoubleExtension,
    checkUrlShortener,
    checkReferrerMismatch,
} = FilenameUrlHeuristics;

describe("FilenameUrlHeuristics.checkRlo", () => {
    test("detects U+202E (RLO) in a filename", () => {
        // classic "gpj\u202Exe.exe" style trick (content shortened for clarity)
        const r = checkRlo("invoice\u202Egpj.exe", "https://example.com/invoice.exe");
        assert.ok(r);
        assert.equal(r.location, "filename");
    });

    test("detects other bidi control characters (LRE, RLE, isolates)", () => {
        for (const ch of ["\u202A", "\u202B", "\u202D", "\u2066", "\u2067", "\u2068", "\u2069"]) {
            const r = checkRlo(`file${ch}name.exe`, "");
            assert.ok(r, `expected a hit for U+${ch.codePointAt(0).toString(16)}`);
        }
    });

    test("detects RLO in the raw URL when the filename is clean", () => {
        const r = checkRlo("clean.exe", "https://example.com/invoice\u202Egpj.exe");
        assert.ok(r);
        assert.equal(r.location, "url");
    });

    test("detects a percent-encoded RLO character in the URL", () => {
        const r = checkRlo("clean.exe", "https://example.com/invoice%E2%80%AEgpj.exe");
        assert.ok(r);
        assert.equal(r.location, "url");
    });

    test("ordinary filename and URL produce no hit", () => {
        assert.equal(checkRlo("invoice.pdf", "https://example.com/invoice.pdf"), null);
    });

    test("null/undefined/empty inputs do not throw", () => {
        assert.equal(checkRlo(null, null), null);
        assert.equal(checkRlo(undefined, undefined), null);
        assert.equal(checkRlo("", ""), null);
    });

    test("a malformed percent-encoded URL does not throw", () => {
        assert.equal(checkRlo("clean.exe", "https://example.com/%E0%A4%A"), null);
    });

    test("hostile 10k-char input (no RLO present) completes well under budget", () => {
        const hostile = "a".repeat(10000);
        const start = performance.now();
        const r = checkRlo(hostile + ".exe", `https://example.com/${hostile}`);
        const ms = performance.now() - start;
        assert.equal(r, null);
        assert.ok(ms < 50, `expected < 50ms, took ${ms.toFixed(2)}ms`);
    });
});

describe("FilenameUrlHeuristics.checkPaddedDoubleExtension", () => {
    test("detects a decoy extension padded with underscores before a dangerous extension", () => {
        const r = checkPaddedDoubleExtension("Invoice_PDF____________________.exe");
        assert.ok(r);
        assert.equal(r.decoy, "pdf");
        assert.equal(r.dangerous, "exe");
        assert.ok(r.paddingLength >= 8);
    });

    test("detects padding made of spaces", () => {
        const r = checkPaddedDoubleExtension(`invoice.pdf${" ".repeat(40)}.exe`);
        assert.ok(r);
        assert.equal(r.decoy, "pdf");
    });

    test("detects padding made of repeated dots", () => {
        const filename = "invoice.pdf" + ".".repeat(20) + ".exe";
        const r = checkPaddedDoubleExtension(filename);
        assert.ok(r);
        assert.equal(r.decoy, "pdf");
    });

    test("detects padding made of zero-width/invisible characters", () => {
        const padding = "\u200B\u200C\u200D\u2060\uFEFF".repeat(3); // 15 invisible chars
        const r = checkPaddedDoubleExtension(`invoice.pdf${padding}.exe`);
        assert.ok(r);
    });

    test("a plain double extension with NO padding is not flagged by this check (covered by getDoubleExtension instead)", () => {
        assert.equal(checkPaddedDoubleExtension("invoice.pdf.exe"), null);
    });

    test("padding shorter than the minimum threshold is not flagged", () => {
        assert.equal(checkPaddedDoubleExtension("invoice.pdf___.exe"), null);
    });

    test("no decoy-recognisable token before the padding does not fire", () => {
        // "xyz" is not in DangerousExts.DECOY — ordinary long filename, not a disguise
        assert.equal(checkPaddedDoubleExtension(`invoice_xyz${"_".repeat(20)}.exe`), null);
    });

    test("final extension not dangerous does not fire", () => {
        assert.equal(checkPaddedDoubleExtension(`invoice_pdf${"_".repeat(20)}.txt`), null);
    });

    test("null/empty/no-extension input does not throw", () => {
        assert.equal(checkPaddedDoubleExtension(null), null);
        assert.equal(checkPaddedDoubleExtension(""), null);
        assert.equal(checkPaddedDoubleExtension("noextension"), null);
        assert.equal(checkPaddedDoubleExtension("."), null);
        assert.equal(checkPaddedDoubleExtension("trailing.dot."), null);
    });

    test("handles a path-qualified filename (strips directory separators)", () => {
        const r = checkPaddedDoubleExtension(`C:\\Users\\x\\Downloads\\invoice_pdf${"_".repeat(20)}.exe`);
        assert.ok(r);
    });

    test("hostile 10k-char padding run completes well under budget and does not throw", () => {
        // Padding this long pushes the decoy token outside MAX_INPUT_LENGTH's
        // tail window, so no hit is expected here (a known, accepted limit of
        // the perf cap) — what this test guards is ReDoS/perf, not detection
        // at an unbounded length.
        const hostile = "invoice_pdf" + "_".repeat(10000) + ".exe";
        const start = performance.now();
        const r = checkPaddedDoubleExtension(hostile);
        const ms = performance.now() - start;
        assert.equal(typeof r, "object"); // null is an object — just confirms no throw/garbage type
        assert.ok(ms < 50, `expected < 50ms, took ${ms.toFixed(2)}ms`);
    });

    test("padding within the scan window (realistic but long) is still detected", () => {
        const filename = "invoice_pdf" + "_".repeat(1500) + ".exe";
        const r = checkPaddedDoubleExtension(filename);
        assert.ok(r);
        assert.equal(r.decoy, "pdf");
    });
});

// v3.2.0 (3P Matrix alignment §1): checkBrandHomoglyph/checkLookalikeTopSite
// and their test blocks are REMOVED — replaced by one unified check, now
// its own module with its own test file (see
// tools/tests/LookalikeDomainCheck.test.js).

describe("FilenameUrlHeuristics.checkUrlShortener", () => {
    test("detects a known shortener domain", () => {
        const r = checkUrlShortener("bit.ly");
        assert.ok(r);
        assert.equal(r.matchedShortener, "bit.ly");
    });

    test("detects a known shortener via a subdomain", () => {
        const r = checkUrlShortener("www.tinyurl.com");
        assert.ok(r);
    });

    test("an ordinary domain is not flagged", () => {
        assert.equal(checkUrlShortener("example.com"), null);
    });

    test("null/empty input does not throw", () => {
        assert.equal(checkUrlShortener(null), null);
        assert.equal(checkUrlShortener(""), null);
    });
});

describe("FilenameUrlHeuristics.checkReferrerMismatch", () => {
    test("flags a referrer on a clearly unrelated origin", () => {
        const r = checkReferrerMismatch("https://totally-unrelated-site.example/page", "https://cdn.other-example.net/file.exe");
        assert.ok(r);
        assert.equal(r.referrerHost, "totally-unrelated-site.example");
        assert.equal(r.finalHost, "cdn.other-example.net");
    });

    test("same host → no signal", () => {
        assert.equal(checkReferrerMismatch("https://example.com/page", "https://example.com/file.exe"), null);
    });

    test("same registered domain, different subdomain → no signal", () => {
        assert.equal(checkReferrerMismatch("https://www.example.com/page", "https://cdn.example.com/file.exe"), null);
    });

    test("missing referrer → neutral (no signal, not a penalty)", () => {
        assert.equal(checkReferrerMismatch(null, "https://example.com/file.exe"), null);
        assert.equal(checkReferrerMismatch("", "https://example.com/file.exe"), null);
        assert.equal(checkReferrerMismatch(undefined, "https://example.com/file.exe"), null);
    });

    test("missing final URL → neutral (no signal, not a penalty)", () => {
        assert.equal(checkReferrerMismatch("https://example.com/page", null), null);
        assert.equal(checkReferrerMismatch("https://example.com/page", ""), null);
    });

    test("both missing → neutral", () => {
        assert.equal(checkReferrerMismatch(null, null), null);
    });

    test("an unparsable referrer does not throw", () => {
        assert.equal(checkReferrerMismatch("not a url", "https://example.com/file.exe"), null);
    });

    test("an unparsable final URL does not throw", () => {
        assert.equal(checkReferrerMismatch("https://example.com/page", "not a url"), null);
    });

    test("a non-http(s) referrer (e.g. a browser-internal page) is ignored", () => {
        assert.equal(checkReferrerMismatch("about:blank", "https://example.com/file.exe"), null);
        assert.equal(checkReferrerMismatch("chrome://downloads/", "https://example.com/file.exe"), null);
    });
});

describe("FilenameUrlHeuristics — general robustness", () => {
    test("none of the four checks throw on completely empty/garbage input", () => {
        assert.doesNotThrow(() => checkRlo(undefined, undefined));
        assert.doesNotThrow(() => checkPaddedDoubleExtension(undefined));
        assert.doesNotThrow(() => checkUrlShortener(undefined));
        assert.doesNotThrow(() => checkReferrerMismatch(undefined, undefined));
    });
});
