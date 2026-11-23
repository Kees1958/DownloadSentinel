"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { UrlUtils } from "../../util/UrlUtils.js";

describe("UrlUtils.cleanUrl", () => {
    test("strips query string", () => {
        assert.equal(UrlUtils.cleanUrl("https://example.com/f.exe?x=1"), "https://example.com/f.exe");
    });
    test("strips fragment", () => {
        assert.equal(UrlUtils.cleanUrl("https://example.com/f.exe#frag"), "https://example.com/f.exe");
    });
    test("strips both, query first", () => {
        assert.equal(UrlUtils.cleanUrl("https://example.com/f.exe?x=1#frag"), "https://example.com/f.exe");
    });
    test("empty/falsy input returns empty string", () => {
        assert.equal(UrlUtils.cleanUrl(""), "");
        assert.equal(UrlUtils.cleanUrl(null), "");
        assert.equal(UrlUtils.cleanUrl(undefined), "");
    });
});

describe("UrlUtils.getHostname", () => {
    test("extracts lowercased hostname", () => {
        assert.equal(UrlUtils.getHostname("HTTPS://EXAMPLE.COM/f.exe"), "example.com");
    });
    test("returns null for unparseable URL", () => {
        assert.equal(UrlUtils.getHostname("not a url"), null);
    });
});

describe("UrlUtils.getHostname — blob: URLs", () => {
    test("unwraps a blob: URL created from a normal https page", () => {
        // Regression test for a reported bug: adding a domain to the
        // trusted-domains list had no effect on blob: downloads (e.g.
        // "blob:https://claude.ai/uuid") because "blob:" is not a special
        // scheme in the WHATWG URL spec, so new URL(...).hostname was
        // always "" for these — the real host was silently lost.
        assert.equal(
            UrlUtils.getHostname("blob:https://claude.ai/d1add171-be81-4294-b54c-7baff451866a"),
            "claude.ai"
        );
    });

    test("unwraps a blob: URL with a port", () => {
        assert.equal(UrlUtils.getHostname("blob:http://example.com:8080/abc"), "example.com");
    });

    test("unwraps a blob: URL created from a non-http origin (e.g. an extension page)", () => {
        assert.equal(UrlUtils.getHostname("blob:chrome-extension://abcdefghij/abc"), "abcdefghij");
    });

    test("a sandboxed/opaque-origin blob (blob:null/uuid) falls back to null, not a false host", () => {
        assert.equal(UrlUtils.getHostname("blob:null/12345678-1234-1234-1234-123456789012"), null);
    });

    test("non-blob URLs are unaffected", () => {
        assert.equal(UrlUtils.getHostname("https://claude.ai/file.zip"), "claude.ai");
    });
});

describe("UrlUtils.getRegisteredDomain", () => {
    // Ordinary single-label-TLD case — unchanged from before the PSL switch.
    test("plain .com domain, strips subdomain", () => {
        assert.equal(UrlUtils.getRegisteredDomain("sub.example.com"), "example.com");
    });

    // Regression test: a naive "last two labels" rule returns "co.uk" here
    // (wrong — "co.uk" isn't a registrable domain, nobody owns it), silently
    // merging every .co.uk/.com.br/etc. site into one fake shared "domain".
    // See CHANGELOG.md for the investigation (measured against the
    // real top-1M site list) that led to switching to the real Public
    // Suffix List for this.
    test("multi-label suffix (co.uk) keeps the real registrable name", () => {
        assert.equal(UrlUtils.getRegisteredDomain("sub.example.co.uk"), "example.co.uk");
    });
    test("multi-label suffix (com.br)", () => {
        assert.equal(UrlUtils.getRegisteredDomain("www.example.com.br"), "example.com.br");
    });
    test("multi-label suffix (co.jp)", () => {
        assert.equal(UrlUtils.getRegisteredDomain("www.amazon.co.jp"), "amazon.co.jp");
    });

    // A ccTLD with NO multi-label convention must NOT gain a spurious extra
    // label — e.g. .de/.nl register directly at the second level.
    test("ordinary ccTLD with no multi-label convention", () => {
        assert.equal(UrlUtils.getRegisteredDomain("www.example.de"), "example.de");
    });

    // A private/platform suffix explicitly listed in the PSL (anyone can
    // register "<name>.github.io" as if it were their own domain) —
    // something a generic "strip known TLD words" heuristic could never
    // get right without an explicit list entry.
    test("private suffix (github.io)", () => {
        assert.equal(UrlUtils.getRegisteredDomain("someuser.github.io"), "someuser.github.io");
    });

    test("hostname IS exactly a multi-label suffix — no registrable label left", () => {
        assert.equal(UrlUtils.getRegisteredDomain("co.uk"), null);
    });
    test("returns null for single-label host", () => {
        assert.equal(UrlUtils.getRegisteredDomain("localhost"), null);
    });
    test("returns null for falsy input", () => {
        assert.equal(UrlUtils.getRegisteredDomain(null), null);
    });
});

describe("UrlUtils.getTld", () => {
    test("extracts last label lowercased", () => {
        assert.equal(UrlUtils.getTld("evil.DOWNLOAD"), "download");
    });
    test("returns null for falsy input", () => {
        assert.equal(UrlUtils.getTld(null), null);
    });
});

describe("UrlUtils.toVtUrlId", () => {
    test("produces a base64url string with no padding", () => {
        const id = UrlUtils.toVtUrlId("https://example.com/file.exe");
        assert.match(id, /^[A-Za-z0-9_-]+$/);
        assert.ok(!id.includes("="));
    });
    test("strips query/fragment before encoding (same id for both)", () => {
        const a = UrlUtils.toVtUrlId("https://example.com/file.exe?x=1");
        const b = UrlUtils.toVtUrlId("https://example.com/file.exe");
        assert.equal(a, b);
    });
});
