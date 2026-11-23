"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { DownloadTrust } from "../../util/DownloadTrust.js";

const DOMAINS = ["chromewebstore.google.com", "apps.microsoft.com", "claude.ai", "sharepoint.com"];

describe("DownloadTrust.isPageMadeDownload — v3.3.0 item 22/26", () => {
    test("a blob: URL is page-made", () => {
        assert.equal(DownloadTrust.isPageMadeDownload("blob:https://claude.ai/d1add171-be81-4294-b54c-7baff451866a"), true);
    });
    test("a sandboxed/opaque-origin blob:null URL is still page-made", () => {
        assert.equal(DownloadTrust.isPageMadeDownload("blob:null/12345678-1234-1234-1234-123456789012"), true);
    });
    test("a data: URL is page-made", () => {
        assert.equal(DownloadTrust.isPageMadeDownload("data:text/plain;base64,SGVsbG8="), true);
    });
    test("matching is case-insensitive on the scheme", () => {
        assert.equal(DownloadTrust.isPageMadeDownload("BLOB:https://claude.ai/abc"), true);
        assert.equal(DownloadTrust.isPageMadeDownload("Data:text/plain,hi"), true);
    });
    test("an ordinary https: download URL is not page-made", () => {
        assert.equal(DownloadTrust.isPageMadeDownload("https://example.com/setup.exe"), false);
    });
    test("null/undefined/empty input never throws", () => {
        assert.equal(DownloadTrust.isPageMadeDownload(null), false);
        assert.equal(DownloadTrust.isPageMadeDownload(undefined), false);
        assert.equal(DownloadTrust.isPageMadeDownload(""), false);
    });
});

describe("DownloadTrust.isTrustedDomain — v3.3.0 item 27/26, referrer fallback", () => {
    test("an ordinary https: URL matches its own host against the trusted list", () => {
        assert.equal(DownloadTrust.isTrustedDomain("https://claude.ai/some/file.pdf", DOMAINS), true);
    });

    test("a subdomain of a trusted domain also matches", () => {
        assert.equal(DownloadTrust.isTrustedDomain("https://my-team.sharepoint.com/file.docx", DOMAINS), true);
    });

    test("an untrusted host does not match", () => {
        assert.equal(DownloadTrust.isTrustedDomain("https://totally-untrusted.example/file.exe", DOMAINS), false);
    });

    test("a normal blob: URL (non-opaque origin) matches its own embedded host — no referrer needed", () => {
        assert.equal(DownloadTrust.isTrustedDomain("blob:https://claude.ai/uuid-here", DOMAINS), true);
    });

    test("a sandboxed blob:null/… download has no host of its own — falls back to the referrer", () => {
        // This is the exact bug report that motivated item 27: claude.ai's
        // sandboxed-iframe artifact downloads have no extractable host at
        // all from the URL alone, so a user's claude.ai whitelist entry
        // never matched without this fallback.
        const url = "blob:null/12345678-1234-1234-1234-123456789012";
        assert.equal(DownloadTrust.isTrustedDomain(url, DOMAINS), false); // no referrer given — can't resolve
        assert.equal(DownloadTrust.isTrustedDomain(url, DOMAINS, "https://claude.ai/chat/abc"), true); // referrer resolves it
    });

    test("a data: URL (no host at all) also falls back to the referrer", () => {
        const url = "data:application/pdf;base64,JVBERi0xLjQK";
        assert.equal(DownloadTrust.isTrustedDomain(url, DOMAINS), false);
        assert.equal(DownloadTrust.isTrustedDomain(url, DOMAINS, "https://claude.ai/chat/abc"), true);
    });

    test("an untrusted referrer does not grant trust for a hostless download", () => {
        const url = "blob:null/12345678-1234-1234-1234-123456789012";
        assert.equal(DownloadTrust.isTrustedDomain(url, DOMAINS, "https://untrusted.example/page"), false);
    });

    test("an empty/missing trusted-domains list never throws and trusts nothing", () => {
        assert.equal(DownloadTrust.isTrustedDomain("https://claude.ai/file.pdf", []), false);
        assert.equal(DownloadTrust.isTrustedDomain("https://claude.ai/file.pdf", null), false);
        assert.equal(DownloadTrust.isTrustedDomain("https://claude.ai/file.pdf", undefined), false);
    });
});
