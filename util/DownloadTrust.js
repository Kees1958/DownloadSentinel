"use strict";

/**
 * DownloadTrust.js — pure, chrome.*-free helpers for "is this download from
 * a trusted source" / "is this a page-generated (blob:/data:) download",
 * extracted out of background.js (C1 convention — same reasoning as
 * util/FilenameAnalysis.js's own header: pure logic lives here so it can be
 * unit-tested without a chrome.* mock). v3.3.0 (3P Matrix alignment item 26
 * — test coverage for items 22/27's blob:/data: page-made-download fixes).
 *
 * No shared state — background.js owns the mutable "what domains are
 * currently trusted" list (runtimeCustomDomains / runtimeTrustAiDownloads)
 * and passes it in as `doNotCheckDomains` each call.
 */
import { UrlUtils } from "./UrlUtils.js";

// v3.3.0 (3P Matrix alignment item 22) — a file the page generated itself
// (blob:/data: address — claude.ai artifacts, other web-app downloads) never
// carries a file extension in its own URL, so the "extension hidden" signal
// would otherwise fire on every single one of them. PAGE_MADE_URL_RE is the
// single source of truth for that test.
const PAGE_MADE_URL_RE = /^(?:blob|data):/i;

function isPageMadeDownload(url) {
    return PAGE_MADE_URL_RE.test(String(url || ""));
}

// v3.3.0 (3P Matrix alignment item 27) — match the file's own host first;
// when the file's own address has no host at all (a data: URL, or a
// sandboxed blob:null/… download from an iframe with no origin), fall back
// to the host of the page the download came from (referrerUrl). Without
// this fallback, a user-added trusted domain like claude.ai silently never
// matches a sandboxed artifact download — the exact bug report that
// motivated this fix.
//
// @param {string} url                  - the download's own URL
// @param {string[]} doNotCheckDomains  - the full effective trusted-domain
//        list (built-in + AI-downloads opt-in + user custom), as
//        background.js's getAllDoNotCheckDomains() returns it
// @param {string|null} [referrerUrl]   - chrome.downloads.DownloadItem.referrer
function isTrustedDomain(url, doNotCheckDomains, referrerUrl = null) {
    const hostname = UrlUtils.getHostname(url) || (referrerUrl && UrlUtils.getHostname(referrerUrl));
    if (!hostname) return false;
    return (doNotCheckDomains || []).some(d =>
        hostname === d || hostname.endsWith("." + d)
    );
}

export const DownloadTrust = { isPageMadeDownload, isTrustedDomain, PAGE_MADE_URL_RE };
