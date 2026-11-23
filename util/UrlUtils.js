"use strict";

/**
 * UrlUtils.js
 * Shared helpers for URL cleaning, hostname extraction, and TLD extraction.
 * Loaded as a plain script (no ES modules) so it works in both the service
 * worker (importScripts) and content pages (<script src="…">).
 */
import { PublicSuffixList } from "./PublicSuffixList.js";

export const UrlUtils = (function () {

    /**
     * Strip query string and fragment from a URL string.
     * Returns the cleaned URL string, or the original on failure.
     */
    function cleanUrl(url) {
        if (!url) return "";
        return url.split("?")[0].split("#")[0];
    }

    /**
     * Extract the hostname (lowercased) from a URL string.
     * Returns null if the URL is unparseable, or if it's an opaque-origin
     * blob: URL with no verifiable host (see below).
     *
     * blob: URLs need special handling: "blob:" is not a "special" scheme
     * per the WHATWG URL spec (unlike http/https/ftp/ws/wss/file), so the
     * standard parser never extracts an authority/host component from one —
     * new URL("blob:https://example.com/uuid").hostname is "", every time.
     * The real hostname is embedded in .pathname instead: everything after
     * "blob:" is the full inner URL (e.g. "https://example.com/uuid"). That
     * inner origin is set by the browser itself at the moment the blob was
     * created via URL.createObjectURL() — a page cannot forge a blob URL
     * claiming a different origin — so re-parsing it here is a reliable way
     * to recover the real host, not a spoofable one.
     *
     * A blob created from a sandboxed/opaque-origin context looks like
     * "blob:null/uuid" instead — .pathname is then "null/uuid", which is not
     * itself a parseable URL. That case falls through to null, the same
     * conservative "no verifiable host" result an unparseable URL gets —
     * correct, since an opaque origin genuinely has nothing to trust-list
     * against.
     */
    function getHostname(url) {
        try {
            const parsed = new URL(url);
            if (parsed.protocol === "blob:") {
                try {
                    return new URL(parsed.pathname).hostname.toLowerCase();
                } catch {
                    return null; // opaque-origin blob ("blob:null/…") — no real host to recover
                }
            }
            return parsed.hostname.toLowerCase();
        } catch {
            return null;
        }
    }

    /**
     * Extract the eTLD+1-style registered domain from a hostname, using the
     * real Public Suffix List (see util/PublicSuffixList.js for the
     * algorithm). E.g. "sub.example.co.uk" → "example.co.uk" — correctly
     * keeping all three labels, unlike the naive last-two-labels rule this
     * used to be (which wrongly returned just "co.uk").
     */
    function getRegisteredDomain(hostname) {
        if (!hostname) return null;
        return PublicSuffixList.getRegisteredDomain(hostname.toLowerCase());
    }

    /**
     * Extract the TLD (last label) from a hostname.
     * E.g. "evil.download" → "download"
     */
    function getTld(hostname) {
        if (!hostname) return null;
        const parts = hostname.split(".");
        return parts[parts.length - 1].toLowerCase();
    }

    /**
     * Encode a clean (query-stripped) URL into the base64url ID that
     * VirusTotal uses as its URL identifier.
     */
    function toVtUrlId(url) {
        const clean = cleanUrl(url);
        return btoa(
            encodeURIComponent(clean).replace(
                /%([0-9A-F]{2})/g,
                (_, hex) => String.fromCharCode(parseInt(hex, 16))
            )
        )
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
    }

    return { cleanUrl, getHostname, getRegisteredDomain, getTld, toVtUrlId };
})();
