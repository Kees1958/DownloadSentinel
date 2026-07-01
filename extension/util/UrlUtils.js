"use strict";

/**
 * UrlUtils.js
 * Shared helpers for URL cleaning, hostname extraction, and TLD extraction.
 * Loaded as a plain script (no ES modules) so it works in both the service
 * worker (importScripts) and content pages (<script src="…">).
 */
const UrlUtils = (function () {

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
     * Returns null if the URL is unparseable.
     */
    function getHostname(url) {
        try {
            return new URL(url).hostname.toLowerCase();
        } catch {
            return null;
        }
    }

    /**
     * Extract the eTLD+1-style registered domain from a hostname.
     * E.g. "sub.example.co.uk" → "example.co.uk" (best-effort, 2-label fallback).
     * For our purposes a simple last-two-labels approach is sufficient.
     */
    function getRegisteredDomain(hostname) {
        if (!hostname) return null;
        const parts = hostname.split(".");
        if (parts.length < 2) return null;
        return parts.slice(-2).join(".");
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
