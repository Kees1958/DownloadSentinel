"use strict";

/**
 * SuspiciousTlds.js
 * Risk scores (0–100) for TLDs frequently abused in phishing, spam, and
 * malware delivery. Higher score = stronger indicator of risk.
 */
const SuspiciousTlds = (function () {

    // prettier-ignore
    const TABLE = {
        // EXTREME RISK — highly disposable / frequently abused infrastructure
        "zip":      100,
        "click":     83,
        "cfd":       83,
        "rest":      83,
        "surf":      80,

        // VERY HIGH RISK — cheap gTLDs heavily used in phishing/spam ecosystems
        "top":       73,
        "icu":       70,
        "shop":      68,
        "xyz":       65,
        "online":    65,
        "site":      65,

        // HIGH RISK — common in scams, impersonation, and malware delivery
        "mov":       60,
        "review":    60,
        "download":  58,
        "monster":   55,
        "buzz":      52,
        "fun":       50,
        "live":      50,

        // MEDIUM RISK — mixed legitimate use, but regularly abused
        "sbs":       45,
        "store":     42,
        "space":     42,
        "website":   42,
        "cloud":     40,
        "digital":   40,
        "solutions": 40,
        "info":      40,
        "agency":    38,
        "pro":       38,
        "tech":      38,
        "email":     38,
        "app":       35,
        "dev":       35
    };

    /**
     * Look up a TLD in the table.
     * @param {string} tld - Just the last label, e.g. "xyz"
     * @returns {{ score: number, tld: string } | null}
     */
    function lookup(tld) {
        if (!tld) return null;
        const t = tld.toLowerCase();
        if (TABLE[t] !== undefined) {
            return { score: TABLE[t], tld: t };
        }
        return null;
    }

    return { lookup };
})();
