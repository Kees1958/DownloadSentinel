"use strict";

/**
 * SuspiciousDomains.js
 * Risk scores (0–100) for domains that are frequently used in malware delivery.
 * Higher score = stronger indicator of risk.
 *
 * Lookup is done against the full hostname AND the registered domain (last two labels),
 * so "raw.githubusercontent.com" is matched even if the download comes from a subdomain.
 */
const SuspiciousDomains = (function () {

    // prettier-ignore
    const TABLE = {
        // Dynamic DNS (very high signal)
        "duckdns.org":            95,
        "3322.org":               95,
        "ddns.net":               90,
        "hopto.org":              90,
        "zapto.org":              90,
        "servehttp.com":          90,
        "serveftp.com":           90,
        "sytes.net":              90,
        "myvnc.com":              90,
        "mywire.org":             90,
        "mooo.com":               90,
        "dynu.net":               85,
        "freedns.afraid.org":     85,
        "redirectme.net":         85,
        "ddns.me":                80,

        // Free hosting / serverless hosting
        "workers.dev":            85,
        "pages.dev":              85,
        "github.io":              75,
        "netlify.app":            75,
        "vercel.app":             75,
        "onrender.com":           75,
        "fly.dev":                70,
        "firebaseapp.com":        70,
        "web.app":                65,
        "glitch.me":              65,
        "surge.sh":               65,

        // Code and content hosting
        // Note: raw.githubusercontent.com, github.com, gitlab.com, bitbucket.org,
        // sourceforge.net, pastebin.com, hastebin.com are handled by RiskyHostingSites.js
        // with more nuanced scoring — not duplicated here.
        "gist.githubusercontent.com": 80,

        // File sharing
        // Note: gofile.io, transfer.sh, mediafire.com, mega.nz, dropboxusercontent.com
        // are handled by RiskyHostingSites.js — not duplicated here.
        "catbox.moe":             80,
        "pixeldrain.com":         75,
        "file.io":                70,
        "drive.google.com":       35,
        "docs.google.com":        30,

        // URL shorteners
        "is.gd":                  70,
        "tinyurl.com":            65,
        "bit.ly":                 60,
        "cutt.ly":                60,
        "rebrand.ly":             55,
        "shorturl.at":            55,
        "tiny.cc":                55,
        "rb.gy":                  50,
        "t.ly":                   50,
        "ow.ly":                  40,
        "s.id":                   40,

        // Messaging / CDN platforms
        // Note: cdn.discordapp.com and discordapp.com are handled by RiskyHostingSites.js
        "discord.com":            60,
        "t.me":                   55,
        "telegram.org":           40,

        // Additional CDN-style hosting
        "raw.githack.com":        75,
        "jsdelivr.net":           35
    };

    /**
     * Look up a hostname in the table.
     * Checks the full hostname first, then the registered domain (last two labels).
     * Returns { score, matchedDomain } or null if not found.
     */
    function lookup(hostname) {
        if (!hostname) return null;
        const h = hostname.toLowerCase();

        // Full hostname match (e.g. "raw.githubusercontent.com")
        if (TABLE[h] !== undefined) {
            return { score: TABLE[h], matchedDomain: h };
        }

        // Registered-domain match (last two labels)
        const parts = h.split(".");
        if (parts.length >= 2) {
            const reg = parts.slice(-2).join(".");
            if (TABLE[reg] !== undefined) {
                return { score: TABLE[reg], matchedDomain: reg };
            }
        }

        return null;
    }

    return { lookup };
})();
