"use strict";

/**
 * SketchyUrlCheck.js
 *
 * Heuristic analysis of a download URL's structural properties.
 * Returns a score 0–100 (0 = nothing suspicious, 100 = maximally sketchy).
 *
 * Checks performed (in order):
 *   1. IP address as host                          → handled by IpAddressCheck in ScoringEngineV2
 *   2. Punycode (xn--) — homograph/lookalike trick → SCORES.PUNYCODE
 *   3. Excessive subdomains (> 3 labels)           → SCORES.EXCESSIVE_SUBDOMAINS
 *   4. Brand impersonation in hostname             → SCORES.BRAND_IMPERSONATION per matched brand
 *   4a. Fuzzy (typo) brand impersonation           → SCORES.FUZZY_BRAND_IMPERSONATION per matched brand
 *   5. Lookalike character substitution            → SCORES.LOOKALIKE_CHAR (generic + brand normalisation)
 *   6. Opaque/parameterised download path          → SCORES.OPAQUE_PATH
 *
 * Dropped vs. original sketch:
 *   - Brand name in path  (too much noise)
 *   - Urgency words in path (too much noise)
 *   - Special characters in hostname (too much noise)
 *   - Suspicious TLD (scored as a separate host-reputation check in ScoringEngineV2)
 *
 * V2.4.1: the generic lookalike-character check (item 5) was temporarily
 * disabled because it flagged legitimate trailing-digit hostnames like
 * "download3.operacdn.com" (numbered mirrors/CDN pool servers). Fixed and
 * re-enabled — see hasLookalikeChar() below for the corrected boundary rules.
 *
 * V2.6.1: added item 4a, fuzzy (edit-distance) brand-name matching, and
 * expanded the BRANDS table from 29 to ~110 entries (Interbrand Best Global
 * Brands 2025 + Comparably Top 1000 Brands 2022). Exact substring matching
 * (item 4) only catches a correctly-spelled brand name in a suspicious
 * position; it does not catch a genuine misspelling like "gooogle.com" or
 * "microsft.com" used as the whole domain — that is what item 4a adds.
 * Scope limit: item 4a compares each hostname LABEL as a whole against each
 * brand keyword, so it catches a bare typo'd domain but not a typo combined
 * with a suffix (e.g. "micrsoft-support.com") — that would need a more
 * expensive sliding-window comparison, deliberately not implemented here to
 * keep this addition proportionate; item 4 (exact match) already covers the
 * suffix case when the brand name itself is spelled correctly.
 *
 * V3.2.0 (3P Matrix alignment §2): items 4/4a now delegate to the shared
 * util/Brands.js — the ~540-keyword merged list (was this file's own
 * ~113-entry BRANDS table plus BrandDomains.json's separately-grown
 * 22-entry list) — instead of a local table and substring match. Brands.js
 * also switches matching from bare substring (`host.includes(keyword)`) to
 * separate dot/hyphen-split WORDS, so "google" no longer matches
 * "googleusercontent" and "apple" no longer matches "pineapple" (measured
 * false-alarm rate on a 215,348-site CrUX sample: 1.05% substring -> 0.82%
 * separate-words + wholeNameOnly + fuzzy>=7 — see that module's header).
 */
import { UrlUtils } from "../util/UrlUtils.js"; // getHostname()/getRegisteredDomain() — see that file
import { Brands } from "../util/Brands.js";

export const SketchyUrlCheck = (function () {

    // ── Score weights ──────────────────────────────────────────────────────────
    // All point contributions for this file's checks, gathered here per project
    // convention (single source of truth for magic numbers, with rationale).
    const SCORES = Object.freeze({
        PUNYCODE:               30, // xn-- prefix — homograph/lookalike domain trick
        EXCESSIVE_SUBDOMAINS:   10, // hostname has > 3 dot-separated labels
        BRAND_IMPERSONATION:    15, // per matched brand keyword, on a non-canonical host
        FUZZY_BRAND_IMPERSONATION: 12, // per typo'd brand keyword — slightly lower than an
                                        // exact match since edit-distance matching is inherently
                                        // less certain (a coincidental near-miss is more plausible
                                        // than a coincidental exact substring)
        // LOOKALIKE_CHAR removed v3.2.0 — see check 5's comment in check() below.
        OPAQUE_PATH:            20  // script endpoint / query-param delivery, no visible extension
    });

    // v3.2.0 (3P Matrix alignment §0.1): how many labels IN FRONT OF THE
    // REGISTERED DOMAIN count as "excessive subdomains". Counting raw
    // dot-separated labels (the old rule, "> 3 labels total") wrongly
    // flagged every multi-label-suffix host as suspicious purely for having
    // a public suffix with more than one label — "news.bbc.co.uk" (1 real
    // subdomain label: "news") and in fact every ".co.uk"/".com.br"/etc.
    // site landed over the old threshold for no reason connected to actual
    // subdomain depth. Counting only labels before the registered domain
    // (UrlUtils.getRegisteredDomain) fixes this; 3 is unchanged as "that's
    // unusually deep for a normal download link".
    const EXCESSIVE_SUBDOMAIN_LABELS = 3;

    // ── Main function ──────────────────────────────────────────────────────────

    /**
     * Analyse a URL string for suspicious structural patterns.
     *
     * @param {string} inputUrl
     * @returns {{ score: number, signals: string[] }}
     *   score   — 0 (nothing suspicious) to 100 (maximally sketchy)
     *   signals — human-readable descriptions of triggered checks
     */
    function check(inputUrl) {
        let score     = 0;
        const signals = [];

        let url;
        try {
            url = new URL(inputUrl);
        } catch {
            // Unparseable URL — no score
            return { score: 0, signals: [] };
        }

        const host = UrlUtils.getHostname(inputUrl) || "";

        // ── 1. IP address — handled by IpAddressCheck in ScoringEngineV2 ──────

        // ── 2. Punycode ──────────────────────────────────────────────────────
        if (host.includes("xn--")) {
            score += SCORES.PUNYCODE;
            signals.push(`Punycode detected — possible lookalike domain (+${SCORES.PUNYCODE})`);
        }

        // ── 3. Excessive subdomains ──────────────────────────────────────────
        // Count only labels in front of the registered domain (v3.2.0 — see
        // EXCESSIVE_SUBDOMAIN_LABELS above for why a raw label count was wrong).
        {
            const registeredDomain = UrlUtils.getRegisteredDomain(host) || host;
            const hostLabelCount       = host ? host.split(".").length : 0;
            const registeredLabelCount = registeredDomain.split(".").length;
            const subdomainLabelCount = Math.max(0, hostLabelCount - registeredLabelCount);
            if (subdomainLabelCount >= EXCESSIVE_SUBDOMAIN_LABELS) {
                score += SCORES.EXCESSIVE_SUBDOMAINS;
                signals.push(`Excessive subdomains: ${subdomainLabelCount} levels before the registered domain (+${SCORES.EXCESSIVE_SUBDOMAINS})`);
            }
        }

        // ── 4. Brand impersonation (exact) ────────────────────────────────────
        // ── 4a. Brand impersonation (fuzzy — typo of a brand name) ────────────
        // v3.2.0 (3P Matrix alignment §2): delegates to the shared
        // util/Brands.js — see that module's header. matchBrand() already
        // skips a host that is itself a known brand domain (or subdomain),
        // so there's no separate "is this a legitimate brand host" gate
        // needed here any more (that used to be isKnownLegitimateBrandHost()
        // — now Brands.isExemptHost(), called internally by both match
        // functions below).
        const brandMatch = Brands.matchBrand(host);
        if (brandMatch) {
            score += SCORES.BRAND_IMPERSONATION;
            signals.push(`Brand impersonation: "${brandMatch.keyword}" in hostname (+${SCORES.BRAND_IMPERSONATION})`);
        } else {
            const fuzzyMatch = Brands.matchBrandFuzzy(host);
            if (fuzzyMatch) {
                score += SCORES.FUZZY_BRAND_IMPERSONATION;
                signals.push(`Possible typo of brand "${fuzzyMatch.keyword}" in hostname (+${SCORES.FUZZY_BRAND_IMPERSONATION})`);
            }
        }

        // ── 5. Generic lookalike-character substitution ──────────────────────
        // v3.2.0 (3P Matrix alignment §1): REMOVED, along with
        // SCORES.LOOKALIKE_CHAR above. Folded into the new
        // protection/LookalikeDomainCheck.js, which replaces this check plus
        // FilenameUrlHeuristics.checkBrandHomoglyph/checkLookalikeTopSite
        // with one unified, multi-step look-alike test (see that module).

        // ── 6. Opaque / parameterised download path ──────────────────────────
        // Legitimate software distribution almost always serves files with a
        // meaningful filename in the URL path (e.g. /files/setup.exe).
        // A path that ends in a script endpoint (?id=, .php, .aspx, /download)
        // with no filename extension is a common pattern for redirect-chain
        // malware delivery and drive-by downloads.
        // Skip check if the path already has a visible dangerous extension —
        // those are caught by the extension classifier, not this heuristic.
        const pathname = url.pathname.toLowerCase();
        const hasVisibleExt = /\.(exe|msi|bat|cmd|ps1|vbs|sh|py|rb|zip|rar|7z|iso|dmg|pkg|deb|rpm)$/.test(pathname);
        if (!hasVisibleExt) {
            const opaquePatterns = [
                /[?&](id|file|dl|download|token|key|hash)=/i,  // query param delivery
                /\/(download|dl|get|serve|fetch)(\/|$)/i,      // generic download endpoint
                /\.(php|aspx|asp|cfm|cgi|jsp)(\/|$|\?)/i,     // server-side script endpoint
            ];
            for (const pattern of opaquePatterns) {
                if (pattern.test(url.href)) {
                    score += SCORES.OPAQUE_PATH;
                    signals.push(`Opaque download path — file served via script or parameter (+${SCORES.OPAQUE_PATH})`);
                    break; // one signal per URL, no stacking
                }
            }
        }

        return { score: Math.max(0, Math.min(100, score)), signals };
    }

    return { check };

})();
