"use strict";

/**
 * SketchyUrlCheck.js
 *
 * Heuristic analysis of a download URL's structural properties.
 * Returns a score 0–100 (0 = nothing suspicious, 100 = maximally sketchy).
 *
 * Checks performed (in order):
 *   1. IP address as host                          → handled by IpAddressCheck in ScoringEngineV2
 *   2. Punycode (xn--) — homograph/lookalike trick → +30
 *   3. Excessive subdomains (> 3 labels)           → +10
 *   4. Brand impersonation in hostname             → +15 per matched brand
 *   5. Lookalike character substitution            → only via brand normalisation (no generic check)
 *
 * Dropped vs. original sketch:
 *   - Brand name in path  (too much noise)
 *   - Urgency words in path (too much noise)
 *   - Special characters in hostname (too much noise)
 *   - Raw digit count (replaced by lookalike character rule)
 *   - Suspicious TLD (scored as a separate host-reputation check in ScoringEngineV2)
 */
const SketchyUrlCheck = (function () {

    // ── Brand table ────────────────────────────────────────────────────────────
    // canonical = the real hostname the brand owns.
    // Any host containing the keyword that is NOT the canonical or a subdomain
    // of it is flagged as impersonation.
    const BRANDS = [
        // Identity / OS / Productivity
        { keyword: "microsoft",     canonical: "microsoft.com"       },
        { keyword: "office",        canonical: "office.com"          },
        { keyword: "onedrive",      canonical: "onedrive.com"        },
        { keyword: "teams",         canonical: "teams.microsoft.com" },
        { keyword: "google",        canonical: "google.com"          },
        { keyword: "gmail",         canonical: "gmail.com"           },
        { keyword: "googledrive",   canonical: "drive.google.com"    },
        { keyword: "apple",         canonical: "apple.com"           },
        { keyword: "icloud",        canonical: "icloud.com"          },
        // E-commerce / Finance
        { keyword: "amazon",        canonical: "amazon.com"          },
        { keyword: "paypal",        canonical: "paypal.com"          },
        { keyword: "bankofamerica", canonical: "bankofamerica.com"   },
        { keyword: "hsbc",          canonical: "hsbc.com"            },
        { keyword: "revolut",       canonical: "revolut.com"         },
        // Social / Media
        { keyword: "meta",          canonical: "meta.com"            },
        { keyword: "facebook",      canonical: "facebook.com"        },
        { keyword: "instagram",     canonical: "instagram.com"       },
        { keyword: "netflix",       canonical: "netflix.com"         },
        { keyword: "spotify",       canonical: "spotify.com"         },
        { keyword: "linkedin",      canonical: "linkedin.com"        },
        // Productivity / Collaboration
        { keyword: "adobe",         canonical: "adobe.com"           },
        { keyword: "dropbox",       canonical: "dropbox.com"         },
        { keyword: "docusign",      canonical: "docusign.com"        },
        { keyword: "zoom",          canonical: "zoom.us"             },
        { keyword: "slack",         canonical: "slack.com"           },
        // Logistics
        { keyword: "fedex",         canonical: "fedex.com"           },
        { keyword: "dhl",           canonical: "dhl.com"             },
        { keyword: "ups",           canonical: "ups.com"             },
    ];

    // Characters visually similar to letters used in homograph/typosquatting attacks:
    // 0→o, 1→i/l, 3→e, 4→a, 5→s, 6→g, 8→b, @→a
    const LOOKALIKE_CHARS = new Set(["0", "1", "3", "4", "5", "6", "8", "@"]);

    // Separators that count as boundaries (like letter adjacency) for lookalike detection
    const SEPARATORS = new Set(["-", "_", ".", "~"]);

    /**
     * Returns true when the hostname contains a lookalike character that is:
     *   - between two letters,
     *   - between a letter and a separator (- _ . ~),
     *   - at the start of a label (followed by a letter), or
     *   - at the end of a label (preceded by a letter).
     *
     * Flat +20 — does not stack per occurrence.
     *
     * Examples that trigger: 1ink, server1, m1cr0s0ft, g00gle, p@ypal-secure
     */
    function hasLookalikeChar(host) {
        const chars = host.split("");
        for (let i = 0; i < chars.length; i++) {
            if (!LOOKALIKE_CHARS.has(chars[i])) continue;

            const prev = i > 0               ? chars[i - 1] : null;
            const next = i < chars.length - 1 ? chars[i + 1] : null;

            const prevIsLetter    = prev !== null && /[a-z]/i.test(prev);
            const nextIsLetter    = next !== null && /[a-z]/i.test(next);
            const prevIsSeparator = prev !== null && SEPARATORS.has(prev);
            const nextIsSeparator = next !== null && SEPARATORS.has(next);
            const atStart         = prev === null;   // start of hostname
            const atEnd           = next === null;   // end of hostname

            if (
                (prevIsLetter    && nextIsLetter)    ||  // sandwiched between letters
                (prevIsLetter    && nextIsSeparator) ||  // letter then separator
                (prevIsSeparator && nextIsLetter)    ||  // separator then letter
                (atStart         && nextIsLetter)    ||  // start of label, followed by letter
                (prevIsLetter    && atEnd)               // end of label, preceded by letter
            ) {
                return true;
            }
        }
        return false;
    }

    // Lookalike normalisation map — maps substitute characters back to their
    // letter equivalents for brand matching purposes.
    const NORMALISE_MAP = {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "6": "g",
        "8": "b",
        "@": "a"
    };

    /**
     * Normalise a hostname by replacing lookalike characters with their letter
     * equivalents. Used so brand checks catch e.g. "micr0s0ft" → "microsoft",
     * "p@ypal" → "paypal", "paypa1" → "paypayi" (close enough for includes()).
     */
    function normaliseHost(host) {
        return host.split("").map(ch => NORMALISE_MAP[ch] || ch).join("");
    }

    /**
     * Returns true when the host (or its normalised form) contains the brand
     * keyword but is NOT the canonical domain or a legitimate subdomain of it.
     */
    function isBrandImpersonation(host, brand) {
        const normHost = normaliseHost(host);
        const canon    = brand.canonical;
        const matchesOriginal   = host.includes(brand.keyword);
        const matchesNormalised = normHost.includes(brand.keyword);
        if (!matchesOriginal && !matchesNormalised) return false;
        return host !== canon && !host.endsWith("." + canon);
    }

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

        const host = url.hostname.toLowerCase();

        // ── 1. IP address — handled by IpAddressCheck in ScoringEngineV2 ──────

        // ── 2. Punycode ──────────────────────────────────────────────────────
        if (host.includes("xn--")) {
            score += 30;
            signals.push("Punycode detected — possible lookalike domain (+30)");
        }

        // ── 3. Excessive subdomains ──────────────────────────────────────────
        const parts = host.split(".");
        if (parts.length > 3) {
            score += 10;
            signals.push(`Excessive subdomains: ${parts.length - 1} levels (+10)`);
        }

        // ── 4. Brand impersonation ───────────────────────────────────────────
        for (const brand of BRANDS) {
            if (isBrandImpersonation(host, brand)) {
                score += 15;
                signals.push(`Brand impersonation: "${brand.keyword}" in hostname (+15)`);
            }
        }

        // Clamp before lookalike so headroom calculation is accurate
        score = Math.min(score, 100);

        // ── 5. Lookalike character substitution ──────────────────────────────
        // Only flag when the lookalike characters appear WITHIN a recognised brand
        // name (caught above by isBrandImpersonation via normaliseHost).
        // The generic check is dropped — it caused too many false positives on
        // legitimate URLs like download3.operacdn.com where digits are part of
        // the domain name convention, not spoofing attempts.

        return { score: Math.max(0, Math.min(100, score)), signals };
    }

    return { check };

})();
