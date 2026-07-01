"use strict";

/**
 * RdapProtection.js
 * Checks the registration age of a domain via RDAP.
 * Only called when Quad9 resolves the domain (status ALLOWED).
 *
 * Age scoring rules (mirrors VT's first-seen age logic but uses 30 days
 * as the primary cut-point instead of 7 days, since registration date
 * is a slower-moving signal than "first seen by VT"):
 *
 *   < 30 days old  →  −30  (very new domain, strong signal)
 *   30–90 days old →  −10  (moderately new)
 *   > 90 days old  →    0  (neutral; established domain)
 *
 * Adapted from CallRDAP.js for use as a plain importScripts() module.
 */
const RdapProtection = (function () {

    const RDAP_URL  = "https://rdap.org/domain";
    const TIMEOUT_MS = 8000;

    /**
     * Fetch registration date for a domain via RDAP.
     * @param {string} domain  - Registered domain (e.g. "example.com")
     * @param {AbortSignal} signal
     */
    async function fetchAge(domain, signal) {
        const response = await fetch(
            `${RDAP_URL}/${encodeURIComponent(domain)}`,
            { signal }
        );

        if (!response.ok) {
            return { status: "UNKNOWN", reason: `RDAP lookup failed (${response.status})` };
        }

        const rdap = await response.json();

        const regEvent = rdap.events?.find(
            e => e.eventAction === "registration" || e.eventAction === "registered"
        );

        if (!regEvent?.eventDate) {
            return { status: "UNKNOWN", reason: "Registration date unavailable" };
        }

        const registeredDate = new Date(regEvent.eventDate);
        const ageDays = Math.floor((Date.now() - registeredDate.getTime()) / 86400000);

        return {
            status: ageDays < 30 ? "YOUNG_DOMAIN" : "ESTABLISHED_DOMAIN",
            registered: regEvent.eventDate,
            ageDays
        };
    }

    /**
     * Score registration age using the 30-day cut-point scheme.
     *
     * @param {number|null} ageDays
     * @returns {{ score: number, label: string }}
     */
    function scoreAge(ageDays) {
        if (ageDays === null || ageDays === undefined) {
            return { score: 0, label: "Registration age unknown" };
        }

        const days = Math.max(0, Math.floor(ageDays));

        if (ageDays > 90) return { score:   0, label: `${days} days old (established)` };
        if (ageDays > 30) return { score: -10, label: `${days} days old (moderately new)` };
        return               { score: -30, label: `${days} days old (very new domain)` };
    }

    /**
     * Public API: look up registration age for a domain with a hard timeout.
     *
     * Returns:
     *   { status, score, label, registered?, ageDays? }
     */
    async function check(domain) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort("timeout"), TIMEOUT_MS);

        try {
            const result = await fetchAge(domain, controller.signal);
            clearTimeout(timer);

            if (result.status === "UNKNOWN") {
                return { status: "UNKNOWN", score: 0, label: result.reason || "RDAP data unavailable" };
            }

            const aged = scoreAge(result.ageDays);

            return {
                status:     result.status,
                score:      aged.score,
                label:      aged.label,
                registered: result.registered,
                ageDays:    result.ageDays
            };

        } catch (err) {
            clearTimeout(timer);
            if (err.name === "AbortError") {
                return { status: "UNKNOWN", score: 0, label: "RDAP check timed out" };
            }
            return { status: "UNKNOWN", score: 0, label: `RDAP error: ${err.message}` };
        }
    }

    /** Expose scoreAge so ScoringEngineV2 can use it for domain-list/TLD checks */
    return { check, scoreAge };
})();
