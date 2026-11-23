"use strict";

/**
 * RdapProtection.js
 * Checks the registration age of a domain via RDAP.
 * Only called when Quad9 resolves the domain (status ALLOWED).
 *
 * Age scoring rules (values: APP.RDAP_* in util/AppConstants.js since v3.5.2;
 * mirrors VT's first-seen age logic but uses 30 days
 * as the primary cut-point instead of 7 days, since registration date
 * is a slower-moving signal than "first seen by VT"):
 *
 *   < 30 days old   →  −30  (very new domain, strong signal)
 *   30–90 days old  →  −10  (moderately new)
 *   > 90 days old   →    0  (neutral; established domain)
 *   not applicable  →    0  (v3.3.0, item 1 — the lookup is SKIPPED, not
 *       attempted and failed: a hosting-platform subdomain, or a ccTLD
 *       with no RDAP service at all. See util/DomainAge.js.)
 *   real response, no date published →  −10  (v3.2.0, item 2 — a registry
 *       that answered but didn't publish a registration date. Distinct
 *       from the lookup itself failing, below — RDAP DID answer here.)
 *   lookup failed/timed out → 0, neutral (v3.3.0, item 2 — reversed from
 *       v3.2.0's −10: rdap.org fails or times out often enough in practice
 *       that penalising every failure was too harsh. A flaky/unreachable
 *       THIRD-PARTY SERVICE is not evidence about the domain either way,
 *       unlike "the registry itself published no date," which is.)
 *
 * "DNS didn't resolve at all" is a separate, earlier gate (see
 * ScoringEngineV2's `dnsResolved` guard) and is unaffected by any of this.
 *
 * Adapted from CallRDAP.js for use as an ES module.
 */
import { APP } from "../util/AppConstants.js";
import { domainAgeNotApplicable } from "../util/DomainAge.js";

export const RdapProtection = (function () {

    const RDAP_URL   = "https://rdap.org/domain";
    const TIMEOUT_MS = APP.RDAP_TIMEOUT_MS; // defined in AppConstants.js

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
            // A real RDAP response came back, it just has no registration
            // date in it — distinct from the lookup itself failing above.
            // Scored via scoreAge(null) rather than treated as neutral —
            // see this file's header, v3.2.0.
            return { status: "NO_DATE", reason: "Registration date not published by the registry" };
        }

        const registeredDate = new Date(regEvent.eventDate);
        const ageDays = Math.floor((Date.now() - registeredDate.getTime()) / 86400000);

        return {
            status: ageDays < APP.RDAP_YOUNG_DAYS ? "YOUNG_DOMAIN" : "ESTABLISHED_DOMAIN",
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
            // v3.2.0 (3P Matrix alignment §4) — no published date is treated
            // like 31-90 days old, not as neutral. See this file's header.
            return { score: APP.RDAP_NO_DATE_SCORE, label: "registration age not published — treated as recent" };
        }

        const days = Math.max(0, Math.floor(ageDays));

        // v3.5.2 — cut-points and scores from APP (single source, shared with 3P Matrix)
        if (ageDays > APP.RDAP_RECENT_DAYS) return { score: 0, label: `${days} days old (established)` };
        if (ageDays > APP.RDAP_YOUNG_DAYS)  return { score: APP.RDAP_RECENT_SCORE, label: `${days} days old (moderately new)` };
        return { score: APP.RDAP_YOUNG_SCORE, label: `${days} days old (very new domain)` };
    }

    /**
     * Public API: look up registration age for a domain with a hard timeout.
     *
     * Returns:
     *   { status, score, label, registered?, ageDays? }
     */
    async function check(domain) {
        // v3.3.0 (item 1) — skip the network call entirely when RDAP cannot
        // give a real answer for this domain (hosting-platform subdomain, or
        // a ccTLD with no RDAP service). Neutral, not a penalty: see
        // util/DomainAge.js.
        const notApplicable = domainAgeNotApplicable(domain);
        if (notApplicable) {
            return { status: "NOT_APPLICABLE", score: 0, label: notApplicable.text };
        }

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort("timeout"), TIMEOUT_MS);

        try {
            const result = await fetchAge(domain, controller.signal);
            clearTimeout(timer);

            if (result.status === "UNKNOWN") {
                // v3.3.0 (item 2) — the RDAP lookup itself failed (non-2xx,
                // bad body) rather than answering with no date. Reversed
                // from v3.2.0: scored neutral (0), not scoreAge(null)'s -10
                // — see this file's header. `status` stays "UNKNOWN" so the
                // distinct reason is still visible in the label/diagnostics.
                return { status: "UNKNOWN", score: 0, label: result.reason || "RDAP lookup failed" };
            }

            if (result.status === "NO_DATE") {
                // Unchanged from v3.2.0 — a real response with no date
                // published IS evidence (the registry answered); still
                // scored via scoreAge(null), -10. See this file's header.
                const aged = scoreAge(null);
                return { status: "NO_DATE", score: aged.score, label: aged.label };
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
            // v3.3.0 (item 2) — a timeout or thrown fetch error is the
            // lookup failing, same as the UNKNOWN branch above: neutral
            // (0), not scoreAge(null)'s -10. Reversed from v3.2.0.
            if (err.name === "AbortError") {
                return { status: "UNKNOWN", score: 0, label: "RDAP check timed out" };
            }
            return { status: "UNKNOWN", score: 0, label: `RDAP error: ${err.message}` };
        }
    }

    /** Expose scoreAge so ScoringEngineV2 can use it for domain-list/TLD checks */
    return { check, scoreAge };
})();
