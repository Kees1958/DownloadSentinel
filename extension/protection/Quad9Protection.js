"use strict";

/**
 * Quad9Protection.js
 * Checks a hostname against Quad9's malware-blocking DNS-over-HTTPS resolver.
 *
 * If Quad9 returns NXDOMAIN (Status 3) with no Authority records, the domain
 * is actively blocked by Quad9's threat-intel feed → score −100.
 *
 * Adapted from CallQuad9.js for use as a plain importScripts() module
 * (no ES module syntax).
 */
const Quad9Protection = (function () {

    const QUAD9_DOH = "https://dns.quad9.net/dns-query";
    const TIMEOUT_MS = 8000;

    /**
     * Query Quad9 DoH for a hostname.
     * @param {string} hostname
     * @param {AbortSignal} [signal]
     * @returns {Promise<{ status: "BLOCKED"|"ALLOWED"|"UNKNOWN", reason?: string, answers?: string[] }>}
     */
    async function checkHostname(hostname, signal) {
        const url = `${QUAD9_DOH}?name=${encodeURIComponent(hostname)}&type=A`;

        const response = await fetch(url, {
            headers: { Accept: "application/dns-json" },
            signal
        });

        if (!response.ok) {
            // 400 typically means Quad9 has no threat-intel data for this TLD/domain
            // — treat as neutral (not blocked) rather than an error worth surfacing.
            const reason = response.status === 400
                ? "Domain not flagged by Quad9"
                : `Quad9 request failed (${response.status})`;
            return { status: "UNKNOWN", reason };
        }

        const result = await response.json();

        // NXDOMAIN — domain either blocked or genuinely non-existent
        if (result.Status === 3) {
            // Quad9 heuristic: Authority count 0 → actively blocked by threat-intel
            //                  Authority count >0 → domain simply doesn't exist
            const isBlocked = !result.Authority || result.Authority.length === 0;
            if (isBlocked) {
                return {
                    status: "BLOCKED",
                    reason: "Domain blocked by Quad9 threat-intelligence feed"
                };
            }
            return {
                status: "UNKNOWN",
                reason: "Domain does not exist (NXDOMAIN)"
            };
        }

        // No answer records at all
        if (!result.Answer || result.Answer.length === 0) {
            return { status: "UNKNOWN", reason: "No DNS answer records returned" };
        }

        // Collect A / AAAA / CNAME records
        const answers = result.Answer
            .filter(a => a.type === 1 || a.type === 5 || a.type === 28)
            .map(a => a.data);

        if (answers.length === 0) {
            return { status: "UNKNOWN", reason: "No A/AAAA/CNAME records found" };
        }

        return { status: "ALLOWED", answers };
    }

    /**
     * Public API: check a hostname with a hard timeout.
     *
     * Returns:
     *   { status, score, label, reason?, answers? }
     *
     *   status "BLOCKED"  → score −100, label "Confirmed malicious"
     *   status "ALLOWED"  → score 0 (neutral; RDAP age will add its own signal)
     *   status "UNKNOWN"  → score 0 (no data, don't penalise)
     */
    async function check(hostname) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort("timeout"), TIMEOUT_MS);

        try {
            const result = await checkHostname(hostname, controller.signal);
            clearTimeout(timer);

            if (result.status === "BLOCKED") {
                return {
                    status:  "BLOCKED",
                    score:   -100,
                    label:   "Confirmed malicious (blocked by Quad9)",
                    reason:  result.reason
                };
            }

            if (result.status === "ALLOWED") {
                return {
                    status:   "ALLOWED",
                    score:    0,
                    label:    "Resolved (not on Quad9 block list)",
                    answers:  result.answers
                };
            }

            // UNKNOWN — domain doesn't exist or DNS error
            return {
                status: "UNKNOWN",
                score:  0,
                label:  result.reason || "No Quad9 data"
            };

        } catch (err) {
            clearTimeout(timer);
            if (err.name === "AbortError") {
                return { status: "UNKNOWN", score: 0, label: "Quad9 check timed out" };
            }
            return { status: "UNKNOWN", score: 0, label: `Quad9 error: ${err.message}` };
        }
    }

    return { check };
})();
