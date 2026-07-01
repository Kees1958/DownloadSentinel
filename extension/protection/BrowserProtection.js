"use strict";

/**
 * BrowserProtection.js
 *
 * Orchestrates two independent reputation axes, run simultaneously:
 *
 *   A. VirusTotal URL check  (existing logic, community score removed)
 *   B. Host reputation       (Quad9 + RDAP + domain list + TLD list + URL pattern)
 *
 * Both complete independently. The caller (background.js) stores and
 * forwards both result objects to the warning page. The warning page
 * reports the worst overall score but shows both info boxes.
 *
 * URL cleaning is delegated to UrlUtils (shared module).
 */
const BrowserProtection = (function () {

    let abortControllers = new Map();

    function closeOpenConnections(key, reason) {
        // Called when a download's lifecycle is fully over (cancelled, allowed,
        // erased, or swept as stale) — abort any in-flight request and DELETE
        // the entry rather than replacing it with a fresh controller. Replacing
        // it left a permanent Map entry per downloadId for the SW's lifetime,
        // an unbounded memory leak (one entry per blocked download, never freed).
        if (abortControllers.has(key)) {
            abortControllers.get(key).abort(reason);
            abortControllers.delete(key);
        }
    }

    // ── VT helpers ─────────────────────────────────────────────────────────

    function unknownVtResult(url, startTime, callback) {
        callback(
            new ProtectionResult(
                url,
                ProtectionResult.ResultType.UNKNOWN,
                ProtectionResult.ResultOrigin.VIRUSTOTAL
            ),
            Date.now() - startTime
        );
    }

    // ── Host-reputation check ───────────────────────────────────────────────

    /**
     * Run all four host-reputation checks simultaneously and return a combined
     * host-reputation result object.
     *
     * @param {string} url       - Original download URL
     * @param {string} fileType  - "executable" | "archive"
     * @returns {Promise<object>} hostResult
     */
    /**
     * Run heuristics on a single URL and return all synchronous signals.
     * Used internally to support dual-URL heuristics comparison.
     */
    function getUrlHeuristics(url) {
        const hostname = UrlUtils.getHostname(url);
        const tld      = UrlUtils.getTld(hostname);
        return {
            hostname,
            tld,
            domainHit:  SuspiciousDomains.lookup(hostname),
            tldHit:     SuspiciousTlds.lookup(tld),
            sketchyUrl: SketchyUrlCheck.check(url),
        };
    }

    /**
     * Pick the worse of two heuristic signals (lower score = worse).
     * Returns whichever signal has the lower score, or the non-null one.
     */
    function worseHit(a, b) {
        if (!a && !b) return null;
        if (!a)       return b;
        if (!b)       return a;
        return (a.score || 0) <= (b.score || 0) ? a : b;
    }

    async function checkHostReputation(url, fileType, ext, mime, totalBytes, originalUrl, isScript = false) {

        // ── Signals that use the finalUrl (actual download) ───────────────────
        const finalHostname = UrlUtils.getHostname(url);
        const finalTld      = UrlUtils.getTld(finalHostname);
        const mimeResult    = MimeCheck.checkMime(ext || "", mime || "");
        const sizeResult    = MimeCheck.checkSize(totalBytes || 0);
        const riskyHosting  = RiskyHostingSites.lookup(finalHostname);

        // ── Signals that use worst of finalUrl vs originalUrl ─────────────────
        const finalHeuristics    = getUrlHeuristics(url);
        const originalHeuristics = (originalUrl && originalUrl !== url)
            ? getUrlHeuristics(originalUrl)
            : null;

        // Take the worse (lower scoring) signal from each category
        const domainHit  = originalHeuristics
            ? worseHit(finalHeuristics.domainHit,  originalHeuristics.domainHit)
            : finalHeuristics.domainHit;
        const tldHit     = originalHeuristics
            ? worseHit(finalHeuristics.tldHit,     originalHeuristics.tldHit)
            : finalHeuristics.tldHit;
        // For sketchyUrl compare by score
        const sketchyFinal    = finalHeuristics.sketchyUrl;
        const sketchyOriginal = originalHeuristics?.sketchyUrl;
        const sketchyUrl = (sketchyOriginal && (sketchyOriginal.score || 0) > (sketchyFinal?.score || 0))
            ? sketchyOriginal
            : sketchyFinal;

        // ── Quad9 + RDAP: run on finalUrl; if originalUrl has different domain,
        //    also run on originalUrl and take the worse result ─────────────────
        const registeredDomain         = UrlUtils.getRegisteredDomain(finalHostname);
        const originalHostname         = originalHeuristics ? originalHeuristics.hostname : null;
        const originalRegisteredDomain = originalHostname
            ? UrlUtils.getRegisteredDomain(originalHostname) : null;

        // Run Quad9 + RDAP on both domains in parallel when needed
        const needsOriginalAsync = originalRegisteredDomain &&
            originalRegisteredDomain !== registeredDomain;

        const asyncChecks = [
            Quad9Protection.check(finalHostname),
            RdapProtection.check(registeredDomain),
            ...(needsOriginalAsync ? [
                Quad9Protection.check(originalHostname),
                RdapProtection.check(originalRegisteredDomain)
            ] : [])
        ];

        const asyncResults = await Promise.all(asyncChecks);
        let quad9Result = asyncResults[0];
        let rdapResult  = asyncResults[1];

        if (needsOriginalAsync) {
            const origQuad9 = asyncResults[2];
            const origRdap  = asyncResults[3];
            // Take worse Quad9: BLOCKED > UNKNOWN > ALLOWED
            const quad9Rank = { BLOCKED: 2, UNKNOWN: 1, ALLOWED: 0 };
            if ((quad9Rank[origQuad9.status] || 0) > (quad9Rank[quad9Result.status] || 0)) {
                quad9Result = origQuad9;
            }
            // Take worse RDAP: lower score = worse
            if ((origRdap.score || 0) < (rdapResult.score || 0)) {
                rdapResult = origRdap;
            }
        }

        const evaluation = ScoringEngineV2.evaluateHostReputation({
            quad9:     quad9Result,
            rdap:      rdapResult,
            domainHit,
            tldHit,
            sketchyUrl,
            mimeResult,
            sizeResult,
            riskyHosting,
            url,
            fileType,
            isScript
        });

        return {
            hostname:        finalHostname,
            originalHostname,
            tld:             finalTld,
            registeredDomain,
            quad9:           quad9Result,
            rdap:            rdapResult,
            domainHit,
            tldHit,
            sketchyUrl,
            mimeResult,
            sizeResult,
            riskyHosting,
            score:           evaluation.score,
            classification:  evaluation.classification,
            label:           evaluation.label,
            hardRuleApplied: evaluation.hardRuleApplied,
            breakdown:       evaluation.breakdown
        };
    }

    // ─────────────────────────────────────────────────────────────────────────

    return {

        abandonPendingRequests(key, reason) {
            closeOpenConnections(key, reason);
        },

        /**
         * Run VT URL check.
         * Called from background.js after download is intercepted.
         * Host reputation is run separately via checkHostReputation().
         */
        checkIfUrlIsMalicious(key, url, callback, originalUrl) {

            if (!key || !url || typeof callback !== "function") return;

            let urlObject;
            try { urlObject = new URL(url); }
            catch {
                console.warn("[DS:BrowserProtection] Invalid URL, skipping VT check:", url);
                return;
            }

            const startTime = Date.now();

            if (!abortControllers.has(key)) {
                abortControllers.set(key, new AbortController());
            }

            const doVtCheck = async (settings) => {

                if (!settings.extensionEnabled)               return;
                if (!settings.virusTotalEnabled)              return;
                if (!settings.isVtApiKeySet || !settings.vtApiKey) return;

                // Session cache: skip re-checking URLs already classified as safe
                if (BrowserProtection.allowedUrls.has(UrlUtils.cleanUrl(url))) {
                    callback(
                        new ProtectionResult(
                            url,
                            ProtectionResult.ResultType.PROBABLY_SAFE,
                            ProtectionResult.ResultOrigin.VIRUSTOTAL,
                            { score: 100, confidence: "Cached", hardRuleApplied: null }
                        ),
                        Date.now() - startTime
                    );
                    return;
                }

                const controller = abortControllers.get(key);
                const signal     = controller?.signal;

                let callbackFired = false;

                const timeoutId = setTimeout(() => {
                    if (callbackFired) return;
                    callbackFired = true;
                    controller?.abort("timeout");
                    unknownVtResult(url, startTime, callback);
                }, 3000); // 3 s — users get impatient beyond this; cached VT lookups typically resolve in 200-800 ms well within budget

                try {
                    // Small delay so warning page is mounted before result arrives
                    await new Promise(r => setTimeout(r, 100));

                    const urlId    = UrlUtils.toVtUrlId(url);
                    const response = await fetch(
                        `https://www.virustotal.com/api/v3/urls/${urlId}`,
                        { method: "GET", headers: { "x-apikey": settings.vtApiKey }, signal }
                    );

                    clearTimeout(timeoutId);
                    if (callbackFired) return;
                    callbackFired = true;

                    if (!response.ok) {
                        unknownVtResult(url, startTime, callback);
                        return;
                    }

                    const fpLevel = settings.fpReductionLevel ?? "MEDIUM";

                    /**
                     * Parse a VT API response into an evaluation result.
                     * Returns null if the URL was not found (404 / no analysis data).
                     */
                    async function parseVtResponse(resp) {
                        if (!resp.ok) return null;
                        const d          = await resp.json();
                        const attrs      = d?.data?.attributes ?? {};
                        const results    = attrs.last_analysis_results ?? {};
                        // If no engines have rated it, treat as unknown
                        if (Object.keys(results).length === 0) return null;
                        const raw      = FpReductionEngines.getRawStats(results);
                        const filtered = FpReductionEngines.filterResults(results, fpLevel);
                        const eval_    = ScoringEngineV2.evaluate({
                            stats:               filtered,
                            rawStats:            raw,
                            firstSubmissionDate: attrs.first_submission_date ?? null,
                            fpLevel
                        });
                        return { eval: eval_, raw, filtered, attrs };
                    }

                    const parsed = await parseVtResponse(response);

                    if (!parsed) {
                        unknownVtResult(url, startTime, callback);
                        return;
                    }

                    const { eval: evaluation, raw: rawStats, filtered: filteredStats } = parsed;

                    const cleanUrl = UrlUtils.cleanUrl(url);
                    if (evaluation.classification === ProtectionResult.ResultType.PROBABLY_SAFE) {
                        BrowserProtection.allowedUrls.add(cleanUrl);
                    }

                    callback(
                        new ProtectionResult(
                            url,
                            evaluation.classification,
                            ProtectionResult.ResultOrigin.VIRUSTOTAL,
                            {
                                score:           evaluation.score,
                                confidence:      evaluation.confidence,
                                breakdown:       evaluation.breakdown,
                                hardRuleApplied: evaluation.hardRuleApplied,
                                rawStats,
                                filteredStats,
                                fpLevel
                            }
                        ),
                        Date.now() - startTime
                    );

                } catch (error) {
                    clearTimeout(timeoutId);
                    if (error.name === "AbortError") return;
                    if (callbackFired) return;
                    callbackFired = true;
                    console.warn("[DS:BrowserProtection] VT fetch error:", error?.message);
                    unknownVtResult(url, startTime, callback);
                }
            };

            Settings.get(settings => doVtCheck(settings));
        },

        /**
         * Run host-reputation checks for a download.
         * Returns a Promise that resolves with the host-reputation result.
         */
        checkHostReputation

    };

})();

// allowedUrls: session cache of URLs already confirmed PROBABLY_SAFE by VT,
// so repeat downloads of the same file don't burn VT's 4-req/min free-tier
// quota. Previously an unbounded Set — every unique safe URL checked over the
// SW's lifetime accumulated permanently. Now capped at MAX_ALLOWED_URLS with
// FIFO eviction (oldest entries drop first) to bound memory growth.
const MAX_ALLOWED_URLS = 200;
class BoundedUrlSet {
    constructor(max) { this.max = max; this.map = new Map(); }
    has(key) { return this.map.has(key); }
    add(key) {
        if (this.map.has(key)) { this.map.delete(key); } // refresh recency
        this.map.set(key, true);
        if (this.map.size > this.max) {
            const oldest = this.map.keys().next().value;
            this.map.delete(oldest);
        }
    }
    get size() { return this.map.size; }
}
BrowserProtection.allowedUrls = new BoundedUrlSet(MAX_ALLOWED_URLS);
