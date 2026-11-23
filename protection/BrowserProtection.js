"use strict";

// ── BrowserProtection.js ──────────────────────────────────────────────────────
// Orchestrates two independent reputation axes, run simultaneously:
//
//   A. VirusTotal URL check  — community score removed
//   B. Host reputation       — DNS threat-intel (user's chosen 2 of 5
//                              providers) + RDAP + domain/TLD lists + URL patterns
//
// Public interface:
//   BrowserProtection.checkIfUrlIsMalicious(key, url, callback, originalUrl)
//       — starts VT fetch on url; also checks originalUrl against VT when it
//         resolves to a different registered domain (redirect-chain check),
//         taking the worse verdict. Fires callback(ProtectionResult, elapsedMs)
//   BrowserProtection.checkHostReputation(url, fileType, ext, mime, totalBytes,
//                                         originalUrl, isScript, obfuscation,
//                                         doubleExt, isLinuxLauncher, filename,
//                                         sizeKnown, referrer, dnsSettings,
//                                         downloadContext)
//       — returns Promise<hostResult>
//   BrowserProtection.abandonPendingRequests(key, reason)
//       — aborts in-flight fetch for the given download key
//   BrowserProtection.cleanup()
//       — abort ALL in-flight requests and clear the session URL cache
//
// State owned by this module:
//   abortControllers  {Map<downloadId, AbortController>}
//       — in-flight VT fetch controllers; deleted on completion, abort, or error.
//         Bounded naturally: one entry per concurrent in-flight VT check.
//         Released via abandonPendingRequests() or on fetch completion.
//   BrowserProtection.allowedUrls  {BoundedUrlSet}
//       — session cache of VT-confirmed-safe URLs; capped at APP.ALLOWED_URLS_MAX
//         with FIFO eviction. Lost on SW restart (safe: re-checked on next download).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * BrowserProtection.js (legacy JSDoc retained for IDE tooling)
 *
 * Orchestrates two independent reputation axes, run simultaneously:
 *
 *   A. VirusTotal URL check  (existing logic, community score removed)
 *   B. Host reputation       (DNS threat-intel + RDAP + domain list + TLD list + URL pattern)
 *
 * Both complete independently. The caller (background.js) stores and
 * forwards both result objects to the warning page. The warning page
 * reports the worst overall score but shows both info boxes.
 *
 * URL cleaning is delegated to UrlUtils (shared module).
 */
import { APP } from "../util/AppConstants.js";
import { UrlUtils } from "../util/UrlUtils.js";
import { SuspiciousDomains } from "../util/SuspiciousDomains.js";
import { SuspiciousTlds } from "../util/SuspiciousTlds.js";
import { RiskyHostingSites } from "../util/RiskyHostingSites.js";
import { HostList } from "../util/HostList.js"; // merged HaGeZi/Kees list — v2.7.0 Step 1
import { StagingCheck } from "./StagingCheck.js"; // lure/command keywords + staging formats — v2.8.0 Step 2
import { ProtectionResult } from "./ProtectionResult.js";
import { ScoringEngineV2 } from "./ScoringEngineV2.js";
import { SketchyUrlCheck } from "./SketchyUrlCheck.js";
import { MimeCheck } from "./MimeCheck.js";
import { DnsThreatProtection } from "./DnsThreatProtection.js";
import { RdapProtection } from "./RdapProtection.js";
import { DnsDefaults } from "../util/DnsDefaults.js"; // region-aware DNS threat-intel defaults (v3.3.1)
import { FilenameAnalysis } from "../util/FilenameAnalysis.js"; // FILE_TYPE enum (v3.4.0)

export const BrowserProtection = (function () {

    const abortControllers = new Map();

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

    /**
     * True when originalUrl exists, differs from url, and resolves to a
     * different registered domain — the condition under which it is worth
     * spending a second (rate-limited) VirusTotal lookup on the original URL
     * as well as the final one.
     *
     * Mirrors the redirect-chain rationale already used for DNS threat-intel/RDAP in
     * checkHostReputation(): a malicious actor can mask the true source
     * behind a clean-looking redirector domain, or vice versa, so the worse
     * of the two verdicts is the one that matters.
     */
    function originalDomainDiffers(url, originalUrl) {
        if (!originalUrl || originalUrl === url) return false;
        const finalDomain    = UrlUtils.getRegisteredDomain(UrlUtils.getHostname(url));
        const originalDomain = UrlUtils.getRegisteredDomain(UrlUtils.getHostname(originalUrl));
        return !!(originalDomain && originalDomain !== finalDomain);
    }

    /**
     * Fetch and evaluate a single URL against the VirusTotal API.
     * Returns { eval, raw, filtered } on a definite VT verdict, or null when
     * VT has no analysis data for the URL (unrated / not found — "unknown").
     * Throws on network error or abort; the caller decides how to handle that.
     */
    async function fetchVtEvaluation(targetUrl, apiKey, fpLevel, signal) {
        const urlId    = UrlUtils.toVtUrlId(targetUrl);
        const response = await fetch(
            `https://www.virustotal.com/api/v3/urls/${urlId}`,
            { method: "GET", headers: { "x-apikey": apiKey }, signal }
        );
        if (!response.ok) return null;

        const data    = await response.json();
        const attrs   = data?.data?.attributes ?? {};
        const results = attrs.last_analysis_results ?? {};
        if (Object.keys(results).length === 0) return null; // no engines rated it — unknown

        return ScoringEngineV2.evaluateFromAnalysisResults(results, fpLevel, attrs.first_submission_date);
    }

    /**
     * Pick the worse (lower-scoring) of two VT evaluations. Either may be
     * null (VT had no data for that URL); a definite result always beats
     * "unknown", and lower score = worse between two definite results.
     */
    function worseVtEvaluation(a, b) {
        if (!a) return b;
        if (!b) return a;
        return a.eval.score <= b.eval.score ? a : b;
    }

    // ── Host-reputation check ───────────────────────────────────────────────

    /**
     * Run all four host-reputation checks simultaneously and return a combined
     * host-reputation result object.
     *
     * @param {string} url       - Original download URL
     * @param {string} fileType  - "executable" | "archive"
     * @param {string} filename  - confirmed or suggested filename (v2.8.0 —
     *        passed through to StagingCheck.checkKeywords())
     * @param {boolean} sizeKnown - true once Chrome has reported a real file
     *        size (v2.8.0 — passed through to StagingCheck.checkFormat());
     *        false at onCreated, when size is typically still 0
     * @param {string|null} referrer - chrome.downloads.DownloadItem.referrer
     *        (v2.11.0 — passed through to FilenameUrlHeuristics.check
     *        ReferrerMismatch()); omit/null when unavailable, which is
     *        treated as "no signal", never a penalty
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
            domainHit:   SuspiciousDomains.lookup(hostname),
            tldHit:      SuspiciousTlds.lookup(tld),
            hostListHit: HostList.lookup(hostname), // v2.7.0 Step 1 — merged HaGeZi/Kees list
            sketchyUrl:  SketchyUrlCheck.check(url),
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

    // Worse of two DnsThreatProtection.check() results for the SAME slot
    // (e.g. "first DNS check" on finalUrl vs on originalUrl) — mirrors
    // worseHit()'s "lower score wins" idea, but DNS results don't carry a
    // graded score, only a status, so rank the statuses instead:
    // BLOCKED is worse than UNKNOWN is worse than ALLOWED/SKIPPED.
    const DNS_STATUS_RANK = Object.freeze({ BLOCKED: 2, UNKNOWN: 1, ALLOWED: 0, SKIPPED: 0 });
    function worseDns(a, b) {
        return (DNS_STATUS_RANK[b?.status] || 0) > (DNS_STATUS_RANK[a?.status] || 0) ? b : a;
    }

    // downloadContext (v3.4.0, renamed and + fpLevel in v3.5.0) —
    // DownloadShape.contextOf(record): { visibleExt, isUnknownBinary, fpLevel };
    // null/omitted = none of them (older callers and tests are unaffected).
    //   fpLevel         FP reduction level → DeliveryContext strategy (v3.5.0)
    //   visibleExt      the name's visible extension even when it is not a
    //                   dangerous one ("pdf") — lets MimeCheck see the R4
    //                   mismatch "invoice.pdf served as an executable type"
    //   isUnknownBinary R1 — scored as Check 26 in evaluateHostReputation()
    // dnsSettings — { first, second }, provider ids from APP.DNS_PROVIDERS
    // (or APP.DNS_NONE to disable a slot). Defaults to the region-aware
    // install defaults (util/DnsDefaults.js) so any caller that omits it
    // (older tests, etc.) still runs a real check rather than silently
    // checking nothing.
    async function checkHostReputation(url, fileType, ext, mime, totalBytes, originalUrl, isScript = false, obfuscation = null, doubleExt = null, isLinuxLauncher = false, filename = "", sizeKnown = false, referrer = null, dnsSettings = null, downloadContext = null) {
        const dnsFirst  = dnsSettings?.first  || DnsDefaults.get().first;
        const dnsSecond = dnsSettings?.second || DnsDefaults.get().second;

        // ── Signals that use the finalUrl (actual download) ───────────────────
        const finalHostname = UrlUtils.getHostname(url);
        const finalTld      = UrlUtils.getTld(finalHostname);
        const mimeResult    = MimeCheck.checkMime(ext || downloadContext?.visibleExt || "", mime || "");
        const isUnknownBinary = !!downloadContext?.isUnknownBinary;
        const fpLevel         = downloadContext?.fpLevel ?? null;
        const sizeResult    = MimeCheck.checkSize(totalBytes || 0);
        const riskyHosting  = RiskyHostingSites.lookup(finalHostname);

        // ── Staging checks (heuristics plan Step 2, v2.8.0) ───────────────────
        // fileCategory mirrors classifyDownload()'s own categories — "script"
        // takes priority over the generic fileType bucket, same precedence
        // FilenameAnalysis.getExtCategory() already uses. "staging"/"other"
        // (plan-defined, lower lure weight tiers StagingCheck.checkKeywords()
        // itself supports) are never produced by classifyDownload(), which
        // only ever returns "executable" or "archive" — not a gap, just not
        // a distinction this codebase's classifier draws today.
        // v3.4.0 — an extensionless generic binary (R1) may well be a program,
        // so lure words weigh as for an executable, not 0 as for "other".
        const fileCategory = isScript ? "script"
            : (fileType === FilenameAnalysis.FILE_TYPE.UNKNOWN_BINARY ? FilenameAnalysis.FILE_TYPE.EXECUTABLE : fileType);

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
        const hostListHit = originalHeuristics // v2.7.0 Step 1 — same worst-of-two pattern as domainHit/tldHit
            ? worseHit(finalHeuristics.hostListHit, originalHeuristics.hostListHit)
            : finalHeuristics.hostListHit;
        // For sketchyUrl compare by score
        const sketchyFinal    = finalHeuristics.sketchyUrl;
        const sketchyOriginal = originalHeuristics?.sketchyUrl;
        const sketchyUrl = (sketchyOriginal && (sketchyOriginal.score || 0) > (sketchyFinal?.score || 0))
            ? sketchyOriginal
            : sketchyFinal;

        // ── DNS threat-intel + RDAP: run on finalUrl; if originalUrl has different domain,
        //    also run on originalUrl and take the worse result ─────────────────
        const registeredDomain         = UrlUtils.getRegisteredDomain(finalHostname);
        const originalHostname         = originalHeuristics ? originalHeuristics.hostname : null;
        const originalRegisteredDomain = originalHostname
            ? UrlUtils.getRegisteredDomain(originalHostname) : null;

        // ── Staging keywords + staging format (heuristics plan Step 2) ────────
        // Pure/synchronous — run alongside the async DNS threat-intel/RDAP calls below,
        // not inside Promise.all, since neither depends on network data.
        const stagingKeywords = StagingCheck.checkKeywords({
            finalUrl:         url,
            originalUrl,
            filename,
            registeredDomain,
            fileCategory
        });
        const stagingFormat = StagingCheck.checkFormat({
            ext,
            totalBytes,
            sizeKnown
        });

        // Run both configured DNS threat-intel checks + RDAP on both domains
        // in parallel when needed
        const needsOriginalAsync = originalRegisteredDomain &&
            originalRegisteredDomain !== registeredDomain;

        const asyncChecks = [
            DnsThreatProtection.check(dnsFirst,  finalHostname),
            DnsThreatProtection.check(dnsSecond, finalHostname),
            RdapProtection.check(registeredDomain),
            ...(needsOriginalAsync ? [
                DnsThreatProtection.check(dnsFirst,  originalHostname),
                DnsThreatProtection.check(dnsSecond, originalHostname),
                RdapProtection.check(originalRegisteredDomain)
            ] : [])
        ];

        const asyncResults = await Promise.all(asyncChecks);
        let dns1Result = asyncResults[0];
        let dns2Result = asyncResults[1];
        let rdapResult = asyncResults[2];

        if (needsOriginalAsync) {
            const origDns1 = asyncResults[3];
            const origDns2 = asyncResults[4];
            const origRdap = asyncResults[5];
            dns1Result = worseDns(dns1Result, origDns1);
            dns2Result = worseDns(dns2Result, origDns2);
            // Take worse RDAP: lower score = worse
            if ((origRdap.score || 0) < (rdapResult.score || 0)) {
                rdapResult = origRdap;
            }
        }

        const dnsChecks = [dns1Result, dns2Result];

        const evaluation = ScoringEngineV2.evaluateHostReputation({
            dnsChecks,
            rdap:      rdapResult,
            domainHit,
            tldHit,
            hostListHit,
            stagingKeywords,
            stagingFormat,
            sketchyUrl,
            mimeResult,
            sizeResult,
            riskyHosting,
            url,
            originalUrl,
            fileType,
            isScript,
            obfuscation,
            doubleExt,
            isLinuxLauncher,
            filename,
            referrer,
            isUnknownBinary,
            fpLevel,
            totalBytes: totalBytes || 0                  // 3P Matrix 4.5.6: large extensionless binary rule
        });

        return {
            hostname:        finalHostname,
            originalHostname,
            tld:             finalTld,
            registeredDomain,
            dnsChecks,
            rdap:            rdapResult,
            domainHit,
            tldHit,
            hostListHit,
            stagingKeywords,
            stagingFormat,
            sketchyUrl,
            mimeResult,
            sizeResult,
            riskyHosting,
            score:           evaluation.score,
            classification:  evaluation.classification,
            label:           evaluation.label,
            hardRuleApplied: evaluation.hardRuleApplied,
            breakdown:       evaluation.breakdown,
            heuristicsOnly:  evaluation.heuristicsOnly   // v3.5.6 — the VirusTotal-unknown verdict (ScoringEngineV2.hostVerdict)
        };
    }

    // ─────────────────────────────────────────────────────────────────────────

    return {

        abandonPendingRequests(key, reason) {
            closeOpenConnections(key, reason);
        },

        /**
         * True while a VT check (including a silent, past-timeout item-16
         * retry) is still in flight for this key. background.js uses this
         * to decide whether releaseDownload() may safely abort/forget a
         * download's in-flight VT request, or must instead leave it running
         * and keep its record alive for a possible late result.
         */
        isVtPending(key) {
            return abortControllers.has(key);
        },

        /**
         * Run VT URL check on the final download URL, and — when originalUrl
         * resolves to a different registered domain — on the original
         * (pre-redirect) URL too, reporting the worse of the two verdicts.
         * Called from background.js after download is intercepted.
         * Host reputation is run separately via checkHostReputation().
         *
         * @param {object} settings - v3.3.0 (item 12) — the caller's own
         *        Settings.get() snapshot, passed in rather than this module
         *        fetching its own copy. background.js already has settings
         *        in hand at every call site (it needed them to decide
         *        whether to call this at all), so a second internal
         *        Settings.get() was a redundant extra read with its own
         *        race-timing window, not a real dependency.
         * @param {function} [onLateResult] - v3.3.0 (item 16) — when the
         *        FIRST VT attempt times out (APP.VT_FETCH_TIMEOUT_MS),
         *        `callback` still fires immediately with an UNKNOWN result
         *        (the caller is never blocked past the normal timeout) —
         *        but if `onLateResult` is given, the in-flight request is
         *        NOT aborted at that point. It keeps running, silently, up
         *        to the longer APP.VT_RETRY_TIMEOUT_MS deadline, and if it
         *        settles with an actual verdict (not a second timeout),
         *        `onLateResult(ProtectionResult, elapsedMs)` fires with it.
         *        Omit this parameter to keep the old behavior exactly
         *        (abort immediately on the first timeout, nothing further).
         */
        checkIfUrlIsMalicious(key, url, callback, originalUrl, settings, onLateResult) {

            if (!key || !url || typeof callback !== "function") return;
            if (!settings) {
                console.warn("[DS:BrowserProtection] checkIfUrlIsMalicious called without settings, skipping VT check");
                return;
            }

            // Validate that url parses; the URL object itself isn't needed here —
            // UrlUtils re-parses as needed downstream — only the validity check is.
            try { new URL(url); }
            catch {
                console.warn("[DS:BrowserProtection] Invalid URL, skipping VT check");   // v3.6.0: no address in logs (3P Matrix C52)
                return;
            }

            const startTime = Date.now();

            if (!abortControllers.has(key)) {
                abortControllers.set(key, new AbortController());
            }

            doVtCheck(settings);

            // v3.3.0 (item 14) — function declaration, not an arrow const,
            // for the same reason every other multi-step async worker in
            // this module (fetchVtEvaluation, checkHostReputation) already
            // is one: it reads as a named step in the file's own flow, not
            // a one-off inline callback.
            async function doVtCheck(settings) {

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

                let callbackFired = false;   // the ORIGINAL callback has fired (first timeout or success)
                let retryTimeoutId = null;   // v3.3.0 (item 16) — the extended-deadline timer, when retrying

                const timeoutId = setTimeout(() => {
                    if (callbackFired) return;
                    callbackFired = true;
                    unknownVtResult(url, startTime, callback); // caller is never blocked past this point

                    if (typeof onLateResult !== "function") {
                        // No retry requested — exactly the old behavior.
                        controller?.abort("timeout");
                        abortControllers.delete(key);
                        return;
                    }

                    // v3.3.0 (item 16) — don't abort. Let the in-flight fetch
                    // keep running silently, on a longer leash, in case VT
                    // still comes back with a real verdict. The key stays in
                    // abortControllers (BrowserProtection.isVtPending(key)
                    // reports true) until this settles one way or the other.
                    retryTimeoutId = setTimeout(() => {
                        controller?.abort("retry-timeout");
                        abortControllers.delete(key);
                    }, APP.VT_RETRY_TIMEOUT_MS);
                }, APP.VT_FETCH_TIMEOUT_MS); // see AppConstants.js

                try {
                    // Small delay so warning page is mounted before result arrives
                    await new Promise(r => setTimeout(r, APP.VT_FETCH_STARTUP_DELAY_MS));

                    const fpLevel = settings.fpReductionLevel ?? "MEDIUM";

                    // Redirect-chain check: only spend a second VT lookup on
                    // originalUrl when it actually resolves to a different
                    // registered domain than the final download URL (bug fix —
                    // originalUrl used to be accepted as a parameter and silently
                    // ignored). Both requests share one AbortController/signal so
                    // abandoning the download cancels both together.
                    const needsOriginalCheck = originalDomainDiffers(url, originalUrl);

                    const [finalProbe, originalProbe] = await Promise.all([
                        fetchVtEvaluation(url, settings.vtApiKey, fpLevel, signal),
                        needsOriginalCheck
                            ? fetchVtEvaluation(originalUrl, settings.vtApiKey, fpLevel, signal)
                            : Promise.resolve(null)
                    ]);

                    clearTimeout(timeoutId);
                    clearTimeout(retryTimeoutId);

                    // v3.3.0 (item 16) — if the original deadline already
                    // fired (callbackFired was set there), this result is
                    // arriving LATE, after the caller was already told
                    // UNKNOWN. Report it via onLateResult instead of
                    // `callback`, which must never fire twice.
                    const isLate = callbackFired;
                    if (!isLate) callbackFired = true;
                    const deliver = isLate ? onLateResult : callback;

                    const parsed = worseVtEvaluation(finalProbe, originalProbe);

                    if (!parsed) {
                        // Still no verdict even after waiting longer — on the
                        // ORIGINAL path this is reported as UNKNOWN (as
                        // always); on a LATE retry there is nothing NEW to
                        // report (the caller already has UNKNOWN), so stay
                        // silent — see this parameter's own doc comment.
                        abortControllers.delete(key);
                        if (!isLate) unknownVtResult(url, startTime, callback);
                        return;
                    }

                    const { eval: evaluation, raw: rawStats, filtered: filteredStats } = parsed;

                    // Cache only against the exact final URL requested — never mark
                    // it "safe" solely because a *different* (originalUrl) lookup
                    // came back clean.
                    if (parsed === finalProbe &&
                        evaluation.classification === ProtectionResult.ResultType.PROBABLY_SAFE) {
                        BrowserProtection.allowedUrls.add(UrlUtils.cleanUrl(url));
                    }

                    // Release the AbortController — no longer needed once a verdict fires
                    abortControllers.delete(key);
                    if (deliver) {
                        deliver(
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
                    }

                } catch (error) {
                    clearTimeout(timeoutId);
                    clearTimeout(retryTimeoutId);
                    abortControllers.delete(key); // release on error too
                    if (error.name === "AbortError") return; // includes both the original abandon AND the retry-timeout abort above
                    if (callbackFired) return; // late error after an already-reported UNKNOWN — nothing new to report, stay silent (same as the late "still no verdict" case above)
                    callbackFired = true;
                    console.warn("[DS:BrowserProtection] VT fetch error:", error?.message);
                    unknownVtResult(url, startTime, callback);
                }
            }
        },

        /**
         * Run host-reputation checks for a download.
         * Returns a Promise that resolves with the host-reputation result.
         */
        checkHostReputation,

        /**
         * Abort ALL in-flight VT requests and clear the session URL cache.
         * Called when the extension is disabled or for testing/reset purposes.
         * Safe to call at any time; is a no-op if nothing is in-flight.
         */
        cleanup() {
            for (const [key, controller] of abortControllers) {
                controller.abort("cleanup");
                abortControllers.delete(key);
            }
            if (BrowserProtection.allowedUrls) {
                BrowserProtection.allowedUrls.clear();
            }
        }

    };

})();

// allowedUrls: session cache of URLs already confirmed PROBABLY_SAFE by VT,
// so repeat downloads of the same file don't burn VT's 4-req/min free-tier
// quota. Previously an unbounded Set — every unique safe URL checked over the
// SW's lifetime accumulated permanently. Now capped at MAX_ALLOWED_URLS with
// FIFO eviction (oldest entries drop first) to bound memory growth.
// BoundedUrlSet — FIFO-evicting Set capped at APP.ALLOWED_URLS_MAX entries.
// Prevents the allowedUrls cache from growing unboundedly over the SW's lifetime.
class BoundedUrlSet {
    constructor(max) { this.max = max; this.map = new Map(); }
    has(key)  { return this.map.has(key); }
    add(key)  {
        if (this.map.has(key)) { this.map.delete(key); } // refresh recency
        this.map.set(key, true);
        if (this.map.size > this.max) {
            // Evict oldest (first inserted) entry
            this.map.delete(this.map.keys().next().value);
        }
    }
    clear()   { this.map.clear(); }
    get size() { return this.map.size; }
}
BrowserProtection.allowedUrls = new BoundedUrlSet(APP.ALLOWED_URLS_MAX);
