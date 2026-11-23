"use strict";

// ── WarnPolicy.js ─────────────────────────────────────────────────────────────
// v3.5.2 — decides whether a scored download or site gets a WARNING WINDOW
// (DownloadSentinel / 3P Matrix download warning, 3P Matrix site dialog), or
// stays quiet. Single source for both extensions and both checks.
//
// Rule: warn when the score is at or below the threshold for the user's
// setting, OR when one of the check's EXCEPTIONS is present — a combination
// that always deserves a look, whatever the score:
//
//   exception       download  site   meaning
//   KNOWN_BAD          ✔        ✔    a DNS threat-intel block, or ≥1 VirusTotal engine flags it
//   IMPERSONATION      ✔        ✔    look-alike of a brand/popular site, or a brand name on an open platform
//   FILE_ITSELF        ✔        —    the file lies about itself or is directly runnable code: any WHAT-question
//                                    signal (CombinationScoring.FAMILY_QUESTION) — disguised/mismatched type,
//                                    double extension, extensionless binary, script, launcher, staging format
//   LURE_ROUTE         ✔        —    the link was opened from a chat or webmail page
//   YOUNG_DOMAIN       ✔        —    domain registered ≤ APP.RDAP_YOUNG_DAYS ago (too noisy for page visits)
//
// Only route quirks and moderate sender signals are left to the threshold.
// Explained route quirks (DeliveryContext: score 0, `explained`) never count.
//
// Download thresholds are per FP reduction level (DOWNLOAD_WARN_FROM). Site
// thresholds are per 3P Matrix protection level and live in 3P Matrix
// (data/constants.js SITE_DIALOG_FROM) — this module does not know levels;
// siteDecision() takes the threshold as an argument.
//
// Not decided here: "Silent when probably safe" (autoAllow) and the
// extensionless-binary always-warn switch (util/DownloadShape.mustAlwaysWarn)
// run first in the glue, unchanged.
//
// Public interface:
//   WarnPolicy.CHECK, WarnPolicy.EXCEPTION, WarnPolicy.CONFIG
//   WarnPolicy.exceptionsFound(check, entries, { vtMalicious }) -> EXCEPTION[]
//   WarnPolicy.downloadDecision({ combinedScore, fpLevel, entries, vtMalicious })
//       -> { warn, threshold, exceptions }
//   WarnPolicy.siteDecision({ score, threshold, entries }) -> { warn, threshold, exceptions }
//   WarnPolicy.exceptionText(exception) -> plain-language reason
//   WarnPolicy.windowHint(fpLevel, formatScore) -> Options sentence for that level (both extensions)
//
// Pure: no chrome.* access, no state. Dependencies: AppConstants (RDAP
// young score), CombinationScoring (families / questions).
// ─────────────────────────────────────────────────────────────────────────────
import { APP } from "../util/AppConstants.js";
import { CombinationScoring } from "./CombinationScoring.js";

export const WarnPolicy = (function () {

    const CHECK = Object.freeze({ DOWNLOAD: "download", SITE: "site" });

    const EXCEPTION = Object.freeze({
        KNOWN_BAD:     "known-bad",
        IMPERSONATION: "impersonation",
        FILE_ITSELF:   "file-itself",
        LURE_ROUTE:    "lure-route",
        YOUNG_DOMAIN:  "young-domain",
    });

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIG — every knob, one place.
    // ─────────────────────────────────────────────────────────────────────────
    const CONFIG = Object.freeze({
        // FP reduction level → warn when the combined score is at or below this;
        // null = always warn (every monitored download, as before v3.5.2).
        DOWNLOAD_WARN_FROM: Object.freeze({
            HIGH:   -45,   // middle of the "suspicious" band — not more lenient (two real sender problems)
            MEDIUM: -30,   // the "suspicious" line (= 3P Matrix's site default)
            LOW:    -15,
            NONE:   null,
        }),
        DEFAULT_FP_LEVEL: "MEDIUM",

        EXCEPTIONS_FOR: Object.freeze({
            [CHECK.DOWNLOAD]: Object.freeze([EXCEPTION.KNOWN_BAD, EXCEPTION.IMPERSONATION, EXCEPTION.FILE_ITSELF,
                                             EXCEPTION.LURE_ROUTE, EXCEPTION.YOUNG_DOMAIN]),
            [CHECK.SITE]:     Object.freeze([EXCEPTION.KNOWN_BAD, EXCEPTION.IMPERSONATION]),
        }),

        // Breakdown sources per exception (sources are the scoring entries' `source`).
        KNOWN_BAD_SOURCES:     Object.freeze(["DnsThreat"]),
        IMPERSONATION_SOURCES: Object.freeze(["LookalikeDomain", "PlatformBrand"]),
        LURE_ROUTE_SOURCES:    Object.freeze(["MessageOrigin"]),
        YOUNG_DOMAIN_SOURCES:  Object.freeze(["RDAP"]),
        VT_FLAGGED_MIN:        1,     // VirusTotal "malicious" engine count that counts as KNOWN_BAD

        // Options-page sentence per FP level ({score} = the level's threshold, formatted by the caller).
        WINDOW_HINT: Object.freeze({
            FROM_SCORE:  "A warning window opens from score {score}; risky combinations always get one.",
            ALWAYS:      "Every checked download gets a warning window.",
            SCORE_TOKEN: "{score}",
        }),

        EXCEPTION_TEXT: Object.freeze({
            [EXCEPTION.KNOWN_BAD]:     "flagged as malicious by a threat-intelligence service",
            [EXCEPTION.IMPERSONATION]: "imitates a brand or a popular site",
            [EXCEPTION.FILE_ITSELF]:   "the file itself looks deceptive or is runnable code",
            [EXCEPTION.LURE_ROUTE]:    "the link was opened from a chat or webmail page",
            [EXCEPTION.YOUNG_DOMAIN]:  "the domain is very new",
        }),
    });

    function isCountable(entry) {
        return !!entry && (entry.score ?? 0) < 0 && !entry.explained;
    }

    function hasSource(entries, sources) {
        return entries.some(e => isCountable(e) && sources.includes(e.source));
    }

    const DETECT = Object.freeze({
        [EXCEPTION.KNOWN_BAD]:     (entries, ctx) => hasSource(entries, CONFIG.KNOWN_BAD_SOURCES)
                                                     || (ctx.vtMalicious ?? 0) >= CONFIG.VT_FLAGGED_MIN,
        [EXCEPTION.IMPERSONATION]: (entries) => hasSource(entries, CONFIG.IMPERSONATION_SOURCES),
        [EXCEPTION.FILE_ITSELF]:   (entries) => entries.some(e => isCountable(e)
                                                     && CombinationScoring.questionOf(e.source) === CombinationScoring.QUESTION.WHAT),
        [EXCEPTION.LURE_ROUTE]:    (entries) => hasSource(entries, CONFIG.LURE_ROUTE_SOURCES),
        [EXCEPTION.YOUNG_DOMAIN]:  (entries) => entries.some(e => isCountable(e)
                                                     && CONFIG.YOUNG_DOMAIN_SOURCES.includes(e.source)
                                                     && e.score <= APP.RDAP_YOUNG_SCORE),
    });

    function exceptionsFound(check, entries, ctx = {}) {
        const list = Array.isArray(entries) ? entries : [];
        return (CONFIG.EXCEPTIONS_FOR[check] || []).filter(ex => DETECT[ex](list, ctx));
    }

    function decide(score, threshold, exceptions) {
        const byScore = threshold === null || (typeof score === "number" && score <= threshold);
        return { warn: byScore || exceptions.length > 0, threshold, exceptions };
    }

    function downloadDecision({ combinedScore, fpLevel = null, entries = [], vtMalicious = 0 }) {
        const levels = CONFIG.DOWNLOAD_WARN_FROM;
        const threshold = Object.prototype.hasOwnProperty.call(levels, fpLevel) ? levels[fpLevel] : levels[CONFIG.DEFAULT_FP_LEVEL];
        return decide(combinedScore, threshold, exceptionsFound(CHECK.DOWNLOAD, entries, { vtMalicious }));
    }

    function siteDecision({ score, threshold, entries = [] }) {
        return decide(score, threshold ?? null, exceptionsFound(CHECK.SITE, entries));
    }

    function exceptionText(exception) {
        return CONFIG.EXCEPTION_TEXT[exception] ?? exception;
    }

    function windowHint(fpLevel, formatScore = String) {
        const levels = CONFIG.DOWNLOAD_WARN_FROM;
        if (!Object.prototype.hasOwnProperty.call(levels, fpLevel)) return "";
        const from = levels[fpLevel];
        return from === null ? CONFIG.WINDOW_HINT.ALWAYS
                             : CONFIG.WINDOW_HINT.FROM_SCORE.replace(CONFIG.WINDOW_HINT.SCORE_TOKEN, formatScore(from));
    }

    return { CHECK, EXCEPTION, CONFIG, exceptionsFound, downloadDecision, siteDecision, exceptionText, windowHint };
})();
