"use strict";

// ── CombinationScoring.js ─────────────────────────────────────────────────────
// Heuristics plan Step 3 (v2.9.0): combine several independent host-reputation
// signals instead of "worst single signal wins" (the model used through
// v2.8.0). Several real risk indicators firing together are worse than any
// one of them alone; this module lets them add up, with decay, while
// signals that measure the same underlying thing are grouped into "families"
// so they cannot inflate each other by being counted twice.
//
// v3.5.6 — small signals (weaker than STACK_MIN_SIGNAL) stack ONLY when the
// heuristics are the only indicator we have AND the source is dubious (user
// decision 2026-11-09):
//   * VirusTotal knows the file (it gave a verdict, clean or not): small
//     signals never stack — VT is the stronger evidence.
//   * VirusTotal does not know it (no key, no answer in time, never seen),
//     or there is no VirusTotal at all (3P Matrix's site check): small
//     signals stack, with the same decay, when the source is dubious — a
//     host on a misused-for-malware / file-sharing / campaign / host-threat
//     list, an abused TLD, a very young domain or a DNS threat hit
//     (DUBIOUS_SOURCES, isDubiousSource()).
// Only ADDING UP changes: whether a small signal counts as "corroborating"
// (the RiskyHosting solo rule, ScoringEngineV2 Check 10b / 3P Matrix's site
// platform rule) stays at STACK_MIN_SIGNAL — a small route quirk must not
// also double a platform's score (FP sweep: 7-Zip via SourceForge).
// A WeakSignalCluster (DeliveryContext) already sums the small signals in
// full; when one is present they do not stack a second time individually.
//
// Public interface:
//   CombinationScoring.combineHostResults(results, { heuristicsOnly } = {})
//   CombinationScoring.smallSignalsStack(results, { heuristicsOnly } = {}) -> boolean (v3.5.6)
//   CombinationScoring.canStack(score, smallStack)  -> boolean (v3.5.6)
//   CombinationScoring.isDubiousSource(results)     -> boolean (v3.5.6)
//       — results: array of { score, label, source, meta? } exactly as
//         ScoringEngineV2.evaluateHostReputation() already builds (meta is
//         optional, per-entry extra data a combination rule may need — e.g.
//         StagingKeywords' command-vs-lure split for rules C3/C5).
//       — returns { score, label, source, signalCount, combined, firedRules }
//
// Dependencies: util/AppConstants.js (RDAP "very young" score, v3.5.6); pure
// function/data only — no chrome.* access, no shared mutable state.
//
// State owned: none — FAMILY_MAP, CONFIG and COMBO_RULES are built once and
// frozen at module load (B3a/B8 — stateless constants), same convention as
// StagingCheck.js.
// ─────────────────────────────────────────────────────────────────────────────

import { APP } from "../util/AppConstants.js";

export const CombinationScoring = (function () {

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIG — every magic number for the combination algorithm itself,
    // gathered here (B1). Per-check *scores* (the values a single signal is
    // worth) stay in ScoringEngineV2.js's SCORING_CONFIG, same as always —
    // this block only tunes how multiple already-scored signals combine.
    // ─────────────────────────────────────────────────────────────────────────
    const CONFIG = Object.freeze({
        STACK_DECAY:          0.5,   // 2nd family counts ×0.5, 3rd ×0.25, 4th ×0.125
        MAX_STACKED_FAMILIES: 4,     // more than 4 families contributes nothing further
        STACK_MIN_SIGNAL:    -15,    // weak noise (e.g. GitHub raw's -10 RiskyHosting) never stacks
        COMBO_BONUS_CAP:     -20,    // floor on the SUM of all fired combination-rule bonuses
        STACK_MAX_DELTA:     -35,    // floor on (stack + bonus) together — most that combining
                                      // can add on top of the single worst signal
        // v3.5.6 — a "dubious source": one of these signals fired (negative, not
        // explained). RDAP counts only at "very young" (APP.RDAP_YOUNG_SCORE).
        DUBIOUS_SOURCES: Object.freeze(["DomainList", "RiskyHosting", "HostList", "ActiveThreatHost",
                                        "TldList", "DnsThreat", "RDAP"]),
        DUBIOUS_AGE_SOURCE: "RDAP",
        DUBIOUS_AGE_AT:     APP.RDAP_YOUNG_SCORE,
    });

    // ─────────────────────────────────────────────────────────────────────────
    // Family grouping — within a family, only the worst (most negative)
    // member's score counts; this is what stops, e.g., a HostList hit and an
    // IP-address-as-host hit (both "who/where is this host" signals) from
    // being treated as two independent pieces of evidence when they are
    // really the same underlying observation seen two ways.
    //
    // "NEUTRAL" is not a combining family at all (SizeCheck) — it never
    // stacks with anything, and is only ever reported alone (unchanged from
    // v2.8.0) when it is literally the only signal present.
    // ─────────────────────────────────────────────────────────────────────────
    const FAMILY_MAP = Object.freeze({
        DomainList:        "HOST_IDENTITY",
        HostList:          "HOST_IDENTITY",
        RiskyHosting:      "HOST_IDENTITY",
        IpAddressCheck:    "HOST_IDENTITY",
        RDAP:              "HOST_AGE",
        TldList:           "TLD",
        SketchyUrl:        "URL_SHAPE",
        UrlCredentials:    "URL_SHAPE",
        ProtocolCheck:     "TRANSPORT",
        ProtocolDowngrade: "TRANSPORT",
        ScriptFormat:      "FILE_FORMAT",
        StagingFormat:     "FILE_FORMAT",
        LinuxLauncher:     "FILE_FORMAT",
        DoubleExtension:   "FILE_DECEPTION",
        Obfuscation:       "FILE_DECEPTION",
        MimeCheck:         "FILE_DECEPTION",
        StagingKeywords:   "CONTENT",
        SizeCheck:         "NEUTRAL",

        // ── Heuristics plan "Later steps" (v2.11.0 — Step 5) ──────────────────
        // See protection/FilenameUrlHeuristics.js for each check's detail.
        RloObfuscation:      "FILE_DECEPTION", // same family as DoubleExtension/Obfuscation — a disguised/hidden extension
        PaddedDoubleExtension: "FILE_DECEPTION",
        UrlShortener:        "URL_SHAPE",      // weak/contextual — groups with SketchyUrl/UrlCredentials, not NEUTRAL,
                                                // so it can still contribute a small amount when stacked with something else
        ReferrerMismatch:    "URL_SHAPE",

        // v3.2.0 (3P Matrix alignment §0.2/§1): registered now so DS and 3P
        // Matrix's shared modules stay identical. NonStandardPort has no
        // producing check in DS yet — harmless to have mapped in advance,
        // needed only if/when DS adds a port signal.
        NonStandardPort:     "HOST_IDENTITY",

        // v3.2.0 (3P Matrix alignment §1): one unified check — domain-
        // identity spoofing family, same as DomainList/HostList/
        // IpAddressCheck — replacing the old BrandHomoglyph +
        // LookalikeTopSite pair above (see protection/LookalikeDomainCheck.js).
        LookalikeDomain:     "HOST_IDENTITY",

        // v3.4.0 (heuristic R1): the server hides what the file is — the same
        // "file type concealed" observation as Obfuscation, so same family
        // (only the worst of the two counts if both were ever present).
        ExtensionlessBinary: "FILE_DECEPTION",

        // v3.5.0 — route signals, see FAMILY_QUESTION below.
        HiddenExtension:     "DELIVERY",   // extension only visible after the download landed (was Obfuscation/UNKNOWN_REVEALED)
        MessageOrigin:       "ORIGIN",     // link opened from webmail / chat
        WeakSignalCluster:   "CLUSTER",    // several small oddities together (protection/DeliveryContext.js)
        // v3.5.2 — a brand name in the subdomain of an open platform
        // (paypal-login.vercel.app). URL_SHAPE, not HOST_IDENTITY: it must STACK
        // with the platform's own list hit (HOST_IDENTITY), not be swallowed by it.
        PlatformBrand:       "URL_SHAPE",
    });

    // ─────────────────────────────────────────────────────────────────────────
    // v3.5.0 — the three questions a family answers. Used by
    // protection/DeliveryContext.js: route quirks may be "explained" by a
    // recognised delivery pattern, but only when nothing is wrong with WHO
    // sends the file, and nothing ever explains away WHAT the file is.
    //   WHAT  — the file itself (disguise, format, content)
    //   WHO   — the sender (identity lists, domain age, TLD)
    //   ROUTE — how it travelled (URL shape, transport, delivery, origin)
    // NEUTRAL / CLUSTER are not questions (null).
    // ─────────────────────────────────────────────────────────────────────────
    const QUESTION = Object.freeze({ WHAT: "what", WHO: "who", ROUTE: "route" });
    const FAMILY_QUESTION = Object.freeze({
        FILE_DECEPTION: QUESTION.WHAT,
        FILE_FORMAT:    QUESTION.WHAT,
        CONTENT:        QUESTION.WHAT,
        HOST_IDENTITY:  QUESTION.WHO,
        HOST_AGE:       QUESTION.WHO,
        TLD:            QUESTION.WHO,
        URL_SHAPE:      QUESTION.ROUTE,
        TRANSPORT:      QUESTION.ROUTE,
        DELIVERY:       QUESTION.ROUTE,
        ORIGIN:         QUESTION.ROUTE,
    });

    function questionOf(source) {
        return FAMILY_QUESTION[FAMILY_MAP[source]] ?? null;
    }

    const HOST_AGE_FAMILY = "HOST_AGE"; // the one family whose standalone case is doubled (see below)
    const NEUTRAL_FAMILY  = "NEUTRAL";
    const CLUSTER_FAMILY  = "CLUSTER";   // v3.5.6 — DeliveryContext's WeakSignalCluster

    // ── v3.5.6 — when do small signals stack? (see header) ────────────────────
    function isCounted(entry) { return !!entry && (entry.score ?? 0) < 0 && !entry.explained; }

    function isDubiousSource(results) {
        return Array.isArray(results) && results.some(e => isCounted(e)
            && CONFIG.DUBIOUS_SOURCES.includes(e.source)
            && (e.source !== CONFIG.DUBIOUS_AGE_SOURCE || e.score <= CONFIG.DUBIOUS_AGE_AT));
    }

    function smallSignalsStack(results, { heuristicsOnly = false } = {}) {
        return heuristicsOnly && isDubiousSource(results)
            && !results.some(e => familyOf(e.source) === CLUSTER_FAMILY);   // the cluster already summed them
    }

    // The one stacking test: a negative signal stacks when it is strong enough,
    // or when small signals stack for this download/site (smallSignalsStack).
    function canStack(score, smallStack) {
        return score < 0 && (smallStack || score <= CONFIG.STACK_MIN_SIGNAL);
    }

    function familyOf(source) {
        return FAMILY_MAP[source] || null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Combination rules — each fires at most once, only when ALL of its
    // conditions hold against the worst-per-family scores (and, for C3/C5,
    // the CONTENT entry's command/lure split carried in its `meta`). Bonuses
    // are summed, then floored at CONFIG.COMBO_BONUS_CAP as a group.
    // ─────────────────────────────────────────────────────────────────────────
    const COMBO_RULES = Object.freeze([
        {
            id: "C1", bonus: -10,
            label: "Script or staging file from free/dynamic hosting",
            test: (ctx) => (ctx.familyScore("HOST_IDENTITY") ?? 0) <= -35 && ctx.hasFamily("FILE_FORMAT"),
        },
        {
            id: "C2", bonus: -10,
            label: "Brand-new domain serving a script or disguised file",
            // v3.5.0: DELIVERY added — HiddenExtension left FILE_DECEPTION, and
            // "young domain + extension hidden until it landed" must keep this bonus.
            test: (ctx) => (ctx.familyScore("HOST_AGE") ?? 0) <= -20 &&
                           (ctx.hasFamily("FILE_FORMAT") || ctx.hasFamily("FILE_DECEPTION") || ctx.hasFamily("DELIVERY")),
        },
        {
            id: "C3", bonus: -15,
            label: "Command syntax in the URL of a script download",
            test: (ctx) => ctx.hasCommandContent() && ctx.hasFamily("FILE_FORMAT"),
        },
        {
            id: "C4", bonus: -10,
            label: "Young domain on an abused TLD",
            test: (ctx) => (ctx.familyScore("TLD") ?? 0) <= -25 && (ctx.familyScore("HOST_AGE") ?? 0) <= -20,
        },
        {
            id: "C5", bonus: -10,
            label: "Lure filename with a disguised extension",
            test: (ctx) => ctx.hasLureContent() && ctx.hasFamily("FILE_DECEPTION"),
        },
        {
            id: "C6", bonus: -10,
            label: "Bare IP over unencrypted HTTP",
            test: (ctx) => ctx.hasSource("IpAddressCheck") && ctx.hasFamily("TRANSPORT"),
        },
        {
            // v3.5.0 — the classic lure: a file on an open upload platform
            // (RiskyHosting: Discord attachments, MEGA, Dropbox, raw GitHub …)
            // whose link was clicked in a chat or webmail. Neither alone says
            // much; together they are the typical "free Nitro / invoice"
            // delivery. MessageOrigin also counts as corroboration for the
            // RiskyHosting solo-halving rule (ScoringEngineV2
            // SCORING_CONFIG.RISKY_HOSTING_CORROBORATING_SOURCES).
            id: "C7", bonus: -15,
            label: "File on a file-sharing platform, link opened from a chat or webmail",
            test: (ctx) => ctx.hasSource("RiskyHosting") && ctx.hasSource("MessageOrigin"),
        },
    ]);

    /**
     * Build the lookup context combo rules test against, from the
     * worst-per-family map and the raw entries (for per-source/meta checks
     * no family-level score can express — C3/C5/C6).
     */
    function buildRuleContext(worstPerFamily, entries) {
        const bySource = new Map(entries.map(e => [e.source, e]));
        return {
            familyScore: (family) => worstPerFamily.has(family) ? worstPerFamily.get(family).score : undefined,
            hasFamily:   (family) => worstPerFamily.has(family),
            hasSource:   (source) => bySource.has(source),
            hasCommandContent: () => !!bySource.get("StagingKeywords")?.meta?.hasCommandSignal,
            hasLureContent:    () => !!bySource.get("StagingKeywords")?.meta?.hasLureSignal,
        };
    }

    /**
     * @param {Array<{score:number, label:string, source:string, meta?:object}>} results
     *        Every non-zero host-reputation signal gathered so far (same
     *        array ScoringEngineV2.evaluateHostReputation() already builds).
     *        Must NOT include a Quad9 hard-rule entry — the caller handles
     *        that short-circuit before calling this (Step 3 algorithm step 1).
     * @returns {{score:number, label:string, source:string, signalCount:number,
     *            combined:boolean, firedRules:string[]}}
     */
    function combineHostResults(results, { heuristicsOnly = false } = {}) {
        if (!Array.isArray(results) || results.length === 0) {
            return { score: 0, label: null, source: null, signalCount: 0, combined: false, firedRules: [] };
        }

        // Worst (most negative) entry per family — NEUTRAL excluded entirely,
        // tracked separately only as a last-resort fallback (see below).
        const worstPerFamily = new Map();
        let worstNeutral = null;
        const smallStack = smallSignalsStack(results, { heuristicsOnly });   // v3.5.6

        for (const entry of results) {
            const family = familyOf(entry.source);
            // A source missing from FAMILY_MAP (should never happen — see
            // tests/CombinationScoring.test.js's data-integrity check — but
            // if a future check ever forgets to register one) degrades
            // safely by falling into the same bucket as NEUTRAL: reported
            // alone if it's the only thing present, never silently dropped,
            // never allowed to combine/stack with anything else.
            if (!family || family === NEUTRAL_FAMILY) {
                if (!worstNeutral || entry.score < worstNeutral.score) worstNeutral = entry;
                continue;
            }
            const current = worstPerFamily.get(family);
            if (!current || entry.score < current.score) worstPerFamily.set(family, entry);
        }

        // No family-grouped signal at all — only a NEUTRAL one (or nothing).
        // Falls back to exactly the NEUTRAL entry alone, same as v2.8.0.
        if (worstPerFamily.size === 0) {
            if (!worstNeutral) return { score: 0, label: null, source: null, signalCount: 0, combined: false, firedRules: [] };
            return {
                score: worstNeutral.score, label: worstNeutral.label, source: worstNeutral.source,
                signalCount: 1, combined: false, firedRules: []
            };
        }

        // Exactly one family present — identical to v2.8.0's single-signal
        // output. RDAP is the one case needing a transform: v2.8.0 doubled
        // RDAP's raw score when it was the ONLY signal available (no other
        // signal to lean on, so the age signal alone is weighted more
        // heavily); that doubling is applied here, at output time, rather
        // than baked into RDAP's stored score, so the same raw score can
        // also be used un-doubled when it combines with other families below.
        if (worstPerFamily.size === 1) {
            const [[family, entry]] = worstPerFamily;
            const score = family === HOST_AGE_FAMILY
                ? Math.max(-100, entry.score * 2)
                : entry.score;
            return { score, label: entry.label, source: entry.source, signalCount: 1, combined: false, firedRules: [] };
        }

        // Two or more families — combine.
        const ranked = [...worstPerFamily.values()].sort((a, b) => a.score - b.score); // most negative first
        const base = ranked[0];

        let stack = 0;
        for (let i = 1; i < Math.min(ranked.length, CONFIG.MAX_STACKED_FAMILIES); i++) {
            const score = ranked[i].score;
            if (canStack(score, smallStack)) {
                stack += score * Math.pow(CONFIG.STACK_DECAY, i);
            }
        }

        const ctx = buildRuleContext(worstPerFamily, results);
        const firedRules = [];
        let bonus = 0;
        for (const rule of COMBO_RULES) {
            if (rule.test(ctx)) { bonus += rule.bonus; firedRules.push(rule.id); }
        }
        bonus = Math.max(bonus, CONFIG.COMBO_BONUS_CAP); // floor the group total, not each rule

        const extra = Math.max(stack + bonus, CONFIG.STACK_MAX_DELTA);
        const score = Math.max(-100, Math.round(base.score + extra));

        return {
            score, label: base.label, source: base.source,
            signalCount: ranked.length, combined: true, firedRules, smallSignalsStacked: smallStack
        };
    }

    return {
        combineHostResults,
        smallSignalsStack, // v3.5.6
        canStack,          // v3.5.6
        isDubiousSource,   // v3.5.6
        // Exposed for tests and for anything that wants to introspect the
        // model without duplicating it (e.g. a future admin/debug view).
        FAMILY_MAP,
        CONFIG,
        COMBO_RULES,
        QUESTION,          // v3.5.0
        FAMILY_QUESTION,   // v3.5.0
        questionOf,        // v3.5.0
    };

})();
