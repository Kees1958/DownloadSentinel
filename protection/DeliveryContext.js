"use strict";

// ── DeliveryContext.js ────────────────────────────────────────────────────────
// v3.5.0 — context step between "every signal scored" and "signals combined"
// (ScoringEngineV2.evaluateHostReputation). Reasons about the download as a
// real-world delivery instead of a pile of independent numbers:
//
//   1. EXPLAIN — a route quirk (unrelated referrer, extension hidden until the
//      file landed, short link, link from a chat, HTTPS→HTTP via a mirror) is
//      "explained" when a hard anchor shows it is how this delivery normally
//      works (util/DeliveryPatterns.js: vendor-owned delivery host, mirror
//      network, the platform's own download link). Explained signals are
//      still shown, at score 0 with the reason, but do not count.
//      Never when anything is wrong with WHO sends the file (identity lists,
//      domain age, TLD) — except that a platform's own download link may be
//      explained on that platform's risky-host entry (the risky score stays).
//      Never for WHAT the file is (disguise, format, content).
//   2. CLUSTER — weak signals (score −1 … −14, weaker than
//      CombinationScoring.CONFIG.STACK_MIN_SIGNAL) never stack on their own.
//      When enough of them, from DIFFERENT families, occur together, they are
//      summed into one WeakSignalCluster signal (which does stack). One fewer
//      is needed on an open upload platform (a RiskyHosting host), where a
//      good platform reputation says nothing about the uploaded file.
//   3. CREDIT — "established, well-known site": a small positive score when
//      the host is on the top-sites list, HTTPS, DNS-resolved, and nothing is
//      wrong with WHO or WHAT. Applied after combination; never cancels a
//      deception signal (it does not apply when one exists).
//
// Which of these run, and the cluster threshold, is a per-FP-level STRATEGY
// (CONFIG.FP_STRATEGIES) instead of only a score multiplier.
//
// Public interface:
//   DeliveryContext.CONFIG
//   DeliveryContext.strategyFor(fpLevel)            -> frozen strategy
//   DeliveryContext.apply({ results, url, originalUrl, fpLevel })
//       -> { scoring, display }
//          scoring: entries to combine (explained ones removed, cluster added)
//          display: every entry for the breakdown (explained ones at 0 + reason)
//   DeliveryContext.creditFor({ scoring, url, isHttps, dnsResolved, fpLevel, isTopSite })
//       -> credit entry { score, label, source } | null
//
// Pure: no chrome.* access, no shared mutable state; input arrays are never
// mutated (entries are copied before being changed).
// Dependencies: CombinationScoring.js (families/questions), DeliveryPatterns.js.
// ─────────────────────────────────────────────────────────────────────────────
import { CombinationScoring } from "./CombinationScoring.js";
import { DeliveryPatterns } from "../util/DeliveryPatterns.js";

export const DeliveryContext = (function () {

    const QUESTION   = CombinationScoring.QUESTION;
    const questionOf = CombinationScoring.questionOf;
    function familyOf(source) { return CombinationScoring.FAMILY_MAP[source] ?? null; }

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIG — every knob of this step, in one place.
    // ─────────────────────────────────────────────────────────────────────────
    const CONFIG = Object.freeze({
        // FP reduction level → how the extension reasons (not only how hard it
        // scores; the VT-unknown multiplier in SCORING_CONFIG still applies).
        //   explainRouteQuirks  recognised delivery patterns stop counting
        //   weakClusterMin      weak signals from this many families add up
        //   establishedCredit   the "established, well-known site" credit
        FP_STRATEGIES: Object.freeze({
            HIGH:   Object.freeze({ explainRouteQuirks: true,  weakClusterMin: 4, establishedCredit: true  }),
            MEDIUM: Object.freeze({ explainRouteQuirks: true,  weakClusterMin: 3, establishedCredit: true  }),
            LOW:    Object.freeze({ explainRouteQuirks: false, weakClusterMin: 2, establishedCredit: false }),
            NONE:   Object.freeze({ explainRouteQuirks: false, weakClusterMin: 2, establishedCredit: false }),
        }),
        DEFAULT_FP_LEVEL: "MEDIUM",            // when a caller passes none (older callers, tests)

        OPEN_PLATFORM_CLUSTER_RELIEF: 1,       // one fewer weak signal needed on a RiskyHosting host
        WEAK_CLUSTER_MIN_FLOOR:       2,       // a "cluster" is never a single signal
        WEAK_CLUSTER_FLOOR:         -45,       // the summed cluster never scores below this

        ESTABLISHED_SITE_CREDIT:     10,       // positive score of the credit

        // Route signals and what can explain each. Keys are breakdown sources.
        //   vendor   final download host is vendor-owned (DeliveryPatterns.vendorOf)
        //   mirror   the ORIGINAL url is a mirror-network redirector
        //   platform the original or final url is a platform's own download link
        EXPLAINABLE: Object.freeze({
            ReferrerMismatch:  Object.freeze(["vendor"]),
            UrlShortener:      Object.freeze(["vendor"]),
            MessageOrigin:     Object.freeze(["vendor"]),
            HiddenExtension:   Object.freeze(["vendor", "platform"]),
            ProtocolDowngrade: Object.freeze(["mirror"]),
        }),
        // Warning-page wording (plain language, one place). An explained row
        // shows EXPLAINED_TEXT + " — normal for <reason>"; the original label
        // is kept on the entry as `rawLabel`.
        EXPLAINED_TEXT: Object.freeze({
            ReferrerMismatch:  "Downloaded from a different site than the page you came from",
            UrlShortener:      "Opened through a short link",
            MessageOrigin:     "Link opened from a chat or webmail page",
            HiddenExtension:   "No file extension visible in the link",
            ProtocolDowngrade: "Switched from HTTPS to HTTP during the download",
        }),
        // Plain names of weak oddities, for the cluster row.
        ODDITY_NAMES: Object.freeze({
            ReferrerMismatch: "unrelated referring page",
            MessageOrigin:    "link from a chat or webmail",
            UrlShortener:     "short link",
            RDAP:             "fairly new domain",
            RiskyHosting:     "file-sharing host",
            TldList:          "often-abused domain ending",
            SketchyUrl:       "odd-looking link",
            HostList:         "host on a risk list",
            DomainList:       "domain on a risk list",
            StagingKeywords:  "lure words",
            HiddenExtension:  "no extension in the link",
        }),

        // WHO sources a "platform" explanation may coexist with (the risky-host
        // entry of that very platform); every other WHO signal still blocks.
        PLATFORM_TOLERATED_WHO: Object.freeze(new Set(["RiskyHosting"])),
    });

    function strategyFor(fpLevel) {
        return CONFIG.FP_STRATEGIES[fpLevel] ?? CONFIG.FP_STRATEGIES[CONFIG.DEFAULT_FP_LEVEL];
    }

    function isNegative(entry) { return (entry.score ?? 0) < 0; }

    // The anchors present for this download, computed once.
    function anchorsFor(url, originalUrl) {
        const vendor   = DeliveryPatterns.vendorOf(url);
        const mirror   = originalUrl && originalUrl !== url ? DeliveryPatterns.mirrorNetworkOf(originalUrl) : null;
        const platform = DeliveryPatterns.platformDownloadLinkOf(originalUrl) || DeliveryPatterns.platformDownloadLinkOf(url);
        return { vendor, mirror, platform };
    }

    function reasonFor(kind, anchors) {
        if (kind === "vendor"   && anchors.vendor)   return `${anchors.vendor} downloads`;
        if (kind === "mirror"   && anchors.mirror)   return `the ${anchors.mirror}`;
        if (kind === "platform" && anchors.platform) return `${anchors.platform}'s own download link`;
        return null;
    }

    // ── 1. EXPLAIN ───────────────────────────────────────────────────────────
    function explain(results, anchors) {
        const whoSources = results.filter(r => isNegative(r) && questionOf(r.source) === QUESTION.WHO).map(r => r.source);
        const anyWho     = whoSources.length > 0;
        const onlyTolerated = anyWho && whoSources.every(s => CONFIG.PLATFORM_TOLERATED_WHO.has(s));

        return results.map(entry => {
            const kinds = CONFIG.EXPLAINABLE[entry.source];
            if (!kinds || !isNegative(entry)) return entry;
            for (const kind of kinds) {
                const allowed = !anyWho || (kind === "platform" && onlyTolerated);
                const reason  = allowed ? reasonFor(kind, anchors) : null;
                if (reason) {
                    const text = CONFIG.EXPLAINED_TEXT[entry.source] ?? entry.label;
                    return { ...entry, score: 0, explained: true, rawScore: entry.score, rawLabel: entry.label,
                             label: `${text} — normal for ${reason}` };
                }
            }
            return entry;
        });
    }

    // ── 2. CLUSTER ───────────────────────────────────────────────────────────
    // Worst entry per family; a family counts as "weak" only when even its
    // worst member is weaker than the stacking floor.
    function weakFamilies(results) {
        const worst = new Map();
        for (const entry of results) {
            const family = familyOf(entry.source);
            if (!family || !isNegative(entry) || entry.explained) continue;
            if (!questionOf(entry.source)) continue;                       // NEUTRAL / CLUSTER never count
            const cur = worst.get(family);
            if (!cur || entry.score < cur.score) worst.set(family, entry);
        }
        return [...worst.values()].filter(e => e.score > CombinationScoring.CONFIG.STACK_MIN_SIGNAL);
    }

    function clusterFor(results, strategy) {
        const weak = weakFamilies(results);
        const openPlatform = results.some(r => r.source === "RiskyHosting" && isNegative(r));
        const needed = Math.max(CONFIG.WEAK_CLUSTER_MIN_FLOOR,
            strategy.weakClusterMin - (openPlatform ? CONFIG.OPEN_PLATFORM_CLUSTER_RELIEF : 0));
        if (weak.length < needed) return null;
        const sum = weak.reduce((acc, e) => acc + e.score, 0);
        return {
            score:  Math.max(CONFIG.WEAK_CLUSTER_FLOOR, sum),
            label:  `${weak.length} small oddities together${openPlatform ? " on a file-sharing platform" : ""}: ` +
                    weak.map(e => CONFIG.ODDITY_NAMES[e.source] ?? e.source).join(", "),
            source: "WeakSignalCluster",
            meta:   { members: weak.map(e => e.source), openPlatform },
        };
    }

    function apply({ results, url, originalUrl = null, fpLevel = null }) {
        const strategy  = strategyFor(fpLevel);
        const anchors   = anchorsFor(url, originalUrl);
        const display   = strategy.explainRouteQuirks ? explain(results, anchors) : results.slice();
        const scoring   = display.filter(e => !e.explained);
        const cluster   = clusterFor(scoring, strategy);
        if (cluster) { scoring.push(cluster); display.push(cluster); }
        return { scoring, display };
    }

    // ── 3. CREDIT ────────────────────────────────────────────────────────────
    function creditFor({ scoring, url, isHttps, dnsResolved, fpLevel = null, isTopSite }) {
        if (!strategyFor(fpLevel).establishedCredit) return null;
        if (!isHttps || !dnsResolved || !isTopSite) return null;
        const blocked = scoring.some(r => isNegative(r)
            && (questionOf(r.source) === QUESTION.WHO || questionOf(r.source) === QUESTION.WHAT));
        if (blocked) return null;
        let host = "";
        try { host = new URL(url).hostname; } catch { /* label falls back to no host */ }
        return {
            score:  CONFIG.ESTABLISHED_SITE_CREDIT,
            label:  `Established, well-known site${host ? ` (${host})` : ""} with nothing wrong about the sender or the file`,
            source: "EstablishedSite",
        };
    }

    return { CONFIG, strategyFor, apply, creditFor };
})();
