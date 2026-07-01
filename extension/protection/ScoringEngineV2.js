"use strict";

/**
 * ScoringEngineV2.js
 *
 * Scores a download URL across two independent axes:
 *
 *   A. VirusTotal URL reputation
 *      Weights: detection 70 %, age (VT first-seen) 30 %
 *      Community score removed.
 *
 *   B. Host reputation  (five parallel checks)
 *      1. Quad9 DNS block check
 *      2. RDAP registration age  (only when Quad9 resolves the domain)
 *         • Standalone signal (no domain/TLD/URL hit): score × 2  (e.g. < 30 days → −40)
 *         • Combined with domain/TLD/URL hit: capped at −20 (supporting signal)
 *      3. Suspicious-domain list match  (domain score × VT-suspicious-≥9 multiplier, base −70)
 *      4. Suspicious-TLD list match     (TLD score   × VT-suspicious-5–9 multiplier, base −50)
 *      5. Sketchy URL pattern heuristics (SketchyUrlCheck score × base −35)
 *      6. MIME type vs file extension consistency (mismatch → −60, consistent → 0)
 *      7. File size vs VirusTotal maximum 650 MB  (exceeds → −20)
 *      8. HTTP protocol (when Quad9 resolves domain)  → −40
 *      9. IP address as download host               → −30
 *     10. Risky hosting platform                    → −15 to −80
 *
 *   The caller (BrowserProtection / background.js) runs both axes in parallel
 *   and reports whichever produces the worst (lowest) final score.
 */
const ScoringEngineV2 = (function () {

    const Classification = {
        PROBABLY_SAFE:         "Probably Safe",
        PROBABLY_QUESTIONABLE: "Probably Inconclusive",
        PROBABLY_SUSPICIOUS:   "Probably Suspicious",
        PROBABLY_MALICIOUS:    "Probably Malicious"
    };

    const SECONDS_PER_DAY = 86400;

    // ─────────────────────────────────────────────────────────────────────────
    // A.1  Detection Score  (VT analysis stats)
    //      Age-weighted: recent first-seen dates amplify negative signals.
    // ─────────────────────────────────────────────────────────────────────────
    function scoreDetection(stats, ageDays) {

        const malicious  = stats.malicious  ?? 0;
        const suspicious = stats.suspicious ?? 0;
        const harmless   = stats.harmless   ?? 0;

        const under2 = ageDays !== null && ageDays < 2;
        const under7 = ageDays !== null && ageDays < 7;

        // ── Malicious ────────────────────────────────────────────────────────
        if (malicious >= 5) {
            return { score: -100, label: "≥ 5 malicious detections" };
        }
        if (malicious >= 3) {
            const score = Math.round(-80 * (under7 ? 1.0 : 0.5));
            return { score, label: "3–4 malicious detections" };
        }
        if (malicious >= 1) {
            const mult  = under2 ? 1.0 : under7 ? 0.5 : 0.1;
            const score = Math.round(-60 * mult);
            const label = malicious === 1 ? "1 malicious detection" : "2 malicious detections";
            return { score, label };
        }

        // ── Suspicious ───────────────────────────────────────────────────────
        if (suspicious >= 10) {
            return { score: -70, label: "≥ 10 suspicious detections" };
        }
        if (suspicious >= 5) {
            const score = Math.round(-50 * (under7 ? 1.0 : 0.5));
            return { score, label: "5–9 suspicious detections" };
        }
        if (suspicious >= 3) {
            const score = Math.round(-30 * (under7 ? 1.0 : 0.5));
            return { score, label: "3–4 suspicious detections" };
        }
        if (suspicious === 2) {
            const mult  = under2 ? 1.5 : under7 ? 1.0 : 0.1;
            const score = Math.round(-20 * mult);
            return { score, label: "2 suspicious detections" };
        }
        if (suspicious === 1) {
            const mult  = under2 ? 2.0 : under7 ? 1.0 : 0.5;
            const score = Math.round(-15 * mult);
            return { score, label: "1 suspicious detection" };
        }

        // Clean file — apply longevity bonus + ABC consensus bonus.
        // Longevity: file has been in VT's database long enough to be scrutinised.
        // ABC bonus: rewards clean consensus across many engines (see evaluate()).
        if (harmless > 0) {
            const over30      = ageDays !== null && ageDays >= 30;
            const over7       = ageDays !== null && ageDays >= 7;
            const longevity   = over30 ? 30 : over7 ? 10 : 0;
            const score       = 30 + longevity + (arguments[2] || 0); // abcBonus passed as 3rd arg
            const label       = over30
                ? "No malicious detections (established file)"
                : "No malicious detections";
            return { score, label };
        }
        return { score: 10, label: "Undetected" };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A.2  VT First-Seen Age Score
    //      Cut-points: < 2 days → −20,  2–7 days → −10,  > 7 days → 0
    // ─────────────────────────────────────────────────────────────────────────
    function scoreVtAge(firstSubmissionDate) {

        if (firstSubmissionDate === null || firstSubmissionDate === undefined) {
            return { score: 0, ageDays: null, label: "Unknown age" };
        }

        const ageDays = (Date.now() / 1000 - firstSubmissionDate) / SECONDS_PER_DAY;
        const days    = Math.max(0, Math.floor(ageDays));

        if (ageDays > 7)  return { score:   0, ageDays, label: `${days} days since first seen` };
        if (ageDays > 2)  return { score: -10, ageDays, label: `${days} days since first seen` };
        return                   { score: -20, ageDays, label: `${days} days since first seen` };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A.3  Confidence (VT axis only — reflects data richness, not score)
    // ─────────────────────────────────────────────────────────────────────────
    function computeVtConfidence(ageDays) {
        if (ageDays === null || ageDays === undefined) return "Low";
        if (ageDays > 180) return "High";
        if (ageDays >= 30) return "Medium";
        return "Low";
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A.4  Hard Rules (VT axis — override score-based classification)
    // ─────────────────────────────────────────────────────────────────────────
    function applyHardRules(malicious, suspicious) {
        if (malicious >= 5) {
            return { classification: Classification.PROBABLY_MALICIOUS, reason: "≥ 5 malicious detections" };
        }
        if (suspicious >= 10) {
            return { classification: Classification.PROBABLY_MALICIOUS, reason: "≥ 10 suspicious detections" };
        }
        if (malicious >= 1) {
            return {
                classification: Classification.PROBABLY_SUSPICIOUS,
                reason: `${malicious} malicious detection${malicious > 1 ? "s" : ""}`
            };
        }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Score → Classification  (shared by both axes)
    // ─────────────────────────────────────────────────────────────────────────
    function classifyByScore(score) {
        if (score >= 40)  return Classification.PROBABLY_SAFE;
        if (score >= -30) return Classification.PROBABLY_QUESTIONABLE;
        if (score >= -60) return Classification.PROBABLY_SUSPICIOUS;
        return Classification.PROBABLY_MALICIOUS;
    }

    // =========================================================================
    // B.  Host Reputation Scoring
    //
    // Base multipliers come from VT detection tiers:
    //   suspicious ≥ 9  → −70  (used for domain-list check)
    //   suspicious 5–8  → −50  (used for TLD check)
    //
    // The domain-list/TLD risk score (0–100) acts as a proportion of that
    // multiplier, e.g. a domain with score 80 contributes 80/100 × −70 = −56.
    //
    // RDAP registration age is applied additively after the base score, using
    // the 30-day cut-point:
    //   < 30 days  →  −20
    //   30–90 days →  −10
    //   > 90 days  →    0
    // =========================================================================

    const DOMAIN_BASE_SCORE = -70;   // corresponds to VT suspicious ≥ 9 class
    const TLD_BASE_SCORE    = -50;   // corresponds to VT suspicious 5–8 class
    const SKETCHY_URL_BASE  = -35;   // heuristic only — lower confidence than list hits

    /**
     * Evaluate host reputation from the four parallel checks.
     *
     * @param {object} params
     * @param {object} params.quad9          - result from Quad9Protection.check()
     * @param {object} params.rdap           - result from RdapProtection.check()
     * @param {object|null} params.domainHit  - result from SuspiciousDomains.lookup()
     * @param {object|null} params.tldHit     - result from SuspiciousTlds.lookup()
     * @param {object|null} params.sketchyUrl - result from SketchyUrlCheck.check()
     * @param {string} params.fileType        - "executable" | "archive"
     */
    function evaluateHostReputation({ quad9, rdap, domainHit, tldHit, sketchyUrl, mimeResult, sizeResult, riskyHosting, url, fileType = "executable", isScript = false }) {

        const results = [];

        // ── Check 1: Quad9 block ─────────────────────────────────────────────
        if (quad9) {
            if (quad9.status === "BLOCKED") {
                const label = `Confirmed malicious (${fileType} from Quad9-blocked domain)`;
                results.push({ score: -100, label, source: "Quad9" });
            }
            // ALLOWED / UNKNOWN contribute 0; RDAP and domain/TLD checks add their own signals
        }

        // ── RDAP age penalty ──────────────────────────────────────────────────
        // Two modes depending on whether a domain/TLD list hit is also present:
        //   • Standalone (no domainHit, no tldHit): full score × 2 multiplier
        //     e.g. < 30 days → −30 × 2 = −40  (young domain is the only signal)
        //   • Combined with domainHit/tldHit: capped at −20 (supporting signal only)
        const rdapRaw   = rdap?.score ?? 0;
        const rdapLabel = rdap?.label ?? "Registration age unknown";
        // Parse URL once for protocol + IP checks
        let parsedUrl = null;
        try { parsedUrl = new URL(url || ""); } catch {}
        const isHttp    = parsedUrl && parsedUrl.protocol === "http:";
        const isIpHost  = parsedUrl && /^\d+\.\d+\.\d+\.\d+$/.test(parsedUrl.hostname);

        const hasListHit = !!(domainHit || tldHit || (sketchyUrl && sketchyUrl.score > 0) || (mimeResult && mimeResult.score < 0) || isHttp || isIpHost || riskyHosting || isScript);

        // Score used additively inside domain/TLD combined entries
        const rdapAdditive = rdapRaw < 0 ? Math.max(rdapRaw, -20) : 0;

        // Score used when RDAP is the only signal (2× multiplier)
        const rdapStandalone = rdapRaw < 0 ? Math.max(rdapRaw * 2, -100) : 0;

        if (quad9?.status === "ALLOWED" && rdapRaw < 0 && !hasListHit) {
            results.push({
                score:  rdapStandalone,
                label:  `New domain registration: ${rdap.label}`,
                source: "RDAP"
            });
        }

        // ── Check 3: Suspicious domain list ──────────────────────────────────
        if (domainHit) {
            const baseScore      = Math.round((domainHit.score / 100) * DOMAIN_BASE_SCORE);
            const combined       = Math.max(-100, baseScore + rdapAdditive);
            results.push({
                score:  combined,
                label:  `Suspicious domain "${domainHit.matchedDomain}"`,
                source: "DomainList"
            });
        }

        // ── Check 4: Suspicious TLD ───────────────────────────────────────────
        if (tldHit) {
            const baseScore   = Math.round((tldHit.score / 100) * TLD_BASE_SCORE);
            const combined    = Math.max(-100, baseScore + rdapAdditive);
            results.push({
                score:  combined,
                label:  `Top Level Domain .${tldHit.tld} is on the much abused TLD list`,
                source: "TldList"
            });
        }

        // ── Check 5: Sketchy URL pattern heuristics ──────────────────────────
        if (sketchyUrl && sketchyUrl.score > 0) {
            const baseScore = Math.round((sketchyUrl.score / 100) * SKETCHY_URL_BASE);
            const combined  = Math.max(-100, baseScore + rdapAdditive);
            const topSignal = (sketchyUrl.signals && sketchyUrl.signals[0]) || "Suspicious URL pattern";
            // Strip the score suffix from signal text e.g. "(+20)" or "(+15)"
            const cleanSignal = topSignal.replace(/\s*\(\+\d+\).*$/, "").trim();
            results.push({
                score:  combined,
                label:  `Suspicious URL pattern: ${cleanSignal}`,
                source: "SketchyUrl"
            });
        }

        // ── Check 6: MIME type consistency ───────────────────────────────────
        if (mimeResult && !mimeResult.neutral) {
            if (mimeResult.score < 0) {
                results.push({
                    score:  Math.max(-100, mimeResult.score + rdapAdditive),
                    label:  `File extension ".${mimeResult.ext || ""}" does not match MIME type "${mimeResult.mime || ""}"`,
                    source: "MimeCheck"
                });
            }
            // Consistent result (score 0) — added as informational after scoring
        }

        // ── Check 7: File size vs VirusTotal maximum ──────────────────────────
        if (sizeResult && sizeResult.exceeds) {
            results.push({
                score:  sizeResult.score,
                label:  "File size exceeds scan maximum, only use if you are 100% certain it is safe",
                source: "SizeCheck"
            });
        }

        // ── Check 8: HTTP protocol ───────────────────────────────────────────
        // Only penalise when Quad9 confirms the domain resolves (ALLOWED).
        // If blocked or unknown, other signals already cover the risk.
        if (isHttp && quad9?.status === "ALLOWED") {
            results.push({
                score:  -40,
                label:  "Download served over unencrypted HTTP (not HTTPS)",
                source: "ProtocolCheck"
            });
        }

        // ── Check 9: IP address as download host ──────────────────────────────
        if (isIpHost) {
            results.push({
                score:  -30,
                label:  `Download served from IP address ${parsedUrl.hostname}`,
                source: "IpAddressCheck"
            });
        }

        // ── Check 10: Risky hosting platform ─────────────────────────────────
        if (riskyHosting) {
            results.push({
                score:  riskyHosting.score,
                label:  riskyHosting.label,
                source: "RiskyHosting"
            });
        }

        // ── Check 11: Script format (LOLBin-style interpreted scripts) ────────
        // A download that is a raw script (.ps1, .vbs, .sh, .py, etc.) rather
        // than a compiled binary is a meaningful anomaly: legitimate software
        // distribution overwhelmingly ships compiled installers, not bare
        // scripts. Scripts execute via a trusted system interpreter (LOLBin
        // technique), which is a common malware delivery and evasion pattern.
        // -25: notable signal on its own, but not enough alone to reach the
        // "probably malicious" threshold (-60) since legitimate scripts
        // (setup.sh, install.py, dev tooling) do exist.
        if (isScript) {
            results.push({
                score:  -25,
                label:  "The download is a script, not a program — this is suspicious",
                source: "ScriptFormat"
            });
        }

        if (results.length === 0) {
            // All checks passed with no negative signals — report as Probably Clean.
            // Score 0 maps to PROBABLY_QUESTIONABLE by threshold, so we override
            // the classification directly to PROBABLY_SAFE here.
            return {
                score:           0,
                classification:  Classification.PROBABLY_SAFE,
                label:           "No alarming signals found — domain probably safe",
                hardRuleApplied: null,
                breakdown:       []
            };
        }

        // Worst (lowest) score wins — SketchyUrl always shown last in breakdown
        const LAST_SOURCES = new Set(["SketchyUrl", "IpAddressCheck", "ProtocolCheck", "RiskyHosting"]);
        results.sort((a, b) => {
            const aLast = LAST_SOURCES.has(a.source);
            const bLast = LAST_SOURCES.has(b.source);
            if (aLast && !bLast) return  1;
            if (!aLast && bLast) return -1;
            return a.score - b.score;
        });
        const worst = results.find(r => !LAST_SOURCES.has(r.source)) || results[0];

        // Quad9 block is always Probably Malicious regardless of numeric score
        const hardRule = (worst.source === "Quad9" && worst.score === -100)
            ? `${worst.label}`
            : null;

        const classification = hardRule
            ? Classification.PROBABLY_MALICIOUS
            : classifyByScore(worst.score);

        const hostLabel = classification === Classification.PROBABLY_MALICIOUS
            ? "Suspicious signals found — domain probably malicious"
            : "Suspicious signals found — domain probably suspicious";

        return {
            score:           worst.score,
            classification,
            label:           hostLabel,
            hardRuleApplied: hardRule,
            breakdown:       results
        };
    }

    // =========================================================================
    // A.  VirusTotal URL Evaluation  (public — called by BrowserProtection)
    // =========================================================================

    /**
     * Evaluate VT analysis results.
     * Weights: detection 70 %, age 30 %.  Community removed.
     */
    function evaluate({
        stats               = {},
        rawStats            = null,
        firstSubmissionDate = null,
        fpLevel             = "NONE"
    } = {}) {

        const safeStats  = (stats !== null && typeof stats === "object") ? stats : {};
        const malicious  = safeStats.malicious  ?? 0;
        const suspicious = safeStats.suspicious ?? 0;

        const age = scoreVtAge(firstSubmissionDate);

        // ── ABC consensus bonus ───────────────────────────────────────────────
        // Rewards a strong clean consensus across responding VT engines.
        // Percentage-based: cleanCount / (cleanCount + suspicious + malicious)
        // so 21/21 = 100% regardless of how many engines total responded.
        //
        // Hard block — bonus cannot fire when:
        //   • URL first seen at VT < 7 days ago  (too new to trust consensus)
        //   • Any engine at the current FP level flagged suspicious or malicious
        //
        // Cut-offs:    A ≥ 90% → +30,  B ≥ 70% → +20,  C ≥ 50% → +10
        const cleanCount     = (safeStats.harmless || 0) + (safeStats.undetected || 0);
        const respondedCount = cleanCount + (safeStats.suspicious || 0) + (safeStats.malicious || 0);
        const cleanPct       = respondedCount > 0 ? (cleanCount / respondedCount) * 100 : 0;
        const vtTooNew       = age.ageDays !== null && age.ageDays < 7;

        let abcBonus = 0;
        let abcLabel = null;
        if (cleanCount > 0 && malicious === 0 && suspicious === 0 && !vtTooNew) {
            if      (cleanPct >= 90) { abcBonus = 30; abcLabel = "A"; }
            else if (cleanPct >= 70) { abcBonus = 20; abcLabel = "B"; }
            else if (cleanPct >= 50) { abcBonus = 10; abcLabel = "C"; }
        }

        const detection = scoreDetection(safeStats, age.ageDays, abcBonus);

        // VT score = detection score + age score — simple addition, no weighting.
        // Age influence comes through two clean mechanisms:
        //   1. Longevity bonus inside scoreDetection (+10 at >7 days, +30 at >30 days)
        //   2. Age penalty here (−10 at 2–7 days, −20 at <2 days)
        //   3. ABC hard block prevents bonus firing when first seen < 7 days
        // The old 70/30 weighted split is removed — it was redundant with the
        // longevity bonus already baked into detection.
        let total = Math.max(-100, Math.min(100, detection.score + age.score));

        const hardRule       = applyHardRules(malicious, suspicious);
        const classification = hardRule ? hardRule.classification : classifyByScore(total);

        return {
            classification,
            score:           total,
            confidence:      computeVtConfidence(age.ageDays),
            hardRuleApplied: hardRule?.reason ?? null,
            breakdown:       { detection: { ...detection, abcLabel }, age },
            rawStats:        rawStats || safeStats,
            filteredStats:   safeStats,
            fpLevel
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    return {
        Classification,
        evaluate,
        evaluateHostReputation,
        classifyByScore
    };

})();
