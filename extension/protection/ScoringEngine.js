"use strict";

// ────────────────────────────────────────────────────────────────────────────
// ScoringEngine
//
// Implements the weighted reputation scoring model described in
// "Scoring method.txt":
//
//   1. Detection score   (malicious / suspicious / harmless / undetected)
//   2. Reputation score  (VirusTotal community reputation)
//   3. Age score         (time since first submission)
//   4. Votes score       (amount of community votes)
//
// The four partial scores are summed into a total score in the range
// [-100, 100], which is translated into one of four classifications:
//
//   Probably Safe          ( +30 to +100 )
//   Probably Questionable  (   0 to  +29 )   ("Mixed Signals")
//   Probably Suspicious    (  -1 to  -39 )
//   Probably Malicious     ( -40 to -100 )
//
// A set of hard rules can override the score-based classification — these
// always take precedence and are evaluated in order, top to bottom.
// ────────────────────────────────────────────────────────────────────────────

const ScoringEngine = (function () {

    const Classification = {
        PROBABLY_SAFE:         "Probably Safe",
        PROBABLY_QUESTIONABLE: "Probably Questionable",
        PROBABLY_SUSPICIOUS:   "Probably Suspicious",
        PROBABLY_MALICIOUS:    "Probably Malicious"
    };

    const SECONDS_PER_DAY = 86400;

    // ── 1. Detection score (most important factor) ─────────────────────────
    function scoreDetection(stats) {
        const malicious  = stats.malicious  || 0;
        const suspicious = stats.suspicious || 0;
        const harmless   = stats.harmless   || 0;

        if (malicious >= 3)  return { score: -90, label: "\u2265 3 malicious detections" };
        if (malicious === 2) return { score: -70, label: "2 malicious detections" };
        if (malicious === 1) return { score: -50, label: "1 malicious detection" };

        if (suspicious >= 10) return { score: -60, label: "\u2265 10 suspicious detections" };
        if (suspicious >= 5)  return { score: -45, label: "5-9 suspicious detections" };
        if (suspicious >= 2)  return { score: -30, label: "2-4 suspicious detections" };
        if (suspicious === 1) return { score: -15, label: "1 suspicious detection" };

        if (harmless > 0) return { score: 25, label: "No suspicious or malicious detections" };
        return { score: 10, label: "Only unknown/undetected results" };
    }

    // ── 2. Reputation score ──────────────────────────────────────────────────
    function scoreReputation(reputation) {
        const rep = Number.isFinite(reputation) ? reputation : 0;

        if (rep > 10)   return { score:  20, label: `${rep}` };
        if (rep >= 1)    return { score:  10, label: `${rep}` };
        if (rep === 0)   return { score:   0, label: `${rep}` };
        if (rep >= -10)  return { score: -15, label: `${rep}` };
        if (rep >= -30)  return { score: -30, label: `${rep}` };
        return                   { score: -50, label: `${rep}` };
    }

    // ── 3. Age score (time since first submission) ─────────────────────────
    function scoreAge(firstSubmissionDate) {
        if (!firstSubmissionDate) {
            return { score: 0, ageDays: null, label: "Unknown age" };
        }

        const ageDays = (Date.now() / 1000 - firstSubmissionDate) / SECONDS_PER_DAY;
        const days    = Math.max(0, Math.floor(ageDays));

        // Boundary values (2, 7, 30, 180) belong to the more cautious (lower) bracket —
        // confirmed by the worked example in Scoring method.txt (2 days old → -20).
        if (ageDays > 180) return { score:  15, ageDays, label: `${days} days old` };
        if (ageDays > 30)  return { score:  10, ageDays, label: `${days} days old` };
        if (ageDays > 7)   return { score:   0, ageDays, label: `${days} days old` };
        if (ageDays > 2)   return { score: -10, ageDays, label: `${days} days old` };
        return                    { score: -20, ageDays, label: `${days} days old` };
    }

    // ── 4. Votes score (community engagement) ───────────────────────────────
    function scoreVotes(totalVotes) {
        const votes = (totalVotes?.harmless || 0) + (totalVotes?.malicious || 0);

        if (votes > 50)  return { score: 10, votes, label: `${votes} votes` };
        if (votes >= 10) return { score:  5, votes, label: `${votes} votes` };
        if (votes >= 1)  return { score:  0, votes, label: `${votes} votes` };
        return                  { score: -5, votes, label: `${votes} votes` };
    }

    // ── Confidence (independent of classification) ──────────────────────────
    function computeConfidence(ageDays, votes) {
        const hasAge     = ageDays !== null;
        const highAge    = hasAge && ageDays > 180;
        const mediumAge   = hasAge && ageDays >= 30 && ageDays <= 180;
        const highVotes   = votes > 50;
        const mediumVotes = votes >= 10 && votes <= 50;

        if (highAge && highVotes) return "High";
        if (mediumAge || mediumVotes) return "Medium";
        return "Low";
    }

    // Score ceiling for each hard-rule classification — the displayed score is
    // never allowed to look "better" than this once that classification is forced.
    const HARD_RULE_CEILING = {
        [Classification.PROBABLY_MALICIOUS]:  -40,
        [Classification.PROBABLY_SUSPICIOUS]: -1
    };

    const SEVERITY_RANK = {
        [Classification.PROBABLY_SAFE]:         0,
        [Classification.PROBABLY_QUESTIONABLE]: 1,
        [Classification.PROBABLY_SUSPICIOUS]:   2,
        [Classification.PROBABLY_MALICIOUS]:    3
    };

    // Extra penalty applied per additional hard rule that fires at the same time,
    // so compounding red flags push the score further down rather than being
    // silently collapsed into whichever single rule is reported.
    const STACKING_PENALTY = 5;

    // ── Hard rules — always take precedence over the total score ───────────
    // Returns ALL matching rules (priority-ordered), so simultaneous red flags
    // can both pick the worst classification and compound the score.
    function applyHardRules(malicious, suspicious, reputation) {
        const matches = [];

        if (malicious >= 3) {
            matches.push({ classification: Classification.PROBABLY_MALICIOUS, reason: "\u2265 3 malicious detections" });
        }
        if (suspicious >= 10) {
            matches.push({ classification: Classification.PROBABLY_MALICIOUS, reason: "\u2265 10 suspicious detections" });
        }
        if (Number.isFinite(reputation) && reputation < -50) {
            matches.push({ classification: Classification.PROBABLY_MALICIOUS, reason: "reputation below -50" });
        }
        if (malicious >= 1 && malicious <= 2) {
            matches.push({ classification: Classification.PROBABLY_SUSPICIOUS, reason: "1-2 malicious detections" });
        }

        return matches;
    }

    // ── Final classification from the total score ───────────────────────────
    function classifyByScore(total) {
        if (total >= 30)  return Classification.PROBABLY_SAFE;
        if (total >= 0)   return Classification.PROBABLY_QUESTIONABLE;
        if (total >= -39) return Classification.PROBABLY_SUSPICIOUS;
        return Classification.PROBABLY_MALICIOUS;
    }

    return {

        Classification,

        /**
         * Evaluate a VirusTotal URL object's attributes and produce a
         * classification, total score, confidence rating and full breakdown.
         *
         * @param {Object} input
         * @param {Object} input.stats               - last_analysis_stats {malicious, suspicious, harmless, undetected, ...}
         * @param {number} [input.reputation]         - VT community reputation score
         * @param {Object} [input.totalVotes]         - {harmless, malicious}
         * @param {number} [input.firstSubmissionDate]- epoch seconds
         */
        evaluate: function ({ stats = {}, reputation = 0, totalVotes = {}, firstSubmissionDate = null }) {

            const malicious  = stats.malicious  || 0;
            const suspicious = stats.suspicious || 0;

            const detection       = scoreDetection(stats);
            const reputationScore  = scoreReputation(reputation);
            const age              = scoreAge(firstSubmissionDate);
            const votes            = scoreVotes(totalVotes);

            const rawTotal = detection.score + reputationScore.score + age.score + votes.score;
            let total = Math.max(-100, Math.min(100, rawTotal));

            const hardRuleMatches = applyHardRules(malicious, suspicious, reputation);
            let classification;
            let hardRuleApplied = null;

            if (hardRuleMatches.length > 0) {
                // Worst (most severe) classification among all matched rules wins.
                classification = hardRuleMatches.reduce(
                    (worst, m) => SEVERITY_RANK[m.classification] > SEVERITY_RANK[worst] ? m.classification : worst,
                    hardRuleMatches[0].classification
                );

                // Never let the displayed score look "better" than the forced classification.
                const ceiling = HARD_RULE_CEILING[classification];
                if (typeof ceiling === "number") {
                    total = Math.min(total, ceiling);
                }

                // Compounding red flags: every extra rule beyond the first pushes the
                // score further down, even though only the first/primary reason is reported.
                total -= (hardRuleMatches.length - 1) * STACKING_PENALTY;
                total = Math.max(-100, Math.min(100, total));

                hardRuleApplied = hardRuleMatches[0].reason;
            } else {
                classification = classifyByScore(total);
            }

            const confidence = computeConfidence(age.ageDays, votes.votes);

            return {
                classification,
                score: total,
                confidence,
                hardRuleApplied,
                breakdown: {
                    detection,
                    reputation: reputationScore,
                    age,
                    votes
                }
            };
        }
    };
})();
