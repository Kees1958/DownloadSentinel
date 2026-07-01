"use strict";

class ProtectionResult {
    /**
     * Constructor function for creating a browser protection result object.
     * @param {string} urlChecked - The URL that was checked.
     * @param {string} resultType - The result type of the protection check (e.g., "Probably Safe", "Probably Malicious").
     * @param {number} resultOrigin - The origin of the result (e.g., from endpoint or known top site).
     * @param {Object} [details] - Optional scoring details produced by ScoringEngine.evaluate().
     * @param {number} [details.score] - Total weighted score (-100 to +100).
     * @param {string} [details.confidence] - "High" | "Medium" | "Low" (or "Cached").
     * @param {Object} [details.breakdown] - {detection, reputation, age, votes} partial scores.
     * @param {string} [details.hardRuleApplied] - Description of the hard rule that forced the classification, if any.
     */
    constructor(urlChecked, resultType, resultOrigin, details = {}) {
        this.url = urlChecked;
        this.result = resultType;
        this.origin = resultOrigin;

        this.score = details.score ?? null;
        this.confidence = details.confidence ?? null;
        this.breakdown = details.breakdown ?? null;
        this.hardRuleApplied = details.hardRuleApplied ?? null;
        this.rawStats = details.rawStats ?? null;
        this.filteredStats = details.filteredStats ?? null;
        this.fpLevel = details.fpLevel ?? null;
    }
}

// Technical/non-scored states keep their own names; the four scored
// classifications come from ScoringEngine and mirror "Scoring method.txt".
ProtectionResult.ResultType = {
    FAILED: "Failed",
    UNKNOWN: "Unknown",
    PROBABLY_SAFE: "Probably Safe",
    PROBABLY_QUESTIONABLE: "Probably Inconclusive",
    PROBABLY_SUSPICIOUS: "Probably Suspicious",
    PROBABLY_MALICIOUS: "Probably Malicious"
};

ProtectionResult.ResultOrigin = {
    UNKNOWN: 0, // The result was determined via an unknown origin
    VIRUSTOTAL: 15 // The result was determined via VirusTotal
};

ProtectionResult.ResultOriginNames = {
    0: "Unknown",
    15: "VirusTotal"
};
