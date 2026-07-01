"use strict";

/**
 * FpReductionEngines.js
 *
 * Engine lists for False Positive reduction of VirusTotal results.
 *
 * Hierarchy: HIGH ⊂ MEDIUM ⊂ LOW ⊂ NONE
 *   NONE   = all engines (no filtering)
 *   LOW    = HIGH + MEDIUM + LOW engines
 *   MEDIUM = HIGH + MEDIUM engines
 *   HIGH   = HIGH engines only (one vote per canonical engine family)
 *
 * For HIGH, engines sharing the same underlying SDK are grouped — only ONE
 * detection counts per canonical group, regardless of how many members flag it.
 */
const FpReductionEngines = (function () {

    // ── HIGH tier — canonical engine groups ────────────────────────────────────
    // Key = canonical name, Value = all member names as they appear in VT results
    const HIGH_GROUPS = {
        "BitDefender":          ["BitDefender", "G-Data", "Emsisoft", "Arcabit", "AegisLab", "Panda", "Ad-Aware", "GData"],
        "Avast":                ["Avast", "AVG", "Norton"],
        "Avira":                ["Avira", "Antiy-AVL", "Fortinet"],
        "Sophos":               ["Sophos", "Ikarus"],
        "ESET":                 ["ESET-NOD32", "ESET"],
        "Microsoft":            ["Microsoft", "Windows Defender"],
        "Kaspersky":            ["Kaspersky"],
        "Broadcom":             ["Symantec", "Broadcom"],
        "Malwarebytes":         ["Malwarebytes"],
        "CrowdStrike":          ["CrowdStrike", "CrowdStrike Falcon"],
        "SentinelOne":          ["SentinelOne"],
        "Cylance":              ["Cylance"],
        "Trellix":              ["Trellix", "McAfee"],
        "PaloAlto":             ["Palo Alto Networks", "PaloAlto"],
        "URLhaus":              ["URLhaus"],
        "OpenPhish":            ["OpenPhish"],
    };

    // ── MEDIUM only engines (not in HIGH) ─────────────────────────────────────
    const MEDIUM_ONLY = new Set([
        "alphaMountain.ai", "AlphaMountain",
        "Forcepoint ThreatSeeker",
        "CTX AI",
        "Trend Micro", "TrendMicro", "TrendMicro-HouseCall",
        "F-Secure", "WithSecure",
        "Webroot",
        "Netcraft",
        "SafeToOpen",
        "DrWeb", "Dr.Web",
        "K7AntiVirus", "Quick Heal",
        "Acronis",
        "ESTsecurity", "AhnLab-V3",
        "Google Safebrowsing",
        "Yandex Safebrowsing",
    ]);

    // ── LOW only engines (not in HIGH or MEDIUM) ───────────────────────────────
    const LOW_ONLY = new Set([
        "Heimdal Security",
        "Juniper Networks",
        "Rising",
        "Xcitium Verdict Cloud", "Comodo",
        "Criminal IP",
        "AlienVault", "LevelBlue",
        "EmergingThreats",
        "Sucuri SiteCheck",
        "PhishTank",
        "VX Vault",
        "Blueliv",
        "CINS Army",
        "Cyble",
        "CyRadar",
        "Malware Patrol",
        "MalwareD",
        "PREBYTES",
        "Quttera",
        "Sangfor",
        "Seclookup",
        "ADMINUSLabs",
        "AILabs (MONITORAPP)",
        "Chong Lua Dao",
        "CRDF",
        "ZeroCERT",
        "BlockList",
        "Abusix",
        "ThreatHive",
        "GreenSnow",
        "desenmascara.me",
        "SCUMWARE.org",
        "StopForumSpam",
        "Viettel Threat Intelligence",
        "ViriBack",
        "Certego",
        "Lionic",
        "IPsum",
        "SOCRadar",
        "DNS8",
        "URLQuery",
        "Phishing Database",
        "Scantitan",
        "LevelBlue",
    ]);

    // Build reverse lookup: engine name → canonical group name (HIGH only)
    const ENGINE_TO_CANONICAL = {};
    for (const [canonical, members] of Object.entries(HIGH_GROUPS)) {
        for (const member of members) {
            ENGINE_TO_CANONICAL[member.toLowerCase()] = canonical;
        }
    }

    /**
     * Filter last_analysis_results by FP reduction level and return adjusted stats.
     *
     * @param {object} analysisResults  - VT last_analysis_results object (engine → {category, result})
     * @param {string} level            - "NONE" | "LOW" | "MEDIUM" | "HIGH"
     * @returns {{ malicious: number, suspicious: number, harmless: number, undetected: number }}
     */
    function filterResults(analysisResults, level) {
        if (!analysisResults || level === "NONE") {
            // Count raw totals
            return countRaw(analysisResults || {});
        }

        const canonicalVotes = {}; // tracks which canonical groups have already voted
        let malicious  = 0;
        let suspicious = 0;
        let harmless   = 0;
        let undetected = 0;

        for (const [engine, result] of Object.entries(analysisResults)) {
            const engineLower = engine.toLowerCase();
            const category    = (result.category || "").toLowerCase();

            // Determine if this engine is included in the selected level
            const inHigh   = ENGINE_TO_CANONICAL[engineLower] !== undefined;
            const inMedium = inHigh || MEDIUM_ONLY.has(engine) || MEDIUM_ONLY.has(engine.split(" ")[0]);
            const inLow    = inMedium || LOW_ONLY.has(engine);

            let include = false;
            if (level === "HIGH"   && inHigh)   include = true;
            if (level === "MEDIUM" && inMedium)  include = true;
            if (level === "LOW"    && inLow)     include = true;

            if (!include) continue;

            // For HIGH: deduplicate by canonical group for malicious/suspicious only.
            // Clean verdicts (harmless/undetected) count individually — each engine
            // that says "clean" is a real data point worth counting.
            if (level === "HIGH" && inHigh) {
                const canonical = ENGINE_TO_CANONICAL[engineLower];
                if (category === "malicious" || category === "malware") {
                    if (canonicalVotes[canonical]) continue;
                    canonicalVotes[canonical] = "malicious";
                } else if (category === "suspicious") {
                    if (canonicalVotes[canonical]) continue;
                    canonicalVotes[canonical] = "suspicious";
                }
                // harmless/undetected: no deduplication — count every engine
            }

            if (category === "malicious" || category === "malware") malicious++;
            else if (category === "suspicious")                       suspicious++;
            else if (category === "harmless")                         harmless++;
            else                                                       undetected++;
        }

        return { malicious, suspicious, harmless, undetected };
    }

    /**
     * Count raw unfiltered stats from last_analysis_results.
     */
    function countRaw(analysisResults) {
        let malicious = 0, suspicious = 0, harmless = 0, undetected = 0, unknown = 0;
        for (const result of Object.values(analysisResults)) {
            const cat = (result.category || "").toLowerCase();
            if      (cat === "malicious" || cat === "malware") malicious++;
            else if (cat === "suspicious")                      suspicious++;
            else if (cat === "harmless")                        harmless++;
            else if (cat === "undetected")                      undetected++;
            else                                                unknown++; // timeout, type-unsupported, etc.
        }
        return { malicious, suspicious, harmless, undetected, unknown };
    }

    /**
     * Get raw stats from last_analysis_results (unfiltered).
     */
    function getRawStats(analysisResults) {
        return countRaw(analysisResults || {});
    }

    return { filterResults, getRawStats, HIGH_GROUPS, MEDIUM_ONLY, LOW_ONLY };

})();
