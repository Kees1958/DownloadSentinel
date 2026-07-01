"use strict";

/**
 * FpEngines.js
 *
 * Engine lists for false positive reduction.
 * The hierarchy is cumulative — each level includes all levels above it:
 *   HIGH   = only HIGH engines
 *   MEDIUM = HIGH + MEDIUM engines
 *   LOW    = HIGH + MEDIUM + LOW engines
 *   NONE   = all engines (no filtering)
 *
 * For HIGH tier, engine groups deduplicate OEM resellers — one vote per
 * canonical engine regardless of how many group members flagged it.
 *
 * Voting rule: one vote per canonical group, fired when ANY member flags it.
 */
const FpEngines = (function () {

    // ── HIGH tier — engine groups (one vote per canonical) ────────────────────
    // Key = canonical name (used as the vote key)
    // Members = all VT engine name strings that belong to this group
    const HIGH_GROUPS = [
        { canonical: "BitDefender",       members: ["BitDefender", "G-Data", "GData", "Emsisoft", "Arcabit", "AegisLab", "Panda", "Ad-Aware", "Total Defense"] },
        { canonical: "Avast",             members: ["Avast", "AVG", "Norton"] },
        { canonical: "Avira",             members: ["Avira", "Antiy-AVL", "Antiy", "Fortinet"] },
        { canonical: "Sophos",            members: ["Sophos", "Ikarus"] },
        { canonical: "ESET",              members: ["ESET"] },
        { canonical: "Microsoft",         members: ["Microsoft", "Windows Defender", "MicrosoftSecurityEssentials"] },
        { canonical: "Kaspersky",         members: ["Kaspersky"] },
        { canonical: "Broadcom",          members: ["Symantec", "Broadcom"] },
        { canonical: "Malwarebytes",      members: ["Malwarebytes"] },
        { canonical: "CrowdStrike",       members: ["CrowdStrike", "CrowdStrike Falcon"] },
        { canonical: "SentinelOne",       members: ["SentinelOne"] },
        { canonical: "Cylance",           members: ["Cylance"] },
        { canonical: "Trellix",           members: ["Trellix", "McAfee", "McAfee-GW-Edition"] },
        { canonical: "PaloAlto",          members: ["Palo Alto Networks", "PaloAlto"] },
        { canonical: "AlphaMountain",     members: ["alphaMountain.ai", "AlphaMountain"] },
        { canonical: "URLhaus",           members: ["URLhaus"] },
        { canonical: "OpenPhish",         members: ["OpenPhish"] },
    ];

    // ── MEDIUM only — individual engines (not in HIGH groups) ────────────────
    const MEDIUM_ENGINES = new Set([
        "Trend Micro", "TrendMicro", "TrendMicro-HouseCall",
        "F-Secure", "WithSecure",
        "Webroot",
        "Netcraft",
        "SafeToOpen",
        "Dr.Web", "DrWeb",
        "Quick Heal", "QuickHeal",
        "Acronis",
        "ESTsecurity", "EST Security",
        "Google Safebrowsing",
        "Yandex Safebrowsing",
    ]);

    // ── LOW only — individual engines (not in HIGH or MEDIUM) ────────────────
    const LOW_ENGINES = new Set([
        "Heimdal Security",
        "Juniper Networks",
        "Rising",
        "Xcitium Verdict Cloud", "Xcitium",
        "Criminal IP",
        "AlienVault", "LevelBlue",
        "EmergingThreats", "Emerging Threats",
        "Sucuri SiteCheck", "Sucuri",
        "PhishTank",
        "VX Vault",
        "Blueliv",
        "CINS Army",
        "Cyble",
        "CyRadar",
        "Malware Patrol", "MalwarePatrol",
        "MalwareD", "Malwared",
        "PREBYTES",
        "Quttera",
        "Forcepoint ThreatSeeker",
        "Sangfor",
        "Seclookup",
        "ADMINUSLabs",
        "AILabs (MONITORAPP)", "AILabs",
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
        "CTX AI",
        "URLQuery",
        "Phishing Database",
        "Scantitan",
    ]);

    // Build a flat member→canonical map for HIGH tier
    const HIGH_MEMBER_MAP = {};
    for (const group of HIGH_GROUPS) {
        for (const member of group.members) {
            HIGH_MEMBER_MAP[member.toLowerCase()] = group.canonical;
        }
    }

    /**
     * Filter VT last_analysis_results by the selected FP reduction level.
     * Returns { malicious, suspicious, harmless, undetected } counts
     * after applying the filter.
     *
     * @param {object} analysisResults  - last_analysis_results from VT API
     * @param {string} level            - "NONE" | "LOW" | "MEDIUM" | "HIGH"
     * @returns {{ malicious: number, suspicious: number, harmless: number, undetected: number }}
     */
    function filterResults(analysisResults, level) {
        if (!analysisResults || level === "NONE") {
            // Count all engines directly
            const counts = { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };
            for (const result of Object.values(analysisResults || {})) {
                const cat = (result.category || "").toLowerCase();
                if (cat === "malicious" || cat === "malware") counts.malicious++;
                else if (cat === "suspicious")                 counts.suspicious++;
                else if (cat === "harmless")                   counts.harmless++;
                else if (cat === "undetected")                 counts.undetected++;
            }
            return counts;
        }

        if (level === "HIGH") {
            // One vote per canonical group
            const voted    = new Set();
            const counts   = { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };

            for (const [engine, result] of Object.entries(analysisResults)) {
                const canonical = HIGH_MEMBER_MAP[engine.toLowerCase()];
                if (!canonical) continue;               // not in HIGH tier, skip
                const cat = (result.category || "").toLowerCase();
                if (cat === "malicious" || cat === "malware" || cat === "suspicious") {
                    if (!voted.has(canonical)) {
                        voted.add(canonical);
                        if (cat === "suspicious") counts.suspicious++;
                        else                      counts.malicious++;
                    }
                } else if (cat === "harmless") {
                    counts.harmless++;
                } else if (cat === "undetected") {
                    counts.undetected++;
                }
            }
            return counts;
        }

        // MEDIUM or LOW — include HIGH (deduplicated) + additional individual engines
        const voted  = new Set();
        const counts = { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };

        for (const [engine, result] of Object.entries(analysisResults)) {
            const engineLower = engine.toLowerCase();
            const canonical   = HIGH_MEMBER_MAP[engineLower];
            const inMedium    = MEDIUM_ENGINES.has(engine);
            const inLow       = LOW_ENGINES.has(engine);

            let include = false;
            if (canonical) {
                include = true; // HIGH tier member
            } else if (inMedium) {
                include = true; // MEDIUM tier
            } else if (level === "LOW" && inLow) {
                include = true; // LOW tier (only when level is LOW)
            }

            if (!include) continue;

            const cat = (result.category || "").toLowerCase();

            // HIGH group members: deduplicate by canonical
            if (canonical) {
                if (cat === "malicious" || cat === "malware" || cat === "suspicious") {
                    if (!voted.has(canonical)) {
                        voted.add(canonical);
                        if (cat === "suspicious") counts.suspicious++;
                        else                      counts.malicious++;
                    }
                } else if (cat === "harmless") {
                    counts.harmless++;
                } else if (cat === "undetected") {
                    counts.undetected++;
                }
            } else {
                // Individual engine — count directly
                if (cat === "malicious" || cat === "malware") counts.malicious++;
                else if (cat === "suspicious")                 counts.suspicious++;
                else if (cat === "harmless")                   counts.harmless++;
                else if (cat === "undetected")                 counts.undetected++;
            }
        }
        return counts;
    }

    /**
     * Count all engines without filtering (for the unfiltered line).
     */
    function countAll(analysisResults) {
        return filterResults(analysisResults, "NONE");
    }

    return { filterResults, countAll };

})();
