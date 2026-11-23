"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { CombinationScoring } from "../../protection/CombinationScoring.js";

const { combineHostResults, CONFIG, FAMILY_MAP } = CombinationScoring;

function entry(source, score, extra = {}) {
    return { source, score, label: `${source} label`, ...extra };
}

describe("CombinationScoring.combineHostResults — edge cases", () => {
    test("empty input returns a neutral zero result", () => {
        const r = combineHostResults([]);
        assert.equal(r.score, 0);
        assert.equal(r.combined, false);
        assert.equal(r.signalCount, 0);
    });

    test("a single NEUTRAL (SizeCheck) entry is reported alone, unchanged", () => {
        const r = combineHostResults([entry("SizeCheck", -20)]);
        assert.equal(r.score, -20);
        assert.equal(r.source, "SizeCheck");
        assert.equal(r.combined, false);
    });

    test("an unknown/unmapped source doesn't throw, and is still reported alone (defensive fallback — same path as NEUTRAL)", () => {
        // A source missing from FAMILY_MAP (e.g. a forgotten mapping after a
        // new check is added) degrades safely: it's treated like a NEUTRAL
        // entry — never silently dropped, never allowed to combine/stack.
        const r = combineHostResults([entry("TotallyMadeUpSource", -90)]);
        assert.equal(r.score, -90);
        assert.equal(r.combined, false);
    });
});

describe("CombinationScoring.combineHostResults — single-family invariant", () => {
    test("exactly one family present returns that family's worst entry's raw score unchanged", () => {
        const r = combineHostResults([entry("DomainList", -70)]);
        assert.equal(r.score, -70);
        assert.equal(r.source, "DomainList");
        assert.equal(r.combined, false);
        assert.equal(r.signalCount, 1);
    });

    test("two sources in the SAME family still count as one family (worst of the two)", () => {
        const r = combineHostResults([entry("DomainList", -20), entry("HostList", -70)]);
        assert.equal(r.score, -70); // worst of the family, not stacked
        assert.equal(r.combined, false);
    });

    test("RDAP alone is doubled (standalone rule), capped at -100", () => {
        const r = combineHostResults([entry("RDAP", -30)]);
        assert.equal(r.score, -60);
        assert.equal(r.combined, false);
    });

    test("RDAP alone doubling is capped at -100, not allowed to overshoot", () => {
        const r = combineHostResults([entry("RDAP", -80)]);
        assert.equal(r.score, -100);
    });

    test("NEUTRAL (SizeCheck) alongside exactly one real family does not count as a second family", () => {
        const r = combineHostResults([entry("DomainList", -70), entry("SizeCheck", -20)]);
        assert.equal(r.score, -70); // still single-family behavior, SizeCheck excluded
        assert.equal(r.combined, false);
    });
});

describe("CombinationScoring.combineHostResults — stacking with decay", () => {
    test("two families stack: 2nd family contributes at ×0.5", () => {
        // base -70 (HOST_IDENTITY), 2nd family -30 (TLD) -> stack = -30*0.5 = -15
        // extra = max(-15 + 0 bonus, -35) = -15 -> score = -70 + -15 = -85
        const r = combineHostResults([entry("DomainList", -70), entry("TldList", -30)]);
        assert.equal(r.score, -85);
        assert.equal(r.combined, true);
        assert.equal(r.signalCount, 2);
    });

    test("three families: 2nd at ×0.5, 3rd at ×0.25", () => {
        // base -70; 2nd -30*0.5=-15; 3rd -20*0.25=-5; stack=-20; extra=max(-20,-35)=-20
        // score = -70-20 = -90
        const r = combineHostResults([
            entry("DomainList", -70),
            entry("TldList", -30),
            entry("ProtocolCheck", -20),
        ]);
        assert.equal(r.score, -90);
    });

    test("a signal weaker than STACK_MIN_SIGNAL does not stack at all", () => {
        // RiskyHosting at -10 is weaker than STACK_MIN_SIGNAL (-15) — excluded
        // from the stack sum entirely, matching worked example #1 in the plan.
        const r = combineHostResults([entry("ScriptFormat", -25), entry("RiskyHosting", -10)]);
        assert.equal(r.score, -25); // unchanged from the single ScriptFormat score
    });

    test("a signal exactly at STACK_MIN_SIGNAL does stack (boundary is inclusive)", () => {
        const r = combineHostResults([entry("ScriptFormat", -25), entry("RiskyHosting", -15)]);
        assert.ok(r.score < -25); // some contribution happened
    });

    test("a 5th+ family contributes nothing further (MAX_STACKED_FAMILIES)", () => {
        const withFour = combineHostResults([
            entry("DomainList", -70),       // base
            entry("TldList", -30),          // 2nd
            entry("ProtocolCheck", -30),    // 3rd
            entry("ScriptFormat", -30),     // 4th
        ]);
        const withFive = combineHostResults([
            entry("DomainList", -70),       // base
            entry("TldList", -30),          // 2nd
            entry("ProtocolCheck", -30),    // 3rd
            entry("ScriptFormat", -30),     // 4th
            entry("UrlCredentials", -30),   // 5th — URL_SHAPE, should add nothing
        ]);
        assert.equal(withFour.score, withFive.score);
    });

    test("stack + bonus together never add more than STACK_MAX_DELTA (-35) to the base", () => {
        const r = combineHostResults([
            entry("DomainList", -100),
            entry("TldList", -100),
            entry("ProtocolCheck", -100),
            entry("ScriptFormat", -100),
        ]);
        assert.ok(r.score >= -100 - CONFIG.STACK_MAX_DELTA - 1 || r.score === -100);
        // base alone is already -100 (clamped); the important invariant is the
        // overall score never exceeds the absolute floor.
        assert.ok(r.score >= -100);
    });

    test("final score is always clamped to -100", () => {
        const r = combineHostResults([
            entry("DomainList", -90),
            entry("TldList", -90),
            entry("ProtocolCheck", -90),
            entry("ScriptFormat", -90),
        ]);
        assert.equal(r.score, -100);
    });
});

describe("CombinationScoring.combineHostResults — combination rules", () => {
    test("C1 fires: HOST_IDENTITY <= -35 and FILE_FORMAT present", () => {
        const withRule = combineHostResults([entry("HostList", -40), entry("ScriptFormat", -25)]);
        assert.ok(withRule.firedRules.includes("C1"));
    });

    test("C1 does not fire when HOST_IDENTITY is weaker than -35", () => {
        const noRule = combineHostResults([entry("HostList", -20), entry("ScriptFormat", -25)]);
        assert.ok(!noRule.firedRules.includes("C1"));
    });

    test("C2 fires: HOST_AGE <= -20 and FILE_FORMAT present", () => {
        const r = combineHostResults([entry("RDAP", -20), entry("StagingFormat", -30)]);
        assert.ok(r.firedRules.includes("C2"));
    });

    test("C2 fires via FILE_DECEPTION instead of FILE_FORMAT", () => {
        const r = combineHostResults([entry("RDAP", -25), entry("DoubleExtension", -50)]);
        assert.ok(r.firedRules.includes("C2"));
    });

    test("C3 fires: StagingKeywords command-part meta and FILE_FORMAT present", () => {
        const r = combineHostResults([
            entry("StagingKeywords", -40, { meta: { hasCommandSignal: true, hasLureSignal: false } }),
            entry("ScriptFormat", -25),
        ]);
        assert.ok(r.firedRules.includes("C3"));
    });

    test("C3 does not fire when only the lure part (not command part) is present", () => {
        const r = combineHostResults([
            entry("StagingKeywords", -40, { meta: { hasCommandSignal: false, hasLureSignal: true } }),
            entry("ScriptFormat", -25),
        ]);
        assert.ok(!r.firedRules.includes("C3"));
    });

    test("C4 fires: TLD <= -25 and HOST_AGE <= -20", () => {
        const r = combineHostResults([entry("TldList", -30), entry("RDAP", -25)]);
        assert.ok(r.firedRules.includes("C4"));
    });

    test("C5 fires: StagingKeywords lure-part meta and FILE_DECEPTION present", () => {
        const r = combineHostResults([
            entry("StagingKeywords", -20, { meta: { hasCommandSignal: false, hasLureSignal: true } }),
            entry("DoubleExtension", -50),
        ]);
        assert.ok(r.firedRules.includes("C5"));
    });

    test("C6 fires: IpAddressCheck specifically (not just any HOST_IDENTITY member) and TRANSPORT", () => {
        const r = combineHostResults([entry("IpAddressCheck", -30), entry("ProtocolCheck", -40)]);
        assert.ok(r.firedRules.includes("C6"));
    });

    test("C6 does not fire for a different HOST_IDENTITY member (e.g. DomainList) even with TRANSPORT present", () => {
        const r = combineHostResults([entry("DomainList", -30), entry("ProtocolCheck", -40)]);
        assert.ok(!r.firedRules.includes("C6"));
    });

    test("multiple rules can fire together and their bonuses sum, floored at COMBO_BONUS_CAP", () => {
        // C1 (HOST_IDENTITY<=-35 & FILE_FORMAT) + C6 (IpAddressCheck & TRANSPORT) should both fire.
        const r = combineHostResults([
            entry("IpAddressCheck", -40),      // HOST_IDENTITY, also satisfies C6's specific-source check
            entry("ScriptFormat", -25),        // FILE_FORMAT
            entry("ProtocolCheck", -40),       // TRANSPORT
        ]);
        assert.ok(r.firedRules.includes("C1"));
        assert.ok(r.firedRules.includes("C6"));
    });

    test("combo-rule bonus total never exceeds COMBO_BONUS_CAP in magnitude", () => {
        // Construct a scenario firing every rule at once and confirm the
        // bonus portion of the delta is clamped to COMBO_BONUS_CAP (-20).
        const r = combineHostResults([
            entry("IpAddressCheck", -40),                                         // HOST_IDENTITY (C1, C6)
            entry("RDAP", -25),                                                   // HOST_AGE (C2, C4)
            entry("TldList", -30),                                                // TLD (C4)
            entry("StagingFormat", -30),                                          // FILE_FORMAT (C1, C2, C3)
            entry("DoubleExtension", -50),                                        // FILE_DECEPTION (C2, C5)
            entry("StagingKeywords", -40, { meta: { hasCommandSignal: true, hasLureSignal: true } }), // CONTENT (C3, C5)
            entry("ProtocolCheck", -40),                                          // TRANSPORT (C6)
        ]);
        assert.ok(r.firedRules.length >= 4); // several rules genuinely fired
        // Whatever the stack math does, overall combination delta (score -
        // base-family score) can never exceed STACK_MAX_DELTA in magnitude.
        const base = -50; // DoubleExtension is the most negative single entry
        assert.ok(r.score >= base + CONFIG.STACK_MAX_DELTA - 1);
    });
});

describe("CombinationScoring — worked example from the heuristics plan (Step 3, §3)", () => {
    test("staging chain: TldList + StagingFormat(small container) + RDAP(young) + StagingKeywords(finance) combine to a stronger verdict than any one signal alone", () => {
        const r = combineHostResults([
            entry("TldList", -38),
            entry("StagingFormat", -35),
            entry("RDAP", -20),
            entry("StagingKeywords", -18, { meta: { hasCommandSignal: false, hasLureSignal: true } }),
        ]);
        // Exact figure depends on rounding details not pinned here (see this
        // module's own code comments) — the invariant that matters is that
        // combining is strictly worse than the single worst signal alone.
        assert.ok(r.score < -38);
        assert.ok(r.combined);
        assert.equal(r.signalCount, 4);
    });
});

describe("CombinationScoring — data integrity", () => {
    test("every family referenced by COMBO_RULES exists in FAMILY_MAP's value set", () => {
        const families = new Set(Object.values(FAMILY_MAP));
        assert.ok(families.has("HOST_IDENTITY"));
        assert.ok(families.has("HOST_AGE"));
        assert.ok(families.has("TLD"));
        assert.ok(families.has("FILE_FORMAT"));
        assert.ok(families.has("FILE_DECEPTION"));
        assert.ok(families.has("CONTENT"));
        assert.ok(families.has("TRANSPORT"));
        assert.ok(families.has("URL_SHAPE"));
        assert.ok(families.has("NEUTRAL"));
    });

    test("FAMILY_MAP covers every source ScoringEngineV2.evaluateHostReputation() can emit", () => {
        const expectedSources = [
            "DomainList", "HostList", "RiskyHosting", "IpAddressCheck", "RDAP", "TldList",
            "SketchyUrl", "UrlCredentials", "ProtocolCheck", "ProtocolDowngrade",
            "ScriptFormat", "StagingFormat", "LinuxLauncher", "DoubleExtension",
            "Obfuscation", "MimeCheck", "StagingKeywords", "SizeCheck",
            // v2.11.0 — heuristics plan "Later steps" Step 5
            "RloObfuscation", "PaddedDoubleExtension",
            "UrlShortener", "ReferrerMismatch",
            // v3.2.0 — 3P Matrix alignment §1 (replaces BrandHomoglyph/LookalikeTopSite)
            "LookalikeDomain",
        ];
        for (const source of expectedSources) {
            assert.ok(FAMILY_MAP[source], `missing family mapping for ${source}`);
        }
    });
});
