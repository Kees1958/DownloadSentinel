"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { FpReductionEngines } from "../../util/FpReductionEngines.js";

// A small synthetic VT last_analysis_results fixture covering HIGH, MEDIUM-only,
// and LOW-only tiers, plus a duplicate-vendor-family case for HIGH dedup.
const RESULTS = {
    "BitDefender":  { category: "malicious" },
    "G-Data":       { category: "malicious" },   // same HIGH canonical group as BitDefender
    "Kaspersky":    { category: "harmless" },
    "Trend Micro":  { category: "suspicious" },  // MEDIUM only
    "Rising":       { category: "malicious" },   // LOW only
    "SomeVendor":   { category: "undetected" }   // not in any tier list
};

describe("FpReductionEngines.filterResults", () => {
    test("NONE counts every engine raw, no dedup", () => {
        const r = FpReductionEngines.filterResults(RESULTS, "NONE");
        assert.equal(r.malicious, 3);   // BitDefender, G-Data, Rising
        assert.equal(r.suspicious, 1);  // Trend Micro
        assert.equal(r.harmless, 1);    // Kaspersky
        assert.equal(r.undetected, 1);  // SomeVendor
    });

    test("HIGH dedupes BitDefender/G-Data into a single canonical vote", () => {
        const r = FpReductionEngines.filterResults(RESULTS, "HIGH");
        assert.equal(r.malicious, 1);   // deduped to one
        assert.equal(r.harmless, 1);    // Kaspersky, counted individually
        assert.equal(r.suspicious, 0);  // Trend Micro excluded (MEDIUM only)
        assert.equal(r.undetected, 0);  // SomeVendor excluded entirely
    });

    test("MEDIUM includes HIGH plus MEDIUM-only, still excludes LOW-only", () => {
        const r = FpReductionEngines.filterResults(RESULTS, "MEDIUM");
        assert.equal(r.malicious, 2);   // BitDefender + G-Data, NOT deduped outside HIGH
        assert.equal(r.suspicious, 1);  // Trend Micro included
        assert.ok(r.malicious < 3);     // Rising (LOW-only) excluded
    });

    test("LOW includes everything except unlisted engines", () => {
        const r = FpReductionEngines.filterResults(RESULTS, "LOW");
        assert.equal(r.malicious, 3);   // BitDefender + G-Data + Rising
        assert.equal(r.suspicious, 1);
        assert.equal(r.undetected, 0);  // SomeVendor still excluded — not in any tier
    });

    test("missing analysisResults falls back to an all-zero raw count", () => {
        const r = FpReductionEngines.filterResults(null, "NONE");
        assert.deepEqual(r, { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, unknown: 0 });
    });
});

describe("FpReductionEngines.getRawStats", () => {
    test("counts every category including an 'unknown' bucket for anything else", () => {
        const r = FpReductionEngines.getRawStats({
            a: { category: "malicious" },
            b: { category: "type-unsupported" }
        });
        assert.equal(r.malicious, 1);
        assert.equal(r.unknown, 1);
    });
});
