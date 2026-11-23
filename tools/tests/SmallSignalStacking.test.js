"use strict";

// v3.5.6 — small signals (weaker than CombinationScoring.CONFIG.STACK_MIN_SIGNAL) add up ONLY when the
// heuristics are the only indicator (VirusTotal does not know the file) AND the source is dubious
// (user decision 2026-11-09). Real case: a hidden .bin from a drive.google.com link stayed below the
// warning line because the small "opaque download path" signal never counted.
// Expected values are derived from the library's own constants — nothing typed in.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { CombinationScoring } from "../../protection/CombinationScoring.js";
import { ScoringEngineV2 } from "../../protection/ScoringEngineV2.js";
import { SuspiciousDomains } from "../../util/SuspiciousDomains.js";
import { SketchyUrlCheck } from "../../protection/SketchyUrlCheck.js";
import { FilenameAnalysis } from "../../util/FilenameAnalysis.js";
import { ActiveThreatHosts } from "../../util/ActiveThreatHosts.js";
import { APP } from "../../util/AppConstants.js";
import { BrowserProtection } from "../../protection/BrowserProtection.js";

const { CONFIG, combineHostResults, smallSignalsStack, isDubiousSource, canStack } = CombinationScoring;
const HEURISTICS_ONLY = Object.freeze({ heuristicsOnly: true });
const SMALL = CONFIG.STACK_MIN_SIGNAL + 1;                // just weaker than the stacking floor
const STRONG = CONFIG.STACK_MIN_SIGNAL * 2;               // clearly strong
const DUBIOUS = CONFIG.DUBIOUS_SOURCES[0];                // a dubious-source list hit
const NOT_DUBIOUS_STRONG = "ScriptFormat";                // strong, but says nothing about the source
const SMALL_SOURCE = "SketchyUrl";                        // a small route signal (another family)

const DRIVE_LINK = "https://drive.google.com/uc?export=download&id=1N6hYIxV2EXw5gdNAOzoymk4NA2IzPQGi";
const DRIVE_FILE = "https://drive.usercontent.google.com/download?id=1N6hYIxV2EXw5gdNAOzoymk4NA2IzPQGi&export=download";
const HIDDEN_EXT = "bin";
const HIDDEN_NAME = "file.bin", HIDDEN_MIME = "application/octet-stream";
const ACTIVE_THREAT_URL = "https://raw.githubusercontent.com/user/repo/main/payload.zip";   // a campaign-host shape

function entry(source, score, extra = {}) { return { source, score, label: `${source} label`, ...extra }; }
const decayed = (score, rank) => score * Math.pow(CONFIG.STACK_DECAY, rank);

describe("v3.5.6 — when do small signals stack?", () => {
    test("VirusTotal knows the file: a small signal never stacks (unchanged)", () => {
        const r = combineHostResults([entry(DUBIOUS, STRONG), entry(SMALL_SOURCE, SMALL)]);
        assert.equal(r.score, STRONG);
    });

    test("heuristics only + dubious source: the small signal stacks with the normal decay", () => {
        const r = combineHostResults([entry(DUBIOUS, STRONG), entry(SMALL_SOURCE, SMALL)], HEURISTICS_ONLY);
        assert.equal(r.score, Math.round(STRONG + decayed(SMALL, 1)));
        assert.equal(r.smallSignalsStacked, true);
    });

    test("heuristics only, source NOT dubious: unchanged", () => {
        const r = combineHostResults([entry(NOT_DUBIOUS_STRONG, STRONG), entry(SMALL_SOURCE, SMALL)], HEURISTICS_ONLY);
        assert.equal(r.score, STRONG);
    });

    test("an explained (shown, not counted) list hit does not make the source dubious", () => {
        assert.equal(isDubiousSource([entry(DUBIOUS, STRONG, { explained: true })]), false);
    });

    test("domain age counts as dubious only at 'very young'", () => {
        assert.equal(isDubiousSource([entry(CONFIG.DUBIOUS_AGE_SOURCE, APP.RDAP_YOUNG_SCORE)]), true);
        assert.equal(isDubiousSource([entry(CONFIG.DUBIOUS_AGE_SOURCE, APP.RDAP_YOUNG_SCORE + 1)]), false);
    });

    test("a weak-signal cluster already summed them: no second, individual stacking", () => {
        const withCluster = [entry(DUBIOUS, STRONG), entry("WeakSignalCluster", STRONG), entry(SMALL_SOURCE, SMALL)];
        assert.equal(smallSignalsStack(withCluster, HEURISTICS_ONLY), false);
    });

    test("the one stacking test", () => {
        assert.equal(canStack(SMALL, false), false);
        assert.equal(canStack(SMALL, true), true);
        assert.equal(canStack(CONFIG.STACK_MIN_SIGNAL, false), true);
        assert.equal(canStack(0, true), false);               // only negative signals stack
    });
});

describe("v3.5.6 — the engine returns both verdicts; hostVerdict() picks one", () => {
    function driveBin() {
        return ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null,
            domainHit: SuspiciousDomains.lookup(new URL(DRIVE_LINK).hostname), tldHit: null,
            sketchyUrl: SketchyUrlCheck.check(DRIVE_FILE), mimeResult: null, sizeResult: null, riskyHosting: null,
            url: DRIVE_FILE, originalUrl: DRIVE_LINK, fileType: "executable",
            obfuscation: FilenameAnalysis.getObfuscationSignal(null, HIDDEN_EXT),
        });
    }

    test("real case: hidden .bin from a Drive link — heuristics only scores worse than VT-known", () => {
        const r = driveBin();
        const known = ScoringEngineV2.hostVerdict(r, false), unknown = ScoringEngineV2.hostVerdict(r, true);
        assert.ok(r.breakdown.some(e => e.source === "DomainList"), "the Drive link is a dubious source");
        assert.ok(unknown.score < known.score, JSON.stringify({ known: known.score, unknown: unknown.score }));
        assert.equal(known.score, r.score);                       // the top level is the VT-known verdict
    });

    test("hostVerdict keeps fields a caller added next to the engine's own", () => {
        const r = { ...driveBin(), rdap: { label: "kept" } };
        assert.equal(ScoringEngineV2.hostVerdict(r, true).rdap.label, "kept");
        assert.equal(ScoringEngineV2.hostVerdict(r, true).heuristicsOnly, undefined);
    });

    test("the active-threat floor covers both verdicts", () => {
        const r = ScoringEngineV2.evaluateHostReputation({
            dnsChecks: [{ status: "ALLOWED" }], rdap: null, domainHit: null, tldHit: null, sketchyUrl: null,
            mimeResult: null, sizeResult: null, riskyHosting: null, url: ACTIVE_THREAT_URL, fileType: "archive",
        });
        const floored = ActiveThreatHosts.applyFloor(r, ACTIVE_THREAT_URL);
        assert.ok(floored.score <= ActiveThreatHosts.CONFIG.FLOOR_SCORE);
        assert.ok(ScoringEngineV2.hostVerdict(floored, true).score <= ActiveThreatHosts.CONFIG.FLOOR_SCORE);
    });
});

describe("v3.5.6 — the real path (BrowserProtection.checkHostReputation) carries both verdicts", () => {
    test("the reported Drive .bin: heuristicsOnly reaches the caller and scores worse", async () => {
        const saved = globalThis.fetch;
        globalThis.fetch = async () => { throw new Error("offline test"); };     // DNS/RDAP → unknown
        try {
            const c = FilenameAnalysis.classifyDownload(DRIVE_FILE, DRIVE_LINK, HIDDEN_NAME, HIDDEN_MIME);
            const obfuscation = FilenameAnalysis.getObfuscationSignal(FilenameAnalysis.getRawExt(FilenameAnalysis.extractFilenameFromUrl(DRIVE_LINK)), c.ext);
            const r = await BrowserProtection.checkHostReputation(DRIVE_FILE, c.fileType, c.ext, HIDDEN_MIME, 0, DRIVE_LINK,
                c.isScript, obfuscation, null, false, HIDDEN_NAME, false, null, null, null);
            assert.ok(r.heuristicsOnly, "checkHostReputation must pass the heuristics-only verdict through");
            assert.ok(ScoringEngineV2.hostVerdict(r, true).score < ScoringEngineV2.hostVerdict(r, false).score);
        } finally {
            if (saved === undefined) delete globalThis.fetch; else globalThis.fetch = saved;
        }
    });
});
