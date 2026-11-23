"use strict";

import { test, describe, mock, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { BrowserProtection } from "../../protection/BrowserProtection.js";
import { ProtectionResult } from "../../protection/ProtectionResult.js";
import { APP } from "../../util/AppConstants.js";

// No live network in this test file — every test installs its own
// fully-synthetic globalThis.fetch stub. Timers are mocked (node:test's
// experimental MockTimers) so the item-16 retry-on-timeout tests don't
// actually have to wait out APP.VT_FETCH_TIMEOUT_MS/VT_RETRY_TIMEOUT_MS
// (3s/7s) in real time — virtual time is advanced deterministically instead.

let originalFetch;
const SETTINGS = Object.freeze({
    extensionEnabled: true,
    virusTotalEnabled: true,
    isVtApiKeySet: true,
    vtApiKey: "test-key",
    fpReductionLevel: "NONE", // no engine filtering — see ScoringEngineV2.test.js's own fixtures for this convention
});

beforeEach(() => {
    originalFetch = globalThis.fetch;
    mock.timers.enable({ apis: ["setTimeout"] });
});

afterEach(() => {
    mock.timers.reset();
    if (originalFetch === undefined) delete globalThis.fetch;
    else globalThis.fetch = originalFetch;
});

// Flush pending microtasks (promise .then callbacks queued by a tick()-fired
// timer) without advancing virtual time any further.
async function flushMicrotasks() {
    for (let i = 0; i < 5; i++) await Promise.resolve();
}

// Realistic enough engine counts to actually cross evaluate()'s
// classification thresholds (see ScoringEngineV2.test.js's own fixtures for
// the same pattern) — a single engine's verdict alone does not.
const oneYearAgoUnix = Math.floor(Date.now() / 1000) - 365 * 86400;
function vtJsonResponse(verdict /* "clean" | "malicious" */) {
    const results = verdict === "malicious"
        ? { EngineA: { category: "malicious", result: "Trojan" }, EngineB: { category: "malicious", result: "Trojan" },
            EngineC: { category: "malicious", result: "Trojan" }, EngineD: { category: "malicious", result: "Trojan" },
            EngineE: { category: "malicious", result: "Trojan" } } // 5+ malicious -> hard-rule PROBABLY_MALICIOUS
        : { EngineA: { category: "harmless" }, EngineB: { category: "harmless" }, EngineC: { category: "undetected" } };
    return {
        ok: true,
        json: async () => ({
            data: { attributes: { last_analysis_results: results, first_submission_date: oneYearAgoUnix } },
        }),
    };
}

describe("BrowserProtection.checkIfUrlIsMalicious — basic contract", () => {
    test("missing settings is a safe no-op (never throws, never calls back)", () => {
        let called = false;
        assert.doesNotThrow(() => {
            BrowserProtection.checkIfUrlIsMalicious("k1", "https://example.com/f.exe", () => { called = true; }, null, null);
        });
        assert.equal(called, false);
    });

    test("an invalid URL is a safe no-op", () => {
        let called = false;
        BrowserProtection.checkIfUrlIsMalicious("k2", "not a url", () => { called = true; }, null, SETTINGS);
        assert.equal(called, false);
    });

    test("isVtPending is false for a key with no in-flight check", () => {
        assert.equal(BrowserProtection.isVtPending("no-such-key"), false);
    });

    test("a normal, fast VT response calls back once with the parsed verdict (unchanged pre-item-16 behavior)", async () => {
        globalThis.fetch = async () => vtJsonResponse("clean");
        const results = [];
        BrowserProtection.checkIfUrlIsMalicious("k3", "https://unique-clean-example.test/f.exe", (r) => results.push(r), null, SETTINGS);

        // Let the VT_FETCH_STARTUP_DELAY_MS pause elapse, then the fetch's
        // own microtasks resolve.
        mock.timers.tick(APP.VT_FETCH_STARTUP_DELAY_MS);
        await flushMicrotasks();

        assert.equal(results.length, 1);
        assert.equal(results[0].result, ProtectionResult.ResultType.PROBABLY_SAFE);
        assert.equal(BrowserProtection.isVtPending("k3"), false);
    });
});

describe("BrowserProtection.checkIfUrlIsMalicious — item 16, retry-on-timeout", () => {
    test("without onLateResult, a timeout aborts immediately (old behavior) and isVtPending goes false", async () => {
        let resolveFetch; // left pending deliberately — this test only cares about the timeout path
        globalThis.fetch = () => new Promise((resolve) => { resolveFetch = resolve; });

        const results = [];
        BrowserProtection.checkIfUrlIsMalicious("k4", "https://slow-no-retry-example.test/f.exe", (r) => results.push(r), null, SETTINGS);
        // no onLateResult passed

        mock.timers.tick(APP.VT_FETCH_STARTUP_DELAY_MS);
        await flushMicrotasks();
        mock.timers.tick(APP.VT_FETCH_TIMEOUT_MS);
        await flushMicrotasks();

        assert.equal(results.length, 1);
        assert.equal(results[0].result, ProtectionResult.ResultType.UNKNOWN);
        // Old behavior: the key is released (aborted) right at the first timeout.
        assert.equal(BrowserProtection.isVtPending("k4"), false);
        resolveFetch(vtJsonResponse("clean")); // let the dangling promise settle so it can't leak into another test
    });

    test("with onLateResult: first timeout reports UNKNOWN immediately, then a late verdict arrives via onLateResult", async () => {
        let resolveFetch;
        globalThis.fetch = () => new Promise((resolve) => { resolveFetch = resolve; });

        const results = [];
        const lateResults = [];
        BrowserProtection.checkIfUrlIsMalicious(
            "k5", "https://slow-with-retry-example.test/f.exe",
            (r) => results.push(r), null, SETTINGS,
            (r) => lateResults.push(r)
        );

        mock.timers.tick(APP.VT_FETCH_STARTUP_DELAY_MS);
        await flushMicrotasks();

        // First deadline fires — caller is told UNKNOWN right away.
        mock.timers.tick(APP.VT_FETCH_TIMEOUT_MS);
        await flushMicrotasks();
        assert.equal(results.length, 1);
        assert.equal(results[0].result, ProtectionResult.ResultType.UNKNOWN);

        // Crucially: the request was NOT aborted — still pending, per item 16.
        assert.equal(BrowserProtection.isVtPending("k5"), true);
        assert.equal(lateResults.length, 0);

        // VT finally answers, well within the extended VT_RETRY_TIMEOUT_MS budget.
        resolveFetch(vtJsonResponse("malicious"));
        await flushMicrotasks();

        assert.equal(results.length, 1); // original callback never fires twice
        assert.equal(lateResults.length, 1);
        assert.equal(lateResults[0].result, ProtectionResult.ResultType.PROBABLY_MALICIOUS);
        assert.equal(BrowserProtection.isVtPending("k5"), false); // released once the late verdict lands
    });

    test("with onLateResult: if the retry ALSO times out, nothing further is reported (silent give-up)", async () => {
        let resolveFetch;
        globalThis.fetch = (fetchUrl, opts) => new Promise((resolve, reject) => {
            resolveFetch = resolve;
            opts.signal.addEventListener("abort", () => {
                const err = new Error("aborted");
                err.name = "AbortError";
                reject(err);
            });
        });

        const results = [];
        const lateResults = [];
        BrowserProtection.checkIfUrlIsMalicious(
            "k6", "https://slow-retry-also-times-out-example.test/f.exe",
            (r) => results.push(r), null, SETTINGS,
            (r) => lateResults.push(r)
        );

        mock.timers.tick(APP.VT_FETCH_STARTUP_DELAY_MS);
        await flushMicrotasks();
        mock.timers.tick(APP.VT_FETCH_TIMEOUT_MS); // first deadline
        await flushMicrotasks();
        assert.equal(results.length, 1);
        assert.equal(BrowserProtection.isVtPending("k6"), true);

        mock.timers.tick(APP.VT_RETRY_TIMEOUT_MS); // extended deadline — aborts for real this time
        await flushMicrotasks();

        assert.equal(results.length, 1);     // still just the one UNKNOWN
        assert.equal(lateResults.length, 0); // nothing to report — stays silent, not a second UNKNOWN
        assert.equal(BrowserProtection.isVtPending("k6"), false);
        void resolveFetch; // unused on this path — the abort listener rejects first
    });
});
