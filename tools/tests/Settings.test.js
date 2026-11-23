"use strict";

import { test, describe, before, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { installChromeMock, resetChromeMock, uninstallChromeMock } from "./helpers/chromeMock.js";

// chrome must be mocked before Storage.js/Settings.js ever call chrome.* —
// both only touch chrome.* inside function bodies (never at module load), so
// installing the mock here, before importing, is sufficient and safe.
before(() => installChromeMock());
beforeEach(() => resetChromeMock());
after(() => uninstallChromeMock());

const { Storage } = await import("../../util/Storage.js");
const { Settings } = await import("../../util/Settings.js");

describe("Storage", () => {
    test("round-trips a value through set then get", async () => {
        await new Promise(resolve => Storage.setToLocalStore("k", { a: 1 }, resolve));
        const value = await new Promise(resolve => Storage.getFromLocalStore("k", resolve));
        assert.deepEqual(value, { a: 1 });
    });

    test("get on a missing key resolves undefined, not an error", async () => {
        const value = await new Promise(resolve => Storage.getFromLocalStore("missing-key", resolve));
        assert.equal(value, undefined);
    });
});

describe("Settings", () => {
    test("get() on first run returns full defaults", async () => {
        const settings = await new Promise(resolve => Settings.get(resolve));
        assert.equal(settings.extensionEnabled, true);
        assert.equal(settings.fpReductionLevel, "MEDIUM");
        assert.deepEqual(settings.customDomains, ["sharepoint.com"]);
    });

    test("set() merges a partial update on top of defaults and persists it", async () => {
        await new Promise(resolve => Settings.set({ vtApiKey: "abc123", extensionEnabled: false }, resolve));
        const settings = await new Promise(resolve => Settings.get(resolve));
        assert.equal(settings.vtApiKey, "abc123");
        assert.equal(settings.extensionEnabled, false);
        // Untouched keys keep their defaults — merge must not clobber the rest
        assert.equal(settings.fpReductionLevel, "MEDIUM");
    });

    test("a second set() merges onto the first, not onto raw defaults (no regression)", async () => {
        await new Promise(resolve => Settings.set({ vtApiKey: "abc123" }, resolve));
        await new Promise(resolve => Settings.set({ autoAllow: true }, resolve));
        const settings = await new Promise(resolve => Settings.get(resolve));
        assert.equal(settings.vtApiKey, "abc123"); // still present after the second set()
        assert.equal(settings.autoAllow, true);
    });

    // v3.3.0 (item 13) — schema version + migration scaffolding
    test("get() stamps pre-schema-versioning stored data (no schemaVersion key) up to the current version", async () => {
        // Simulates data saved by an install from before schemaVersion existed:
        // write directly to Storage, bypassing Settings.set()'s own merge.
        await new Promise(resolve => Storage.setToLocalStore("Settings", { vtApiKey: "old-data" }, resolve));
        const settings = await new Promise(resolve => Settings.get(resolve));
        assert.equal(settings.vtApiKey, "old-data"); // migration doesn't touch unrelated data
        assert.equal(settings.schemaVersion, 1);
    });

    test("get() on first run (nothing stored) already has the current schema version", async () => {
        const settings = await new Promise(resolve => Settings.get(resolve));
        assert.equal(settings.schemaVersion, 1);
    });
});
