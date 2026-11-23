"use strict";

import { test, describe, after } from "node:test";
import assert from "node:assert/strict";
import { TopSitesFilter } from "../../util/TopSitesFilter.js";
import { BloomFilter } from "../../util/BloomFilter.js";

// setData()/resetToDefault() mutate this module's shared in-memory state —
// restore the bundled default once this file is done so later test files
// that import this same module instance never see a leaked custom filter.
after(() => {
    TopSitesFilter.resetToDefault();
});

describe("TopSitesFilter.mightBeTopSite — bundled default (real CrUX top-1M data)", () => {
    test("recognises well-known top sites", () => {
        assert.equal(TopSitesFilter.mightBeTopSite("google.com"), true);
        assert.equal(TopSitesFilter.mightBeTopSite("github.com"), true);
    });

    test("recognises a multi-label-TLD top site (registrable domain form)", () => {
        assert.equal(TopSitesFilter.mightBeTopSite("amazon.co.jp"), true);
    });

    test("does not recognise an invented, implausible domain", () => {
        assert.equal(TopSitesFilter.mightBeTopSite("totally-fake-nonexistent-xyz123.com"), false);
    });

    test("null/empty input returns false, never throws", () => {
        assert.equal(TopSitesFilter.mightBeTopSite(null), false);
        assert.equal(TopSitesFilter.mightBeTopSite(""), false);
    });

    test("is case-insensitive", () => {
        assert.equal(TopSitesFilter.mightBeTopSite("GOOGLE.COM"), true);
    });
});

describe("TopSitesFilter.setData / resetToDefault — guard contract", () => {
    test("setData() wholesale-replaces the active filter", () => {
        const { size, numHashes } = BloomFilter.sizeFor(10, 0.01);
        const filter = BloomFilter.create(size, numHashes);
        filter.add("custom-test-domain.example");

        TopSitesFilter.setData({ size, numHashes, bitsBase64: filter.toBase64() });
        assert.equal(TopSitesFilter.mightBeTopSite("custom-test-domain.example"), true);
        // The bundled default's real top sites are gone — proof the swap
        // was total, not merged with the previous filter.
        assert.equal(TopSitesFilter.mightBeTopSite("google.com"), false);
    });

    test("resetToDefault() restores the bundled real-world filter", () => {
        TopSitesFilter.resetToDefault();
        assert.equal(TopSitesFilter.mightBeTopSite("google.com"), true);
    });
});
