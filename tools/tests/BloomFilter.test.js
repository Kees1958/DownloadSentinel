"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { BloomFilter } from "../../util/BloomFilter.js";

describe("BloomFilter.sizeFor", () => {
    test("returns a positive size and hash count for ordinary inputs", () => {
        const { size, numHashes } = BloomFilter.sizeFor(1000, 0.01);
        assert.ok(size > 0);
        assert.ok(numHashes >= 1);
    });

    test("a lower false-positive target yields a larger filter", () => {
        const loose = BloomFilter.sizeFor(1000, 0.1);
        const tight = BloomFilter.sizeFor(1000, 0.001);
        assert.ok(tight.size > loose.size);
    });
});

describe("BloomFilter.create — add/has", () => {
    test("every added item is reported present (no false negatives)", () => {
        const { size, numHashes } = BloomFilter.sizeFor(500, 0.01);
        const filter = BloomFilter.create(size, numHashes);
        const items = Array.from({ length: 500 }, (_, i) => `item-${i}.example`);
        for (const item of items) filter.add(item);
        for (const item of items) assert.ok(filter.has(item), `expected ${item} to be present`);
    });

    test("an empty filter reports nothing as present", () => {
        const { size, numHashes } = BloomFilter.sizeFor(100, 0.01);
        const filter = BloomFilter.create(size, numHashes);
        assert.equal(filter.has("never-added.example"), false);
    });

    test("false-positive rate stays in a reasonable range near the target", () => {
        const target = 0.01;
        const n = 2000;
        const { size, numHashes } = BloomFilter.sizeFor(n, target);
        const filter = BloomFilter.create(size, numHashes);
        for (let i = 0; i < n; i++) filter.add(`real-${i}.example`);

        let falsePositives = 0;
        const trials = 10000;
        for (let i = 0; i < trials; i++) {
            if (filter.has(`absent-${i}.example`)) falsePositives++;
        }
        const rate = falsePositives / trials;
        // Generous bounds (not a precise statistical test) — just guards
        // against a hashing bug that would blow the rate up by an order of
        // magnitude (e.g. all probes colliding on one bit).
        assert.ok(rate < target * 5, `false-positive rate ${rate} far exceeds target ${target}`);
    });
});

describe("BloomFilter.toBase64 / fromBase64 — round trip", () => {
    test("a filter rebuilt from its own base64 answers identically", () => {
        const { size, numHashes } = BloomFilter.sizeFor(300, 0.01);
        const original = BloomFilter.create(size, numHashes);
        const items = Array.from({ length: 300 }, (_, i) => `site-${i}.test`);
        for (const item of items) original.add(item);

        const rebuilt = BloomFilter.fromBase64(size, numHashes, original.toBase64());
        for (const item of items) assert.ok(rebuilt.has(item));
        assert.equal(rebuilt.has("definitely-not-in-the-set.xyz"), original.has("definitely-not-in-the-set.xyz"));
    });
});
