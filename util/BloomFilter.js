"use strict";

/**
 * BloomFilter.js — a small, generic, dependency-free Bloom filter.
 *
 * A Bloom filter answers "is X possibly in this set?" using far less memory
 * than storing the set itself, at the cost of a tunable false-positive rate
 * (NEVER a false negative — if it says "no", the item is definitely not in
 * the set). This is what makes it practical to ship a membership test
 * against a million-entry list (util/TopSitesFilter.js) as a ~1-2MB data
 * file instead of the ~20-30MB the raw domain strings would otherwise cost.
 *
 * Pure, synchronous, no chrome.* access — this module is reused as-is by
 * both the build-time TOOLS script that constructs the filter
 * (tools/build-top-sites-filter.mjs, run under Node) and the EXTENSION
 * runtime that queries it (util/TopSitesFilter.js, run in the browser).
 * Using the exact same code on both ends is deliberate: a Bloom filter's
 * bits are meaningless unless queried with the IDENTICAL hash functions
 * that built them, and importing one shared module guarantees that rather
 * than relying on two hand-kept-in-sync copies.
 *
 * Hashing: Kirsch-Mitzenmacher double hashing (https://www.eecs.harvard.edu/~michaelm/postscripts/rsa2008.pdf)
 * — two independent 32-bit hashes (FNV-1a and a DJB2 variant) combined as
 * g_i(x) = (h1(x) + i * h2(x)) mod m for i = 0..k-1, which is statistically
 * as good as k fully-independent hash functions for this purpose, without
 * needing k separate implementations.
 */
export const BloomFilter = (function () {

    // ── CONFIG — every magic number for this module, gathered here ─────────
    const CONFIG = Object.freeze({
        // Target false-positive rate this module's own sizeFor()/create()
        // convenience aims for when a caller doesn't hand-pick size/numHashes
        // itself. 0.1% is conservative enough that, combined with this check
        // always being scored as a weak/contextual signal (never a hard
        // block — see ScoringEngineV2.js), an occasional coincidental match
        // against an unrelated popular site is an acceptable cost for a
        // compact filter.
        DEFAULT_FALSE_POSITIVE_RATE: 0.001,
    });

    // ── Hash functions — pure, platform-independent (plain ECMAScript
    // integer/string ops only, so Node at build time and the browser's V8 at
    // runtime always agree bit-for-bit). Both forced to unsigned 32-bit via
    // `>>> 0` throughout to avoid sign/overflow drift.
    function fnv1a(str) {
        let hash = 0x811c9dc5; // FNV offset basis (32-bit)
        for (let i = 0; i < str.length; i++) {
            hash ^= str.charCodeAt(i);
            hash = Math.imul(hash, 0x01000193); // FNV prime (32-bit)
        }
        return hash >>> 0;
    }

    function djb2(str) {
        let hash = 5381;
        for (let i = 0; i < str.length; i++) {
            hash = (Math.imul(hash, 33) + str.charCodeAt(i)) >>> 0;
        }
        // Guard: a second hash of 0 would make every g_i() collapse onto the
        // same bit as h1() (i * 0 = 0) — force it odd/non-zero so the k
        // probe positions actually spread out.
        return (hash || 1) >>> 0;
    }

    function* probeBits(item, size, numHashes) {
        const h1 = fnv1a(item);
        const h2 = djb2(item);
        for (let i = 0; i < numHashes; i++) {
            // >>> 0 keeps the sum in unsigned 32-bit range before the modulo,
            // so this is never thrown off by a negative intermediate value.
            yield ((h1 + i * h2) >>> 0) % size;
        }
    }

    // ── Bit-array helpers — a plain Uint8Array used as a packed bitset ──────
    function getBit(bytes, index) {
        return (bytes[index >> 3] & (1 << (index & 7))) !== 0;
    }

    function setBit(bytes, index) {
        bytes[index >> 3] |= (1 << (index & 7));
    }

    // ── Sizing convenience — optimal (size in bits, hash count) for n
    // expected items at a target false-positive rate p. Standard Bloom
    // filter formulas: m = -n*ln(p) / (ln2)^2, k = (m/n)*ln2.
    function sizeFor(expectedItems, falsePositiveRate = CONFIG.DEFAULT_FALSE_POSITIVE_RATE) {
        const m = Math.ceil(-expectedItems * Math.log(falsePositiveRate) / (Math.LN2 * Math.LN2));
        const k = Math.max(1, Math.round((m / expectedItems) * Math.LN2));
        return { size: m, numHashes: k };
    }

    /**
     * Create a new, empty filter of the given size (bits) and hash count.
     * @returns {{add, has, size, numHashes, toBase64}}
     */
    function create(size, numHashes) {
        const bytes = new Uint8Array(Math.ceil(size / 8));

        function add(item) {
            for (const bit of probeBits(item, size, numHashes)) setBit(bytes, bit);
        }

        function has(item) {
            for (const bit of probeBits(item, size, numHashes)) {
                if (!getBit(bytes, bit)) return false; // definitely not a member
            }
            return true; // possibly a member (or a false positive)
        }

        function toBase64() {
            // btoa/Buffer both operate on "binary string" — build one byte
            // at a time rather than assuming either global is present, so
            // this works identically under Node (build time) and the
            // browser (runtime). Referenced via globalThis rather than a
            // bare identifier: this module's EXTENSION-side eslint config
            // (browser/webextensions env only, no Node globals) would
            // otherwise flag a direct "Buffer" reference as undefined, even
            // though it is only ever reached on the Node side of this
            // module's shared build-time/runtime use (see module header).
            let binary = "";
            for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
            if (typeof btoa === "function") return btoa(binary);
            return globalThis.Buffer.from(binary, "binary").toString("base64");
        }

        return { add, has, size, numHashes, toBase64 };
    }

    /**
     * Rebuild a filter from a previously-serialised {size, numHashes,
     * bitsBase64} — the shape util/TopSitesFilter.js's data file carries.
     */
    function fromBase64(size, numHashes, bitsBase64) {
        let binary;
        if (typeof atob === "function") binary = atob(bitsBase64);
        else binary = globalThis.Buffer.from(bitsBase64, "base64").toString("binary");

        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

        function has(item) {
            for (const bit of probeBits(item, size, numHashes)) {
                if (!getBit(bytes, bit)) return false;
            }
            return true;
        }

        return { has, size, numHashes };
    }

    return { create, fromBase64, sizeFor, CONFIG };
})();
