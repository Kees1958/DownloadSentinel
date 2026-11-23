"use strict";

// v3.5.5 — precompiled, lazily parsed list modules (ported from 3P Matrix 4.5.4 tools/test-perf-guards.mjs, P4).
// Every util/<Name>.default.js ships ONE JSON string; util/<Name>.js parses it on its FIRST lookup (util/LazyJson.js),
// never at service-worker start. Checks: importing all wrappers parses nothing; every wrapper answers like the
// shipped data (data/<Name>.json, the single source of truth); resetToDefault() releases and the next
// lookup rebuilds. node --test runs each file in its own process, so the import count below is this file's alone.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const EXT_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const LIST_WRAPPERS = Object.freeze(["PublicSuffixList", "HostList", "TopSitesFilter", "Brands", "SuspiciousTlds",
    "SuspiciousDomains", "RiskyHostingSites", "UrlShorteners", "GovSuffixes", "RdapCctlds", "PlatformSuffixes"]);
const SET_LISTS = Object.freeze(["UrlShorteners", "GovSuffixes", "RdapCctlds", "PlatformSuffixes"]);

// Count JSON.parse calls during the imports only (guard: always restored).
const nativeParse = JSON.parse;
let parses = 0;
JSON.parse = function countingParse(...a) { parses++; return Reflect.apply(nativeParse, JSON, a); };
const W = {};
try {
    for (const n of LIST_WRAPPERS) W[n] = (await import(pathToFileURL(path.join(EXT_ROOT, "util", `${n}.js`)).href))[n];
} finally {
    JSON.parse = nativeParse;
}
const importParses = parses;
const data = Object.fromEntries(LIST_WRAPPERS.map(n =>
    [n, nativeParse(readFileSync(path.join(EXT_ROOT, "data", `${n}.json`), "utf8"))]));

describe("lazy list modules (v3.5.5)", () => {
    test("importing all list wrappers parses nothing", () => assert.equal(importParses, 0));
    test("every generated module exports one JSON string", async () => {
        for (const n of LIST_WRAPPERS) {
            const mod = await import(pathToFileURL(path.join(EXT_ROOT, "util", `${n}.default.js`)).href);
            assert.equal(typeof mod[`${n}DefaultJson`], "string", n);
            assert.deepEqual(nativeParse(mod[`${n}DefaultJson`]), data[n], `${n}.default.js equals data/${n}.json`);
        }
    });
    test("wrappers answer from the shipped data", () => {
        const [plain] = data.PublicSuffixList.rules.filter(r => r.includes("."));
        assert.equal(W.PublicSuffixList.getRegisteredDomain(`a.b.${plain}`), `b.${plain}`);
        const [host, hit] = Object.entries(data.HostList)[0];
        assert.equal(W.HostList.lookup(host)?.score, hit.score);
        const [tld, tScore] = Object.entries(data.SuspiciousTlds)[0];
        assert.equal(W.SuspiciousTlds.lookup(tld)?.score, tScore);
        const [dom, dScore] = Object.entries(data.SuspiciousDomains)[0];
        assert.equal(W.SuspiciousDomains.lookup(dom)?.score, dScore);
        const site = data.RiskyHostingSites[0];
        assert.equal(W.RiskyHostingSites.lookup(site.host)?.score, site.score);
        for (const n of SET_LISTS) {
            assert.deepEqual(W[n].list, data[n], n);
            assert.equal(W[n].set.size, new Set(data[n]).size, n);
        }
        const brand = data.Brands.find(b => !b.wholeNameOnly && !b.keyword.includes("."));
        assert.ok(W.Brands.isExemptHost(brand.domains[0]));
        assert.equal(W.Brands.list.length, data.Brands.length);
        assert.ok(W.TopSitesFilter.mightBeTopSite(brand.domains[0]), "brand websites are built into the filter");
    });
    test("resetToDefault() releases; the next lookup rebuilds", () => {
        const [plain] = data.PublicSuffixList.rules.filter(r => r.includes("."));
        const [host, hit] = Object.entries(data.HostList)[0];
        for (const n of LIST_WRAPPERS) W[n].resetToDefault();
        assert.equal(W.PublicSuffixList.getRegisteredDomain(`a.b.${plain}`), `b.${plain}`);
        assert.equal(W.HostList.lookup(host)?.score, hit.score);
        assert.equal(W.UrlShorteners.set.size, new Set(data.UrlShorteners).size);
        assert.equal(W.Brands.list.length, data.Brands.length);
    });
});
