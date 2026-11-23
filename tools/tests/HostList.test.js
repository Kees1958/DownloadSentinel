"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { HostList } from "../../util/HostList.js";
import { SuspiciousDomains } from "../../util/SuspiciousDomains.js";
import { RiskyHostingSites } from "../../util/RiskyHostingSites.js";

describe("HostList.lookup", () => {
    test("returns null for falsy/empty input", () => {
        assert.equal(HostList.lookup(""), null);
        assert.equal(HostList.lookup(null), null);
        assert.equal(HostList.lookup(undefined), null);
    });

    test("returns null for an unlisted domain", () => {
        assert.equal(HostList.lookup("completely-unknown-domain-xyz123.example"), null);
    });

    test("matches a HaGeZi-DynDNS entry on the exact listed hostname", () => {
        const r = HostList.lookup("dyn.addr.tools");
        assert.ok(r);
        assert.equal(r.matchedDomain, "dyn.addr.tools");
        assert.equal(r.source, "HaGeZi-DynDNS");
        assert.equal(typeof r.score, "number");
    });

    test("matches a subdomain of a multi-label listed entry (suffix walk)", () => {
        // "dyn.addr.tools" is itself 3 labels — a plain "last two labels"
        // lookup would miss "www.dyn.addr.tools" entirely (this was a real
        // bug caught while building this module — see tools/update-lists.mjs
        // lookup()'s header comment).
        const r = HostList.lookup("www.dyn.addr.tools");
        assert.ok(r);
        assert.equal(r.matchedDomain, "dyn.addr.tools");

        const deeper = HostList.lookup("a.b.dyn.addr.tools");
        assert.ok(deeper);
        assert.equal(deeper.matchedDomain, "dyn.addr.tools");
    });

    test("matches a subdomain of a two-label listed entry", () => {
        const r = HostList.lookup("random-subdomain.000webhostapp.com");
        assert.ok(r);
        assert.equal(r.matchedDomain, "000webhostapp.com");
    });

    test("is case-insensitive", () => {
        const r = HostList.lookup("DYN.ADDR.TOOLS");
        assert.ok(r);
        assert.equal(r.matchedDomain, "dyn.addr.tools");
    });

    test("entries already covered by SuspiciousDomains.js are excluded (no double counting)", () => {
        // duckdns.org is a SuspiciousDomains.js entry AND appears in the raw
        // HaGeZi dyndns list — the generator must have excluded it here.
        assert.ok(SuspiciousDomains.lookup("duckdns.org"), "sanity: duckdns.org is in SuspiciousDomains");
        assert.equal(HostList.lookup("duckdns.org"), null);
    });

    test("entries already covered by RiskyHostingSites.js are excluded (no double counting)", () => {
        assert.ok(RiskyHostingSites.lookup("mega.nz"), "sanity: mega.nz is in RiskyHostingSites");
        assert.equal(HostList.lookup("mega.nz"), null);
    });

    test("an entry matched by more than one source list combines its source tags", () => {
        // 000webhostapp.com appears in both HaGeZi-Hoster and Kees-Suspicious
        // raw lists — the merged entry should record both.
        const r = HostList.lookup("000webhostapp.com");
        assert.ok(r);
        assert.ok(r.source.includes("HaGeZi-Hoster"));
        assert.ok(r.source.includes("Kees-Suspicious"));
    });

    test("a plain legitimate vendor domain never matches", () => {
        for (const host of ["microsoft.com", "google.com", "nodejs.org", "python.org", "github.com", "raw.githubusercontent.com"]) {
            assert.equal(HostList.lookup(host), null, `${host} should not be in HostList`);
        }
    });

    test("entry count is in the expected range (sanity check against generator drift)", () => {
        // Loose bounds, not an exact pin — the raw lists are refreshed by
        // tools/update-lists.mjs and will drift slightly release to release.
        assert.ok(HostList._ENTRY_COUNT > 2000 && HostList._ENTRY_COUNT < 3500,
            `HostList._ENTRY_COUNT (${HostList._ENTRY_COUNT}) is outside the expected range — ` +
            `re-run tools/update-lists.mjs and confirm the raw source lists are intact`);
    });
});
