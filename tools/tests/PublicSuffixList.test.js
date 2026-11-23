"use strict";

import { test, describe, afterEach } from "node:test";
import assert from "node:assert/strict";
import { PublicSuffixList } from "../../util/PublicSuffixList.js";

// setData()/resetToDefault() mutate this module's shared in-memory state, so
// every test that calls setData() must restore the bundled default
// afterwards — otherwise one test's custom rule set would leak into the
// next test file that imports this same module instance.
afterEach(() => {
    PublicSuffixList.resetToDefault();
});

describe("PublicSuffixList.getRegisteredDomain — real-world cases", () => {
    test("plain single-label TLD", () => {
        assert.equal(PublicSuffixList.getRegisteredDomain("sub.example.com"), "example.com");
    });

    test("multi-label suffix rule (co.uk, com.br, co.jp)", () => {
        assert.equal(PublicSuffixList.getRegisteredDomain("sub.example.co.uk"), "example.co.uk");
        assert.equal(PublicSuffixList.getRegisteredDomain("www.example.com.br"), "example.com.br");
        assert.equal(PublicSuffixList.getRegisteredDomain("www.amazon.co.jp"), "amazon.co.jp");
    });

    test("ccTLD with no multi-label convention is unaffected", () => {
        assert.equal(PublicSuffixList.getRegisteredDomain("www.example.de"), "example.de");
    });

    test("wildcard rule (*.ck — every label under .ck is itself a suffix unless the registry opts a name out)", () => {
        assert.equal(PublicSuffixList.getRegisteredDomain("www.example.ck"), "example.ck");
    });

    test("exception carved out of a wildcard rule (www.ck is NOT itself a suffix)", () => {
        // The PSL explicitly lists "!www.ck" as an exception to "*.ck" — the
        // registry reserved "www.ck" to mean the plain www of the .ck TLD
        // itself, not a generic third-level suffix slot like other *.ck names.
        assert.equal(PublicSuffixList.getRegisteredDomain("www.ck"), "ck");
    });

    test("private/platform suffix (github.io) — anyone can register <name>.github.io", () => {
        assert.equal(PublicSuffixList.getRegisteredDomain("someuser.github.io"), "someuser.github.io");
    });

    test("hostname IS exactly a (multi-label) suffix — no registrable label left", () => {
        assert.equal(PublicSuffixList.getRegisteredDomain("co.uk"), null);
    });

    test("unrecognised TLD falls back to the default rule (last label alone is the suffix)", () => {
        assert.equal(PublicSuffixList.getRegisteredDomain("sub.example.totallymadeuptld"), "example.totallymadeuptld");
    });

    test("falsy/single-label input", () => {
        assert.equal(PublicSuffixList.getRegisteredDomain(""), null);
        assert.equal(PublicSuffixList.getRegisteredDomain(null), null);
        assert.equal(PublicSuffixList.getRegisteredDomain("localhost"), null);
    });
});

describe("PublicSuffixList.setData / resetToDefault — guard contract", () => {
    test("setData() wholesale-replaces the active rule set, no leftover defaults", () => {
        PublicSuffixList.setData({ rules: ["example"], wildcardRules: [], exceptions: [] });
        assert.equal(PublicSuffixList.getRegisteredDomain("sub.example"), "sub.example");
        // "co.uk" is a real-world rule but NOT in this custom set, so it no
        // longer resolves as a known multi-label suffix at all -- proof the
        // swap was total, not merged with the bundled default. Nothing
        // matches, so this falls back to the default rule (last two
        // labels), exactly like the pre-PSL naive behaviour.
        assert.equal(PublicSuffixList.getRegisteredDomain("sub.test.co.uk"), "co.uk");
    });

    test("resetToDefault() restores the bundled real-world list", () => {
        PublicSuffixList.setData({ rules: ["example"], wildcardRules: [], exceptions: [] });
        PublicSuffixList.resetToDefault();
        assert.equal(PublicSuffixList.getRegisteredDomain("sub.example.co.uk"), "example.co.uk");
    });
});
