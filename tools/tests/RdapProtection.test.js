"use strict";

import { test, describe, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { RdapProtection } from "../../protection/RdapProtection.js";

// No live network in this test file — every test installs its own
// fully-synthetic globalThis.fetch stub.
let originalFetch;

beforeEach(() => { originalFetch = globalThis.fetch; });
afterEach(() => {
    if (originalFetch === undefined) delete globalThis.fetch;
    else globalThis.fetch = originalFetch;
});

describe("RdapProtection.scoreAge — pure cut-point scoring", () => {
    test("very new domain (< 30 days) scores -30", () => {
        assert.equal(RdapProtection.scoreAge(5).score, -30);
    });
    test("moderately new domain (30-90 days) scores -10", () => {
        assert.equal(RdapProtection.scoreAge(45).score, -10);
    });
    test("established domain (> 90 days) scores 0", () => {
        assert.equal(RdapProtection.scoreAge(200).score, 0);
    });
    test("null/undefined age (not determined) scores -10, same tier as moderately-new", () => {
        assert.equal(RdapProtection.scoreAge(null).score, -10);
        assert.equal(RdapProtection.scoreAge(undefined).score, -10);
    });
});

describe("RdapProtection.check — a real response with no date stays -10 (v3.2.0, item 2)", () => {
    // RDAP answered, it just has no registration date published. This is
    // still evidence (the registry answered), unlike the lookup itself
    // failing below — unchanged from v3.2.0.
    test("a real RDAP response with no registration event (NO_DATE) scores -10", async () => {
        globalThis.fetch = async () => ({
            ok: true,
            json: async () => ({ events: [{ eventAction: "last changed", eventDate: "2020-01-01" }] }),
        });
        const r = await RdapProtection.check("example.com");
        assert.equal(r.status, "NO_DATE");
        assert.equal(r.score, -10);
    });
});

describe("RdapProtection.check — a failed/unreachable lookup now scores neutral (v3.3.0, item 2)", () => {
    // Reversed from v3.2.0: the lookup itself failing (non-2xx, thrown
    // error, timeout) is scored 0, not -10. A flaky/unreachable
    // third-party service is not evidence about the domain either way.

    test("a non-2xx RDAP response (fetch 'succeeds' but response not ok) scores 0, not -10", async () => {
        globalThis.fetch = async () => ({ ok: false, status: 404 });
        const r = await RdapProtection.check("example.com");
        assert.equal(r.status, "UNKNOWN");
        assert.equal(r.score, 0);
    });

    test("a thrown network error scores 0, not -10", async () => {
        globalThis.fetch = async () => { throw new Error("network down"); };
        const r = await RdapProtection.check("example.com");
        assert.equal(r.status, "UNKNOWN");
        assert.equal(r.score, 0);
    });

    test("an aborted/timed-out lookup scores 0, not -10", async () => {
        // Simulates what a real timeout looks like from check()'s own catch
        // block's point of view (an AbortError), without waiting out the
        // real APP.RDAP_TIMEOUT_MS — fast and deterministic.
        globalThis.fetch = async () => {
            const err = new Error("aborted");
            err.name = "AbortError";
            throw err;
        };
        const r = await RdapProtection.check("example.com");
        assert.equal(r.status, "UNKNOWN");
        assert.equal(r.score, 0);
        assert.match(r.label, /timed out/);
    });
});

describe("RdapProtection.check — not-applicable domains skip the lookup entirely (v3.3.0, item 1)", () => {
    test("a hosting-platform subdomain scores 0 with no network call", async () => {
        globalThis.fetch = async () => {
            throw new Error("fetch should not be called for a platform subdomain");
        };
        const r = await RdapProtection.check("example.github.io");
        assert.equal(r.status, "NOT_APPLICABLE");
        assert.equal(r.score, 0);
    });

    test("a ccTLD with no RDAP service scores 0 with no network call", async () => {
        globalThis.fetch = async () => {
            throw new Error("fetch should not be called for a ccTLD with no RDAP service");
        };
        // "de" is a real ccTLD with no RDAP service and is not in
        // RdapCctlds's bundled list.
        const r = await RdapProtection.check("example.de");
        assert.equal(r.status, "NOT_APPLICABLE");
        assert.equal(r.score, 0);
    });
});

describe("RdapProtection.check — a real registration date still scores normally", () => {
    test("a young domain (registered 5 days ago) scores -30, not -10", async () => {
        const fiveDaysAgo = new Date(Date.now() - 5 * 86400000).toISOString();
        globalThis.fetch = async () => ({
            ok: true,
            json: async () => ({ events: [{ eventAction: "registration", eventDate: fiveDaysAgo }] }),
        });
        const r = await RdapProtection.check("example.com");
        assert.equal(r.status, "YOUNG_DOMAIN");
        assert.equal(r.score, -30);
    });

    test("an established domain (registered 2000 days ago) scores 0", async () => {
        const longAgo = new Date(Date.now() - 2000 * 86400000).toISOString();
        globalThis.fetch = async () => ({
            ok: true,
            json: async () => ({ events: [{ eventAction: "registered", eventDate: longAgo }] }),
        });
        const r = await RdapProtection.check("example.com");
        assert.equal(r.status, "ESTABLISHED_DOMAIN");
        assert.equal(r.score, 0);
    });
});
