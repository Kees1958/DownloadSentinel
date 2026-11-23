"use strict";

// ── DnsDefaults.test.js ─────────────────────────────────────────────────────
// Covers util/DnsDefaults.js (v3.3.1): region-aware first-install DNS
// threat-intel defaults — France → Control D + Cloudflare, else global.
// ─────────────────────────────────────────────────────────────────────────────

import { test, describe, afterEach } from "node:test";
import assert from "node:assert/strict";
import { DnsDefaults } from "../../util/DnsDefaults.js";
import { APP } from "../../util/AppConstants.js";

describe("DnsDefaults.resolveForTimeZone", () => {
    test("Europe/Paris → Control D first, Cloudflare second", () => {
        const d = DnsDefaults.resolveForTimeZone("Europe/Paris");
        assert.deepEqual({ ...d }, { first: "controld", second: "cloudflare", region: "FR" });
    });

    test("French overseas zones (e.g. Indian/Reunion, America/Martinique) → FR defaults", () => {
        for (const tz of ["Indian/Reunion", "America/Martinique", "Pacific/Tahiti"]) {
            assert.equal(DnsDefaults.resolveForTimeZone(tz).region, "FR", tz);
        }
    });

    test("Europe/Amsterdam and Europe/Monaco → global defaults", () => {
        for (const tz of ["Europe/Amsterdam", "Europe/Monaco"]) {
            const d = DnsDefaults.resolveForTimeZone(tz);
            assert.equal(d.first, APP.DEFAULT_DNS_FIRST, tz);
            assert.equal(d.second, APP.DEFAULT_DNS_SECOND, tz);
            assert.equal(d.region, DnsDefaults.GLOBAL_REGION, tz);
        }
    });

    test("empty / non-string input → global defaults, never throws", () => {
        for (const bad of ["", null, undefined, 42, {}]) {
            assert.equal(DnsDefaults.resolveForTimeZone(bad).region, DnsDefaults.GLOBAL_REGION);
        }
    });

    test("result is frozen", () => {
        assert.ok(Object.isFrozen(DnsDefaults.resolveForTimeZone("Europe/Paris")));
    });

    test("every region rule references real providers and differs first/second", () => {
        for (const rule of APP.DNS_REGION_DEFAULTS) {
            assert.ok(Object.hasOwn(APP.DNS_PROVIDERS, rule.first), rule.region);
            assert.ok(Object.hasOwn(APP.DNS_PROVIDERS, rule.second), rule.region);
            assert.notEqual(rule.first, rule.second, rule.region);
        }
    });
});

describe("DnsDefaults.get / reset", () => {
    afterEach(() => DnsDefaults.reset());

    test("get() returns a cached, valid pair; reset() clears the cache", () => {
        const a = DnsDefaults.get();
        assert.equal(DnsDefaults.get(), a, "same cached object");
        assert.ok(Object.hasOwn(APP.DNS_PROVIDERS, a.first));
        assert.ok(Object.hasOwn(APP.DNS_PROVIDERS, a.second));
        DnsDefaults.reset();
        assert.notEqual(DnsDefaults.get(), a, "fresh object after reset");
    });

    test("get() follows the process time zone (TZ=Europe/Paris)", () => {
        const original = Intl.DateTimeFormat;
        Intl.DateTimeFormat = function () { return { resolvedOptions: () => ({ timeZone: "Europe/Paris" }) }; };
        try {
            DnsDefaults.reset();
            assert.equal(DnsDefaults.get().region, "FR");
        } finally { Intl.DateTimeFormat = original; }
    });

    test("get() falls back to global defaults if Intl throws", () => {
        const original = Intl.DateTimeFormat;
        Intl.DateTimeFormat = function () { throw new Error("no Intl"); };
        try {
            DnsDefaults.reset();
            assert.equal(DnsDefaults.get().region, DnsDefaults.GLOBAL_REGION);
        } finally { Intl.DateTimeFormat = original; }
    });
});

describe("manifest ↔ DNS_PROVIDERS consistency", () => {
    test("required providers are in host_permissions, optional ones ONLY in optional_host_permissions", async () => {
        const { readFile } = await import("node:fs/promises");
        const manifest = JSON.parse(await readFile(new URL("../../manifest.json", import.meta.url), "utf8"));
        const optional = manifest.optional_host_permissions ?? [];
        for (const p of Object.values(APP.DNS_PROVIDERS)) {
            const origin = `https://${p.host}/*`;
            if (p.optionalPermission) {
                assert.ok(optional.includes(origin), `${p.host} missing from optional_host_permissions`);
                assert.ok(!manifest.host_permissions.includes(origin), `${p.host} must not be a required permission`);
            } else {
                assert.ok(manifest.host_permissions.includes(origin), p.host);
            }
        }
    });

    test("no region default uses an optional-permission provider", () => {
        for (const rule of APP.DNS_REGION_DEFAULTS) {
            assert.ok(!APP.DNS_PROVIDERS[rule.first].optionalPermission, rule.region);
            assert.ok(!APP.DNS_PROVIDERS[rule.second].optionalPermission, rule.region);
        }
    });
});
