"use strict";

// ── DnsPermissions.test.js ──────────────────────────────────────────────────
// Covers util/DnsPermissions.js (v3.3.1): optional host permission for
// DNS4EU — acquire on request, release when no slot uses it, never throw.
// ─────────────────────────────────────────────────────────────────────────────

import { test, describe, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { DnsPermissions } from "../../util/DnsPermissions.js";
import { installChromeMock, uninstallChromeMock, setGrantedOrigins } from "./helpers/chromeMock.js";

const DNS4EU_ORIGIN = "https://protective.joindns4.eu/*";

describe("DnsPermissions", () => {
    beforeEach(() => installChromeMock());
    after(() => uninstallChromeMock());

    test("only dns4eu and cleanbrowsing need a runtime permission", () => {
        assert.equal(DnsPermissions.needsPermission("dns4eu"), true);
        assert.equal(DnsPermissions.needsPermission("cleanbrowsing"), true);
        for (const id of ["quad9", "cloudflare", "controld", "none", "bogus", undefined]) {
            assert.equal(DnsPermissions.needsPermission(id), false, String(id));
        }
        assert.equal(DnsPermissions.originFor("dns4eu"), DNS4EU_ORIGIN);
        assert.equal(DnsPermissions.originFor("bogus"), null);
    });

    test("has(): non-optional ids are always granted; dns4eu follows chrome.permissions", async () => {
        assert.equal(await DnsPermissions.has("quad9"), true);
        assert.equal(await DnsPermissions.has("dns4eu"), false);
        setGrantedOrigins([DNS4EU_ORIGIN]);
        assert.equal(await DnsPermissions.has("dns4eu"), true);
    });

    test("request(): resolves false when declined, true when granted, true for non-optional", async () => {
        assert.equal(await DnsPermissions.request("dns4eu"), false);
        setGrantedOrigins([DNS4EU_ORIGIN]);
        assert.equal(await DnsPermissions.request("dns4eu"), true);
        assert.equal(await DnsPermissions.request("cloudflare"), true);
    });

    test("releaseUnused(): removes dns4eu when no slot uses it, keeps it when one does", async () => {
        setGrantedOrigins([DNS4EU_ORIGIN]);
        await DnsPermissions.releaseUnused(["dns4eu", "controld"]);
        assert.equal(await DnsPermissions.has("dns4eu"), true);
        await DnsPermissions.releaseUnused(["controld", "cloudflare"]);
        assert.equal(await DnsPermissions.has("dns4eu"), false);
    });

    test("no chrome.permissions available → never throws, reports not granted", async () => {
        uninstallChromeMock();
        assert.equal(await DnsPermissions.has("dns4eu"), false);
        assert.equal(await DnsPermissions.request("dns4eu"), false);
        await DnsPermissions.releaseUnused([]); // must not throw
    });
});
