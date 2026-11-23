"use strict";

// ── DnsThreatProtection.test.js ─────────────────────────────────────────────
// Covers protection/DnsThreatProtection.js — the generalized (v3.0.6)
// successor to the old single-provider Quad9Protection.js. Hand-builds
// binary DNS response fixtures using LOCAL encode helpers, independent of
// the module's own encoder, so a bug in the module's encoder can't also
// hide itself from these tests by round-tripping through itself.
//
// Covers all three providers' blockStyles:
//   quad9      — "nxdomain-no-authority" (NXDOMAIN + zero Authority records)
//   cloudflare — "zero-ip" (answers with 0.0.0.0 / all-zero AAAA)
//   controld   — "zero-ip" (same blockStyle as cloudflare, different host)
//   dns4eu     — "blockpage-ip" (answers its block-page IP; v3.3.1)
//   cleanbrowsing — "rpz-soa" (no answer + policy-zone SOA in Authority; v3.3.1)
// ─────────────────────────────────────────────────────────────────────────────

import { test, describe, mock, before, after } from "node:test";
import assert from "node:assert/strict";
import { DnsThreatProtection } from "../../protection/DnsThreatProtection.js";
import { APP } from "../../util/AppConstants.js";
import { installChromeMock, uninstallChromeMock, setGrantedOrigins } from "./helpers/chromeMock.js";

// ── Local binary DNS fixture builders (independent of the module's own) ────

function u16(n) { return [(n >> 8) & 0xff, n & 0xff]; }

function encodeLabels(host) {
    const bytes = [];
    for (const label of host.split(".")) {
        const b = new TextEncoder().encode(label);
        bytes.push(b.length, ...b);
    }
    bytes.push(0);
    return bytes;
}

// Builds a full DNS response message.
//   rcode          - 0 (NOERROR) or 3 (NXDOMAIN)
//   authorityCount - NSCOUNT in the header
//   answers        - [{ type: 1|28|5, rdata: number[] }] — A/AAAA/CNAME records
//   authorities    - [{ owner, mname, rname }] — real SOA records appended to
//                    the Authority section (v3.3.1); when given, NSCOUNT is
//                    authorityCount + authorities.length
function buildResponse({ rcode = 0, authorityCount = 0, answers = [], qname = "example.com", authorities = [] }) {
    const header = [
        0, 0,                       // ID
        0x81, rcode & 0x0f,         // flags: QR+RD+RA, rcode in low nibble
        ...u16(1),                  // QDCOUNT
        ...u16(answers.length),     // ANCOUNT
        ...u16(authorityCount + authorities.length), // NSCOUNT
        ...u16(0),                  // ARCOUNT
    ];
    const question = [...encodeLabels(qname), ...u16(1), ...u16(1)]; // QTYPE A, QCLASS IN

    const answerBytes = [];
    for (const a of answers) {
        answerBytes.push(
            ...encodeLabels(qname),     // NAME (uncompressed, same as question — simplest valid form)
            ...u16(a.type),
            ...u16(1),                   // CLASS IN
            0, 0, 0, 60,                  // TTL
            ...u16(a.rdata.length),
            ...a.rdata
        );
    }

    const authorityBytes = [];
    for (const soa of authorities) {
        const rdata = [...encodeLabels(soa.mname), ...encodeLabels(soa.rname),
                       0, 0, 0, 1,  0, 0, 0x1c, 0x20,  0, 0, 3, 0x84,  0, 0x12, 0x75, 0,  0, 1, 0x51, 0x80]; // serial/refresh/retry/expire/minimum
        authorityBytes.push(...encodeLabels(soa.owner), ...u16(6), ...u16(1), 0, 0, 0x0e, 0x10, ...u16(rdata.length), ...rdata);
    }

    return new Uint8Array([...header, ...question, ...answerBytes, ...authorityBytes]).buffer;
}

function aRdata(ip) { return ip.split(".").map(Number); }
function zeroAaaaRdata() { return new Array(16).fill(0); }
function cnameRdata(target) { return encodeLabels(target); }

function fetchReturning(buffer, { ok = true, status = 200 } = {}) {
    return mock.fn(async () => ({
        ok, status,
        arrayBuffer: async () => buffer
    }));
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("DnsThreatProtection.check — disabled/invalid provider", () => {
    test("APP.DNS_NONE returns SKIPPED without a network call", async () => {
        const originalFetch = global.fetch;
        global.fetch = mock.fn();
        try {
            const r = await DnsThreatProtection.check("none", "example.com");
            assert.equal(r.status, "SKIPPED");
            assert.equal(r.score, 0);
            assert.equal(global.fetch.mock.callCount(), 0);
        } finally { global.fetch = originalFetch; }
    });

    test("an unrecognised provider id also returns SKIPPED, never throws", async () => {
        const r = await DnsThreatProtection.check("not-a-real-provider", "example.com");
        assert.equal(r.status, "SKIPPED");
    });
});

describe("DnsThreatProtection.check — quad9 (nxdomain-no-authority blockStyle)", () => {
    test("NXDOMAIN + zero Authority records → BLOCKED", async () => {
        const buf = buildResponse({ rcode: 3, authorityCount: 0, answers: [] });
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(buf);
        try {
            const r = await DnsThreatProtection.check("quad9", "malware.example");
            assert.equal(r.status, "BLOCKED");
            assert.equal(r.score, -100);
            assert.equal(r.provider, "quad9");
            assert.ok(r.label.includes("Quad9"));
        } finally { global.fetch = originalFetch; }
    });

    test("NXDOMAIN + Authority records present → UNKNOWN/NXDOMAIN (genuinely doesn't exist, not blocked)", async () => {
        const buf = buildResponse({ rcode: 3, authorityCount: 1, answers: [] });
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(buf);
        try {
            const r = await DnsThreatProtection.check("quad9", "doesnotexist.example");
            assert.equal(r.status, "UNKNOWN");
            assert.equal(r.reasonCode, "NXDOMAIN");
        } finally { global.fetch = originalFetch; }
    });

    test("A record answer → ALLOWED", async () => {
        const buf = buildResponse({ answers: [{ type: 1, rdata: aRdata("93.184.216.34") }] });
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(buf);
        try {
            const r = await DnsThreatProtection.check("quad9", "example.com");
            assert.equal(r.status, "ALLOWED");
            assert.deepEqual(r.answers, ["93.184.216.34"]);
        } finally { global.fetch = originalFetch; }
    });

    test("CNAME-only answer → ALLOWED with the alias name decoded", async () => {
        const buf = buildResponse({ answers: [{ type: 5, rdata: cnameRdata("alias.example.net") }] });
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(buf);
        try {
            const r = await DnsThreatProtection.check("quad9", "example.com");
            assert.equal(r.status, "ALLOWED");
            assert.deepEqual(r.answers, ["alias.example.net"]);
        } finally { global.fetch = originalFetch; }
    });

    test("no answer records at all → UNKNOWN/NO_ANSWER", async () => {
        const buf = buildResponse({ answers: [] });
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(buf);
        try {
            const r = await DnsThreatProtection.check("quad9", "example.com");
            assert.equal(r.status, "UNKNOWN");
            assert.equal(r.reasonCode, "NO_ANSWER");
        } finally { global.fetch = originalFetch; }
    });

    test("non-OK HTTP status → UNKNOWN/REQUEST_FAILED", async () => {
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(new ArrayBuffer(0), { ok: false, status: 500 });
        try {
            const r = await DnsThreatProtection.check("quad9", "example.com");
            assert.equal(r.status, "UNKNOWN");
            assert.equal(r.reasonCode, "REQUEST_FAILED");
        } finally { global.fetch = originalFetch; }
    });

    test("malformed response body → UNKNOWN/REQUEST_FAILED, never throws", async () => {
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(new ArrayBuffer(2)); // shorter than a DNS header
        try {
            const r = await DnsThreatProtection.check("quad9", "example.com");
            assert.equal(r.status, "UNKNOWN");
            assert.equal(r.reasonCode, "REQUEST_FAILED");
        } finally { global.fetch = originalFetch; }
    });

    test("AbortError (timeout) → UNKNOWN/TIMEOUT", async () => {
        const originalFetch = global.fetch;
        global.fetch = mock.fn(async () => {
            const err = new Error("aborted");
            err.name = "AbortError";
            throw err;
        });
        try {
            const r = await DnsThreatProtection.check("quad9", "example.com");
            assert.equal(r.status, "UNKNOWN");
            assert.equal(r.reasonCode, "TIMEOUT");
        } finally { global.fetch = originalFetch; }
    });

    test("generic network error → UNKNOWN/ERROR, and the real message is surfaced in the label", async () => {
        const originalFetch = global.fetch;
        global.fetch = mock.fn(async () => { throw new TypeError("Failed to fetch"); });
        try {
            const r = await DnsThreatProtection.check("quad9", "example.com");
            assert.equal(r.status, "UNKNOWN");
            assert.equal(r.reasonCode, "ERROR");
            assert.match(r.label, /Failed to fetch/);
        } finally { global.fetch = originalFetch; }
    });
});

describe("DnsThreatProtection.check — cloudflare / controld (zero-ip blockStyle)", () => {
    test("cloudflare: answer is 0.0.0.0 (A) → BLOCKED", async () => {
        const buf = buildResponse({ answers: [{ type: 1, rdata: aRdata("0.0.0.0") }] });
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(buf);
        try {
            const r = await DnsThreatProtection.check("cloudflare", "malware.example");
            assert.equal(r.status, "BLOCKED");
            assert.equal(r.provider, "cloudflare");
            assert.ok(r.label.includes("Cloudflare"));
        } finally { global.fetch = originalFetch; }
    });

    test("controld: answer is all-zero AAAA (::) → BLOCKED", async () => {
        const buf = buildResponse({ answers: [{ type: 28, rdata: zeroAaaaRdata() }] });
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(buf);
        try {
            const r = await DnsThreatProtection.check("controld", "malware.example");
            assert.equal(r.status, "BLOCKED");
            assert.equal(r.provider, "controld");
        } finally { global.fetch = originalFetch; }
    });

    test("controld: a normal, non-zero A answer → ALLOWED, not mistaken for a block", async () => {
        const buf = buildResponse({ answers: [{ type: 1, rdata: aRdata("93.184.216.34") }] });
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(buf);
        try {
            const r = await DnsThreatProtection.check("controld", "example.com");
            assert.equal(r.status, "ALLOWED");
        } finally { global.fetch = originalFetch; }
    });

    test("cloudflare: NXDOMAIN with this blockStyle just means UNKNOWN/NXDOMAIN, never BLOCKED (NXDOMAIN isn't how zero-ip resolvers signal a block)", async () => {
        const buf = buildResponse({ rcode: 3, authorityCount: 1, answers: [] });
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(buf);
        try {
            const r = await DnsThreatProtection.check("cloudflare", "doesnotexist.example");
            assert.equal(r.status, "UNKNOWN");
            assert.equal(r.reasonCode, "NXDOMAIN");
        } finally { global.fetch = originalFetch; }
    });
});

describe("DnsThreatProtection.check — dns4eu (blockpage-ip blockStyle, v3.3.1)", () => {
    // DNS4EU is an optional-permission provider: grant it for this suite (INIT), release after.
    before(() => { installChromeMock(); setGrantedOrigins(["https://protective.joindns4.eu/*"]); });
    after(() => uninstallChromeMock());
    async function runWith(buf, host = "malware.example") {
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(buf);
        try { return await DnsThreatProtection.check("dns4eu", host); }
        finally { global.fetch = originalFetch; }
    }

    test("answer is the DNS4EU block-page IP → BLOCKED", async () => {
        const blockIp = APP.DNS_PROVIDERS.dns4eu.blockPageIps[0];
        const r = await runWith(buildResponse({ answers: [{ type: 1, rdata: aRdata(blockIp) }] }));
        assert.equal(r.status, "BLOCKED");
        assert.equal(r.provider, "dns4eu");
        assert.ok(r.label.includes("DNS4EU"));
    });

    test("answer is 0.0.0.0 → BLOCKED (sinkhole also honoured for this style)", async () => {
        const r = await runWith(buildResponse({ answers: [{ type: 1, rdata: aRdata("0.0.0.0") }] }));
        assert.equal(r.status, "BLOCKED");
    });

    test("normal A answer → ALLOWED", async () => {
        const r = await runWith(buildResponse({ answers: [{ type: 1, rdata: aRdata("93.184.216.34") }] }), "example.com");
        assert.equal(r.status, "ALLOWED");
    });

    test("NXDOMAIN → UNKNOWN/NXDOMAIN, never BLOCKED", async () => {
        const r = await runWith(buildResponse({ rcode: 3, authorityCount: 1 }), "doesnotexist.example");
        assert.equal(r.status, "UNKNOWN");
        assert.equal(r.reasonCode, "NXDOMAIN");
    });

    test("a zero-ip provider does NOT treat DNS4EU's block-page IP as a block", async () => {
        const blockIp = APP.DNS_PROVIDERS.dns4eu.blockPageIps[0];
        const buf = buildResponse({ answers: [{ type: 1, rdata: aRdata(blockIp) }] });
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(buf);
        try {
            const r = await DnsThreatProtection.check("cloudflare", "example.com");
            assert.equal(r.status, "ALLOWED");
        } finally { global.fetch = originalFetch; }
    });

    test("queries the DNS4EU Protective DoH endpoint", async () => {
        let capturedUrl = null;
        const buf = buildResponse({ answers: [{ type: 1, rdata: aRdata("1.2.3.4") }] });
        const originalFetch = global.fetch;
        global.fetch = mock.fn(async (url) => { capturedUrl = url; return { ok: true, status: 200, arrayBuffer: async () => buf }; });
        try {
            await DnsThreatProtection.check("dns4eu", "example.com");
            assert.ok(capturedUrl.startsWith("https://protective.joindns4.eu/dns-query?dns="));
        } finally { global.fetch = originalFetch; }
    });
});

describe("DnsThreatProtection.check — cleanbrowsing (rpz-soa blockStyle, v3.3.1)", () => {
    // Optional-permission provider: grant for this suite (INIT), release after.
    before(() => { installChromeMock(); setGrantedOrigins(["https://doh.cleanbrowsing.org/*"]); });
    after(() => uninstallChromeMock());

    async function runWith(buf, host) {
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(buf);
        try { return await DnsThreatProtection.check("cleanbrowsing", host); }
        finally { global.fetch = originalFetch; }
    }

    // Shapes observed live against 185.228.168.9 on 2026-10-24.
    test("policy-zone SOA (cleanbrowsing.rpz.noc.org), no answer → BLOCKED", async () => {
        const buf = buildResponse({ rcode: 3, qname: "malware.wicar.org",
            authorities: [{ owner: "malware.wicar.org", mname: "cleanbrowsing.rpz.noc.org", rname: "accesspolicy.rpz.noc.org" }] });
        const r = await runWith(buf, "malware.wicar.org");
        assert.equal(r.status, "BLOCKED");
        assert.equal(r.provider, "cleanbrowsing");
    });

    test("same block but NOERROR/NODATA rcode → still BLOCKED (signal is the SOA, not the rcode)", async () => {
        const buf = buildResponse({ rcode: 0, qname: "malware.wicar.org",
            authorities: [{ owner: "malware.wicar.org", mname: "CleanBrowsing.RPZ.noc.org", rname: "accesspolicy.rpz.noc.org" }] });
        assert.equal((await runWith(buf, "malware.wicar.org")).status, "BLOCKED");
    });

    test("registry SOA (com. / a.gtld-servers.net) → UNKNOWN/NXDOMAIN, never BLOCKED", async () => {
        const buf = buildResponse({ rcode: 3, qname: "thisdoesnotexist-12345.com",
            authorities: [{ owner: "com", mname: "a.gtld-servers.net", rname: "nstld.verisign-grs.com" }] });
        const r = await runWith(buf, "thisdoesnotexist-12345.com");
        assert.equal(r.status, "UNKNOWN");
        assert.equal(r.reasonCode, "NXDOMAIN");
    });

    test("truncated Authority section → answers still used, never BLOCKED", async () => {
        // NSCOUNT claims 1 record but none follows — must not throw away the A answer.
        const buf = buildResponse({ authorityCount: 1, answers: [{ type: 1, rdata: aRdata("1.2.3.4") }] });
        assert.equal((await runWith(buf, "example.com")).status, "ALLOWED");
    });

    test("look-alike MNAME without a label boundary (evilrpz.noc.org) → not BLOCKED", async () => {
        const buf = buildResponse({ rcode: 3,
            authorities: [{ owner: "example.org", mname: "evilrpz.noc.org", rname: "x.example" }] });
        assert.equal((await runWith(buf, "example.org")).status, "UNKNOWN");
    });

    test("normal A answer → ALLOWED", async () => {
        const buf = buildResponse({ answers: [{ type: 1, rdata: aRdata("104.20.23.154") }] });
        assert.equal((await runWith(buf, "example.com")).status, "ALLOWED");
    });

    test("queries the Security Filter DoH endpoint", async () => {
        let capturedUrl = null;
        const buf = buildResponse({ answers: [{ type: 1, rdata: aRdata("1.2.3.4") }] });
        const originalFetch = global.fetch;
        global.fetch = mock.fn(async (url) => { capturedUrl = url; return { ok: true, status: 200, arrayBuffer: async () => buf }; });
        try {
            await DnsThreatProtection.check("cleanbrowsing", "example.com");
            assert.ok(capturedUrl.startsWith("https://doh.cleanbrowsing.org/doh/security-filter/?dns="));
        } finally { global.fetch = originalFetch; }
    });

    test("other blockStyles ignore an RPZ SOA (quad9 with authority present → NXDOMAIN, not BLOCKED)", async () => {
        const buf = buildResponse({ rcode: 3,
            authorities: [{ owner: "x.example", mname: "cleanbrowsing.rpz.noc.org", rname: "a.rpz.noc.org" }] });
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(buf);
        try {
            const r = await DnsThreatProtection.check("quad9", "x.example");
            assert.equal(r.reasonCode, "NXDOMAIN");
        } finally { global.fetch = originalFetch; }
    });
});

describe("DnsThreatProtection.check — optional permission guard (v3.3.1)", () => {
    before(() => installChromeMock());
    after(() => uninstallChromeMock());

    test("dns4eu without its permission → UNKNOWN/PERMISSION_MISSING and NO network call", async () => {
        setGrantedOrigins([]);
        const originalFetch = global.fetch;
        global.fetch = mock.fn();
        try {
            const r = await DnsThreatProtection.check("dns4eu", "example.com");
            assert.equal(r.status, "UNKNOWN");
            assert.equal(r.reasonCode, DnsThreatProtection.UNKNOWN_REASON.PERMISSION_MISSING);
            assert.equal(global.fetch.mock.callCount(), 0);
        } finally { global.fetch = originalFetch; }
    });

    test("non-optional providers (cloudflare) never need a runtime grant", async () => {
        setGrantedOrigins([]);
        const buf = buildResponse({ answers: [{ type: 1, rdata: aRdata("1.2.3.4") }] });
        const originalFetch = global.fetch;
        global.fetch = fetchReturning(buf);
        try {
            const r = await DnsThreatProtection.check("cloudflare", "example.com");
            assert.equal(r.status, "ALLOWED");
        } finally { global.fetch = originalFetch; }
    });
});

describe("DnsThreatProtection.check — outgoing request shape", () => {
    test("builds a wire-format query (QDCOUNT=1, correct QNAME labels) in the ?dns= param", async () => {
        let capturedUrl = null;
        const buf = buildResponse({ answers: [{ type: 1, rdata: aRdata("1.2.3.4") }] });
        const originalFetch = global.fetch;
        global.fetch = mock.fn(async (url) => {
            capturedUrl = url;
            return { ok: true, status: 200, arrayBuffer: async () => buf };
        });
        try {
            await DnsThreatProtection.check("quad9", "example.com");
            assert.ok(capturedUrl.startsWith("https://dns.quad9.net/dns-query?dns="));
            const b64 = capturedUrl.split("dns=")[1];
            const bin = Buffer.from(b64.replace(/-/g, "+").replace(/_/g, "/"), "base64");
            const view = new DataView(bin.buffer, bin.byteOffset, bin.byteLength);
            assert.equal(view.getUint16(4), 1); // QDCOUNT
            // QNAME starts right after the 12-byte header: 7"example"3"com"0
            assert.equal(view.getUint8(12), 7);
            assert.equal(bin.slice(13, 20).toString("ascii"), "example");
        } finally { global.fetch = originalFetch; }
    });

    test("a different provider id hits that provider's own host", async () => {
        let capturedUrl = null;
        const buf = buildResponse({ answers: [{ type: 1, rdata: aRdata("1.2.3.4") }] });
        const originalFetch = global.fetch;
        global.fetch = mock.fn(async (url) => { capturedUrl = url; return { ok: true, status: 200, arrayBuffer: async () => buf }; });
        try {
            await DnsThreatProtection.check("controld", "example.com");
            assert.ok(capturedUrl.startsWith("https://freedns.controld.com/p1?dns="));
        } finally { global.fetch = originalFetch; }
    });
});
