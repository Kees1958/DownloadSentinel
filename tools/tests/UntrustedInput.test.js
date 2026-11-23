"use strict";

// ── UntrustedInput.test.js ──────────────────────────────────────────────────
// v3.6.0 — from 3P Matrix 5.0.6 / 5.0.7 (C46 sender kinds, C51 seeded fuzz tests, C52 no addresses in logs).
// Everything random comes from ONE fixed seed, so a failure is reproducible run after run.
//   A. Download addresses / file names / MIME types are attacker-controlled: the parsers they pass through
//      (UrlUtils, FilenameAnalysis.classifyDownload) never throw and always return the promised type.
//   B. Message gate (util/MessageGate.js): for random senders and message types, only this extension's own
//      origin with a known MSG.* is ever allowed; senderLabel() never returns more than an origin.
//   C. Logs (C52): no console call in first-party code prints an address variable (url, href, …Url).
//   D. Extension pages carry the hardened content security policy (manifest.json).
// ─────────────────────────────────────────────────────────────────────────────

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { UrlUtils } from "../../util/UrlUtils.js";
import { FilenameAnalysis } from "../../util/FilenameAnalysis.js";
import { MessageGate } from "../../util/MessageGate.js";
import { MSG } from "../../util/MessageTypes.js";
import { repoPaths, NON_EXTENSION_DIR_NAMES } from "../repoPaths.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const { EXT_ROOT } = repoPaths(import.meta.url);
const SEED = 0x05e4717e;                 // fixed: every run sees the same inputs
const ITERATIONS = 3000;                 // per fuzz target
const MAX_PIECES = 8;                    // pieces glued into one generated string
const MAX_RANDOM_CHARS = 12;             // random characters per "free text" piece
const CHAR_CODE_MAX = 0x2fff;            // random characters drawn from U+0000 … U+2FFF (incl. controls, RTL marks)
const EXTENSION_ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
const URL_PIECES = Object.freeze(["http://", "https://", "ftp://", "javascript:", "data:", "blob:", "blob:null/", "//",
    "xn--", ".", "..", ":", "@", "[", "]", "::1", "127.0.0.1", "0x7f.1", "%2e", "%00", "localhost", "a.b.c", "co.uk",
    "例え.jp", "\u0000", "‮", " ", "#", "?", "=", "&", "/", "\\", ".exe", ".zip", ".pdf.exe", "file", "download"]);
const NAME_PIECES = Object.freeze(["invoice", ".", "..", ".exe", ".scr", ".pdf", ".zip", ".tar.gz", " ", "‮", "​",
    "/", "\\", "~", "%20", "\u0000", "CON", "a".repeat(300)]);
const MIME_PIECES = Object.freeze(["application/", "octet-stream", "x-msdownload", "zip", "text/", "html", ";", " charset=",
    "utf-8", "", "*/*", "\u0000", "APPLICATION/OCTET-STREAM"]);
const SENDER_URL_PIECES = Object.freeze([EXTENSION_ORIGIN, "chrome-extension://other/", "https://evil.example/",
    "pages/warning/WarningPage.html", "?downloadId=1", "#x", "", "null", "about:blank", "file:///"]);
const LOG_SCAN = Object.freeze(["background.js", "util", "protection", "pages"]);   // first-party runtime code
const GENERATED_SUFFIX = ".default.js";                                            // generated data, not code
const LOG_CALL_RE = /console\.(?:log|info|warn|error|debug)\(([^;]*)\)/g;
const ADDRESS_ARG_RE = /(?:\.url\b|\.href\b|\b[a-z]*Url\b|\burl\b|location\b)/;
const REQUIRED_CSP_DIRECTIVES = Object.freeze(["script-src 'self'", "object-src 'none'", "base-uri 'none'", "form-action 'none'"]);

// ── Seeded generator (mulberry32) ────────────────────────────────────────────
function rng(seed) {
    let a = seed >>> 0;
    return () => {
        a = (a + 0x6d2b79f5) >>> 0;
        let t = a;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}
const rand = rng(SEED);
const int = (n) => Math.floor(rand() * n);
const pick = (list) => list[int(list.length)];
function freeText() {
    let s = "";
    for (let i = int(MAX_RANDOM_CHARS); i > 0; i -= 1) s += String.fromCharCode(int(CHAR_CODE_MAX));
    return s;
}
function glue(pieces) {
    let s = "";
    for (let i = int(MAX_PIECES) + 1; i > 0; i -= 1) s += rand() < 0.75 ? pick(pieces) : freeText();
    return s;
}
// A non-string now and then: the chrome.* fields are typed, but a defensive parser must not care.
function maybeNotString(s) {
    const r = rand();
    if (r < 0.03) return null;
    if (r < 0.06) return undefined;
    return s;
}

describe("A. download inputs never break the parsers (seeded fuzz, v3.6.0)", () => {
    test(`UrlUtils.getHostname / cleanUrl / getTld / getRegisteredDomain — ${ITERATIONS} random addresses`, () => {
        for (let i = 0; i < ITERATIONS; i += 1) {
            const url = maybeNotString(glue(URL_PIECES));
            const host = UrlUtils.getHostname(url);
            assert.ok(host === null || typeof host === "string", `getHostname(${JSON.stringify(url)})`);
            const clean = UrlUtils.cleanUrl(url);
            assert.equal(typeof clean, "string", `cleanUrl(${JSON.stringify(url)})`);
            const tld = UrlUtils.getTld(host);
            assert.ok(tld === null || typeof tld === "string");
            const reg = UrlUtils.getRegisteredDomain(host);
            assert.ok(reg === null || typeof reg === "string", `getRegisteredDomain(${JSON.stringify(host)})`);
        }
    });
    test(`FilenameAnalysis.classifyDownload — ${ITERATIONS} random (address, file name, MIME) triples`, () => {
        for (let i = 0; i < ITERATIONS; i += 1) {
            const url = glue(URL_PIECES);
            const raw = maybeNotString(glue(URL_PIECES));
            const name = maybeNotString(glue(NAME_PIECES));
            const mime = maybeNotString(glue(MIME_PIECES));
            const c = FilenameAnalysis.classifyDownload(url, raw, name, mime);
            assert.ok(c === null || (typeof c === "object" && !Array.isArray(c)),
                JSON.stringify({ url, raw, name, mime }));
        }
    });
});

describe("B. message gate (util/MessageGate.js, v3.6.0)", () => {
    const types = Object.values(MSG);
    test("own extension page + known type → allowed", () => {
        const kind = MessageGate.senderKind({ url: `${EXTENSION_ORIGIN}pages/popup/PopupPage.html` }, EXTENSION_ORIGIN);
        assert.equal(kind, MessageGate.SENDER_KIND.EXTENSION_PAGE);
        for (const t of types) assert.equal(MessageGate.isMessageAllowed(t, kind), true, t);
    });
    test("a content script (same extension id, but a web page's URL and a tab) → refused everything", () => {
        const kind = MessageGate.senderKind({ id: "x", url: "https://evil.example/", tab: { id: 7 } }, EXTENSION_ORIGIN);
        assert.equal(kind, null);
        for (const t of types) assert.equal(MessageGate.isMessageAllowed(t, kind), false, t);
    });
    test("missing sender / URL / origin → no kind", () => {
        assert.equal(MessageGate.senderKind(null, EXTENSION_ORIGIN), null);
        assert.equal(MessageGate.senderKind({}, EXTENSION_ORIGIN), null);
        assert.equal(MessageGate.senderKind({ url: EXTENSION_ORIGIN }, ""), null);
    });
    test(`${ITERATIONS} random senders and types: allowed only for the own origin with a known type`, () => {
        for (let i = 0; i < ITERATIONS; i += 1) {
            const sender = rand() < 0.05 ? maybeNotString(null) : { url: maybeNotString(glue(SENDER_URL_PIECES)) };
            const type = rand() < 0.5 ? pick(types) : maybeNotString(glue(types));
            const allowed = MessageGate.isMessageAllowed(type, MessageGate.senderKind(sender, EXTENSION_ORIGIN));
            const expected = !!sender && typeof sender.url === "string" && sender.url.startsWith(EXTENSION_ORIGIN) && types.includes(type);
            assert.equal(allowed, expected, JSON.stringify({ sender, type }));
        }
    });
    test("senderLabel names the origin only — never a path, query or fragment", () => {
        assert.equal(MessageGate.senderLabel({ url: "https://bank.example/reset?token=SECRET#x" }), "https://bank.example");
        assert.equal(MessageGate.senderLabel({ url: `${EXTENSION_ORIGIN}pages/warning/WarningPage.html?downloadId=4` }),
            EXTENSION_ORIGIN.slice(0, -1));
        assert.equal(typeof MessageGate.senderLabel(null), "string");
        for (let i = 0; i < ITERATIONS; i += 1) {
            const label = MessageGate.senderLabel({ url: glue(SENDER_URL_PIECES) });
            assert.ok(!/[?#]/.test(label), label);
        }
    });
});

describe("C. no addresses in logs (3P Matrix C52, v3.6.0)", () => {
    function jsFiles(rel) {
        const abs = path.join(EXT_ROOT, rel);
        if (rel.endsWith(".js")) return [abs];
        return readdirSync(abs, { withFileTypes: true }).flatMap((e) => {
            if (e.isDirectory()) return NON_EXTENSION_DIR_NAMES.has(e.name) ? [] : jsFiles(path.join(rel, e.name));
            return e.name.endsWith(".js") && !e.name.endsWith(GENERATED_SUFFIX) ? [path.join(abs, e.name)] : [];
        });
    }
    test("no console call prints an address variable", () => {
        const hits = [];
        for (const file of LOG_SCAN.flatMap(jsFiles)) {
            for (const m of readFileSync(file, "utf8").matchAll(LOG_CALL_RE)) {
                if (ADDRESS_ARG_RE.test(m[1].replace(/(["'`])(?:\\.|(?!\1).)*\1/g, ""))) hits.push(`${path.relative(EXT_ROOT, file)}: ${m[0]}`);
            }
        }
        assert.deepEqual(hits, []);
    });
});

describe("D. extension-page content security policy (3P Matrix 5.0.6, v3.6.0)", () => {
    test("manifest.json declares the hardened extension_pages policy", () => {
        const manifest = JSON.parse(readFileSync(path.join(EXT_ROOT, "manifest.json"), "utf8"));
        const csp = manifest.content_security_policy?.extension_pages || "";
        for (const d of REQUIRED_CSP_DIRECTIVES) assert.ok(csp.includes(d), `missing "${d}" in ${JSON.stringify(csp)}`);
    });
});
