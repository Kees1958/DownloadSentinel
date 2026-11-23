#!/usr/bin/env node
"use strict";

// check-mv3.mjs  (both repos: tools/ — DownloadSentinel ≥ 3.6.0, 3P Matrix ≥ 5.0.9; 3P Matrix release zip: 3P-Matrix-tools/)
//
// v3.4.0 — Manifest V3 compliance check (hard gate in complete-check.mjs).
// Static: reads manifest.json and parses every .js/.html file of the
// extension folder; never runs extension code and needs no browser.
//
// The SAME file is used by DownloadSentinel and 3P Matrix (copy it
// unchanged): the extension folder comes from the command line. Since
// 3P Matrix 4.4.0 it needs no helper module (DS 3.5.0 imported repoPaths.mjs,
// which 3P Matrix's tools folder does not have).
//
// Usage:
//   node check-mv3.mjs [--ext|--extension <extension folder>] [--json]
//     --ext / --extension   the extension folder (the one holding manifest.json);
//                           default: the folder above this file's tools/ folder (the repo layout of
//                           both projects); 3P Matrix's release layout passes it explicitly
//     --json  print findings as JSON (for other tools); default: text
// Exit code: 0 = compliant, 1 = at least one finding, 2 = could not run.
//
// What it checks (rule ids appear in every finding):
//   Manifest
//     MV3-M1  manifest_version is 3
//     MV3-M2  background is a service worker only (no "scripts"/"page"/"persistent")
//     MV3-M3  no MV2 "browser_action" / "page_action" keys (use "action")
//     MV3-M4  no "webRequestBlocking"; host patterns live in host_permissions,
//             not in "permissions" / "optional_permissions"
//     MV3-M5  content_security_policy is the MV3 object form; extension_pages
//             only allows MV3 script sources (no 'unsafe-eval', no remote hosts)
//     MV3-M6  web_accessible_resources entries are MV3 objects
//             ({ resources: [...], matches | extension_ids: [...] })
//     MV3-M7  declarative_net_request rule_resources: id/enabled/path present,
//             path exists and parses as a JSON array
//   Code (every .js in the folder, every inline/linked script in .html)
//     MV3-C1  no eval(), new Function() / Function(), string setTimeout/setInterval
//     MV3-C2  no remotely hosted code: import / import() / importScripts() /
//             <script src> pointing at http(s):// or protocol-relative //
//     MV3-C3  no MV2-only APIs (chrome.extension.getURL, chrome.tabs.executeScript, …)
//     MV3-C4  no DOM-only globals (window, document, localStorage, …) in the
//             service worker or any module it imports — a service worker has none
//     MV3-C5  every .js file parses (a file the parser cannot read is unchecked)
//
// Does NOT check: Chrome Web Store policy (permissions justification,
// privacy), runtime behaviour, or code a page builds at run time — those
// need a reviewer or a browser.

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as espree from "espree";
import * as eslintScope from "eslint-scope";

// Repo layout (DownloadSentinel ≥ 3.6.0 and 3P Matrix ≥ 5.0.9, as uBlock Dynamic): tools/check-mv3.mjs → the repo
// root IS the extension (used only when no folder is given).
const DEFAULT_EXT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXT_FLAGS = new Set(["--ext", "--extension"]);

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG — every rule input in one place.
// ─────────────────────────────────────────────────────────────────────────────
const CONFIG = Object.freeze({
    REQUIRED_MANIFEST_VERSION: 3,
    ECMA_VERSION:              "latest",

    // Folders never scanned (build/test artefacts and the tools/ package — not shipped code; tools/ sits inside
    // the extension folder in the repo layout).
    EXCLUDED_DIR_NAMES: new Set(["node_modules", ".git", "coverage", ".jscpd", "tools"]),

    // MV2 manifest keys with an MV3 replacement.
    MV2_MANIFEST_KEYS: Object.freeze({
        browser_action: "action",
        page_action:    "action",
    }),
    MV2_BACKGROUND_KEYS: Object.freeze(["scripts", "page", "persistent"]),
    FORBIDDEN_PERMISSIONS: Object.freeze({
        webRequestBlocking: "use declarativeNetRequest (only policy-installed extensions may block in MV3)",
    }),
    PERMISSION_LISTS: Object.freeze(["permissions", "optional_permissions"]),
    HOST_PATTERN_RE: /:\/\/|^<all_urls>$/,

    // MV3 extension_pages CSP: only these script/object sources are allowed.
    CSP_SCRIPT_DIRECTIVES:  Object.freeze(["script-src", "script-src-elem", "object-src", "worker-src"]),
    CSP_ALLOWED_SOURCES:    new Set(["'self'", "'none'", "'wasm-unsafe-eval'", "'inline-speculation-rules'"]),
    CSP_LOCALHOST_SOURCE_RE: /^(https?:\/\/)?(localhost|127\.0\.0\.1)(:\d+)?$/,

    // Remote-code detection: a specifier counts as remote when it matches.
    REMOTE_SPECIFIER_RE: /^(https?:)?\/\//i,

    // String-evaluating timer APIs (MV3-C1, when the first argument is a string).
    STRING_TIMER_CALLEES: new Set(["setTimeout", "setInterval"]),

    // MV2-only API paths (MV3-C3) → MV3 replacement, matched on the member
    // chain, e.g. chrome.extension.getURL(...) or browser.extension.getURL.
    API_ROOTS: new Set(["chrome", "browser"]),
    MV2_APIS: Object.freeze({
        "extension.getURL":            "runtime.getURL",
        "extension.getBackgroundPage": "a service worker has no page — use messaging / chrome.storage",
        "runtime.getBackgroundPage":   "a service worker has no page — use messaging / chrome.storage",
        "extension.sendRequest":       "runtime.sendMessage",
        "extension.onRequest":         "runtime.onMessage",
        "extension.onRequestExternal": "runtime.onMessageExternal",
        "extension.sendMessage":       "runtime.sendMessage",
        "extension.onMessage":         "runtime.onMessage",
        "extension.connect":           "runtime.connect",
        "extension.onConnect":         "runtime.onConnect",
        "extension.lastError":         "runtime.lastError",
        "tabs.executeScript":          "scripting.executeScript",
        "tabs.insertCSS":              "scripting.insertCSS",
        "tabs.removeCSS":              "scripting.removeCSS",
        "tabs.getSelected":            "tabs.query",
        "tabs.getAllInWindow":         "tabs.query",
        "tabs.sendRequest":            "tabs.sendMessage",
        "browserAction":               "action",
        "pageAction":                  "action",
    }),

    // Globals a service worker does not have (MV3-C4).
    SW_FORBIDDEN_GLOBALS: new Set([
        "window", "document", "localStorage", "sessionStorage",
        "XMLHttpRequest", "alert", "confirm", "prompt",
        "DOMParser", "Image", "Audio", "HTMLElement", "FileReaderSync",
    ]),
});

// ─────────────────────────────────────────────────────────────────────────────
// Arguments
// ─────────────────────────────────────────────────────────────────────────────
function parseArgs(argv) {
    const args = { ext: null, json: false };
    for (let i = 0; i < argv.length; i++) {
        if (EXT_FLAGS.has(argv[i])) args.ext = argv[++i] || null;
        else if (argv[i] === "--json") args.json = true;
    }
    return args;
}

// ─────────────────────────────────────────────────────────────────────────────
// Findings — the one collection this script fills; reset per run.
// ─────────────────────────────────────────────────────────────────────────────
function createFindings(extRoot) {
    const list = [];
    return {
        add(rule, file, line, message) {
            list.push({ rule, file: file ? path.relative(extRoot, file) || "." : ".", line: line || 0, message });
        },
        list,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// File helpers
// ─────────────────────────────────────────────────────────────────────────────
function walk(dir, exts, out = []) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const abs = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            if (!CONFIG.EXCLUDED_DIR_NAMES.has(entry.name)) walk(abs, exts, out);
        } else if (entry.isFile() && exts.some(e => entry.name.endsWith(e))) {
            out.push(abs);
        }
    }
    return out;
}

function isFile(p) {
    try { return statSync(p).isFile(); } catch { return false; }
}

function parse(code) {
    const base = { ecmaVersion: CONFIG.ECMA_VERSION, loc: true, range: true };
    try { return espree.parse(code, { ...base, sourceType: "module" }); }
    catch { return espree.parse(code, { ...base, sourceType: "script" }); } // throws again if neither
}

// Depth-first walk over every AST node (parent links for context checks).
function visit(node, fn, parent = null) {
    if (!node || typeof node.type !== "string") return;
    fn(node, parent);
    for (const key of Object.keys(node)) {
        if (key === "parent" || key === "loc" || key === "range") continue;
        const child = node[key];
        if (Array.isArray(child)) child.forEach(c => visit(c, fn, node));
        else if (child && typeof child.type === "string") visit(child, fn, node);
    }
}

// "chrome.tabs.executeScript" for a MemberExpression chain, or null.
function memberPath(node) {
    const parts = [];
    let cur = node;
    while (cur && cur.type === "MemberExpression" && !cur.computed) {
        parts.unshift(cur.property.name);
        cur = cur.object;
    }
    if (cur && cur.type === "Identifier") { parts.unshift(cur.name); return parts.join("."); }
    return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Manifest rules
// ─────────────────────────────────────────────────────────────────────────────
function checkManifest(manifest, manifestPath, extRoot, findings) {
    const add = (rule, msg) => findings.add(rule, manifestPath, 0, msg);

    if (manifest.manifest_version !== CONFIG.REQUIRED_MANIFEST_VERSION) {
        add("MV3-M1", `manifest_version is ${JSON.stringify(manifest.manifest_version)}, must be ${CONFIG.REQUIRED_MANIFEST_VERSION}`);
    }

    const bg = manifest.background;
    if (bg) {
        for (const key of CONFIG.MV2_BACKGROUND_KEYS) {
            if (key in bg) add("MV3-M2", `background.${key} is MV2 — use background.service_worker`);
        }
        if ("service_worker" in bg && typeof bg.service_worker !== "string") {
            add("MV3-M2", "background.service_worker must be a single file path");
        }
    }

    for (const [key, replacement] of Object.entries(CONFIG.MV2_MANIFEST_KEYS)) {
        if (key in manifest) add("MV3-M3", `"${key}" is MV2 — use "${replacement}"`);
    }

    for (const listName of CONFIG.PERMISSION_LISTS) {
        for (const perm of manifest[listName] || []) {
            if (CONFIG.FORBIDDEN_PERMISSIONS[perm]) {
                add("MV3-M4", `"${perm}" in ${listName}: ${CONFIG.FORBIDDEN_PERMISSIONS[perm]}`);
            } else if (typeof perm === "string" && CONFIG.HOST_PATTERN_RE.test(perm)) {
                const target = listName === "permissions" ? "host_permissions" : "optional_host_permissions";
                add("MV3-M4", `host pattern "${perm}" in ${listName} — move it to ${target}`);
            }
        }
    }

    checkCsp(manifest.content_security_policy, add);
    checkWar(manifest.web_accessible_resources, add);
    checkDnr(manifest.declarative_net_request, extRoot, manifestPath, findings);
}

function checkCsp(csp, add) {
    if (csp === undefined) return;
    if (typeof csp === "string") {
        add("MV3-M5", "content_security_policy is an MV2 string — use { \"extension_pages\": \"…\" }");
        return;
    }
    const pages = csp && csp.extension_pages;
    if (typeof pages !== "string") return;
    for (const directive of pages.split(";").map(d => d.trim()).filter(Boolean)) {
        const [name, ...sources] = directive.split(/\s+/);
        if (!CONFIG.CSP_SCRIPT_DIRECTIVES.includes(name.toLowerCase())) continue;
        for (const src of sources) {
            if (!CONFIG.CSP_ALLOWED_SOURCES.has(src.toLowerCase()) && !CONFIG.CSP_LOCALHOST_SOURCE_RE.test(src)) {
                add("MV3-M5", `extension_pages ${name} allows ${src} — MV3 only permits 'self', 'wasm-unsafe-eval', 'none' and localhost`);
            }
        }
    }
}

function checkWar(war, add) {
    if (war === undefined) return;
    if (!Array.isArray(war)) { add("MV3-M6", "web_accessible_resources must be an array"); return; }
    war.forEach((entry, i) => {
        if (typeof entry === "string") {
            add("MV3-M6", `web_accessible_resources[${i}] is an MV2 string — use { resources, matches }`);
        } else if (!entry || !Array.isArray(entry.resources) || !(Array.isArray(entry.matches) || Array.isArray(entry.extension_ids))) {
            add("MV3-M6", `web_accessible_resources[${i}] needs "resources" plus "matches" or "extension_ids" arrays`);
        }
    });
}

function checkDnr(dnr, extRoot, manifestPath, findings) {
    const rules = dnr && dnr.rule_resources;
    if (!rules) return;
    if (!Array.isArray(rules)) { findings.add("MV3-M7", manifestPath, 0, "declarative_net_request.rule_resources must be an array"); return; }
    rules.forEach((res, i) => {
        const where = `rule_resources[${i}]${res && res.id ? ` (${res.id})` : ""}`;
        if (!res || typeof res.id !== "string" || typeof res.enabled !== "boolean" || typeof res.path !== "string") {
            findings.add("MV3-M7", manifestPath, 0, `${where} needs string id, boolean enabled and string path`);
            return;
        }
        const abs = path.join(extRoot, res.path);
        if (!isFile(abs)) { findings.add("MV3-M7", manifestPath, 0, `${where}: ${res.path} does not exist`); return; }
        try {
            if (!Array.isArray(JSON.parse(readFileSync(abs, "utf8")))) {
                findings.add("MV3-M7", abs, 0, `${where}: ruleset is not a JSON array`);
            }
        } catch (e) {
            findings.add("MV3-M7", abs, 0, `${where}: invalid JSON (${e.message})`);
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Code rules (one parsed file at a time)
// ─────────────────────────────────────────────────────────────────────────────
function checkCode(ast, file, findings) {
    const add = (rule, node, msg) => findings.add(rule, file, node.loc?.start?.line, msg);

    visit(ast, (node) => {
        // MV3-C1 — code from strings
        if (node.type === "CallExpression" || node.type === "NewExpression") {
            const callee = node.callee;
            const name = callee.type === "Identifier" ? callee.name
                : (callee.type === "MemberExpression" && !callee.computed ? callee.property.name : null);
            if (name === "eval" && node.type === "CallExpression") add("MV3-C1", node, "eval() — MV3 forbids evaluating strings as code");
            if (name === "Function" && callee.type === "Identifier") add("MV3-C1", node, "Function constructor — MV3 forbids evaluating strings as code");
            if (CONFIG.STRING_TIMER_CALLEES.has(name) && node.arguments[0]
                && (node.arguments[0].type === "Literal" && typeof node.arguments[0].value === "string"
                    || node.arguments[0].type === "TemplateLiteral")) {
                add("MV3-C1", node, `${name}() with a string — pass a function`);
            }
            // MV3-C2 — importScripts("https://…")
            if (name === "importScripts") {
                for (const arg of node.arguments) {
                    if (arg.type === "Literal" && typeof arg.value === "string" && CONFIG.REMOTE_SPECIFIER_RE.test(arg.value)) {
                        add("MV3-C2", node, `importScripts("${arg.value}") — remotely hosted code`);
                    }
                }
            }
        }
        // MV3-C2 — static/dynamic import and re-export of a remote URL
        if ((node.type === "ImportDeclaration" || node.type === "ImportExpression"
             || node.type === "ExportAllDeclaration" || node.type === "ExportNamedDeclaration")
            && node.source && node.source.type === "Literal"
            && typeof node.source.value === "string" && CONFIG.REMOTE_SPECIFIER_RE.test(node.source.value)) {
            add("MV3-C2", node, `import of "${node.source.value}" — remotely hosted code`);
        }
        // MV3-C3 — MV2-only APIs (report the longest chain only)
        if (node.type === "MemberExpression") {
            const full = memberPath(node);
            if (full) {
                const [root, ...rest] = full.split(".");
                if (CONFIG.API_ROOTS.has(root)) {
                    for (const [api, replacement] of Object.entries(CONFIG.MV2_APIS)) {
                        if (rest.join(".") === api) add("MV3-C3", node, `${root}.${api} is MV2-only — use ${replacement}`);
                    }
                }
            }
        }
    });
}

// MV3-C4 — free references to DOM-only globals (eslint-scope: a reference
// that resolves to no declaration in the file is a global). `typeof window`
// is a feature test, never an access, so it is allowed.
function checkServiceWorkerGlobals(ast, file, findings) {
    const scopes = eslintScope.analyze(ast, { ecmaVersion: 2022, sourceType: ast.sourceType });
    const global = scopes.globalScope;
    const typeofTargets = new Set();
    visit(ast, (node) => {
        if (node.type === "UnaryExpression" && node.operator === "typeof" && node.argument.type === "Identifier") {
            typeofTargets.add(node.argument);
        }
    });
    for (const ref of global.through) {
        const id = ref.identifier;
        if (CONFIG.SW_FORBIDDEN_GLOBALS.has(id.name) && !typeofTargets.has(id)) {
            findings.add("MV3-C4", file, id.loc?.start?.line, `"${id.name}" does not exist in a service worker`);
        }
    }
}

// The service worker and every local module it imports, statically.
function serviceWorkerGraph(entry, extRoot, astCache) {
    const seen = new Set();
    const queue = [entry];
    while (queue.length) {
        const file = queue.shift();
        if (seen.has(file) || !isFile(file)) continue;
        seen.add(file);
        const ast = astCache.get(file);
        if (!ast) continue;
        visit(ast, (node) => {
            const spec = (node.type === "ImportDeclaration" || node.type === "ExportAllDeclaration"
                          || node.type === "ExportNamedDeclaration")
                && node.source && typeof node.source.value === "string" ? node.source.value : null;
            if (spec && !CONFIG.REMOTE_SPECIFIER_RE.test(spec)) {
                const target = spec.startsWith("/") ? path.join(extRoot, spec) : path.resolve(path.dirname(file), spec);
                if (!seen.has(target)) queue.push(target);
            }
        });
    }
    return seen;
}

// MV3-C2 for HTML: <script src="https://…"> or protocol-relative.
function checkHtml(file, findings) {
    const html = readFileSync(file, "utf8");
    const re = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;
    let m;
    while ((m = re.exec(html)) !== null) {
        if (CONFIG.REMOTE_SPECIFIER_RE.test(m[1])) {
            const line = html.slice(0, m.index).split("\n").length;
            findings.add("MV3-C2", file, line, `<script src="${m[1]}"> — remotely hosted code`);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Run
// ─────────────────────────────────────────────────────────────────────────────
function run(extRoot) {
    const findings = createFindings(extRoot);
    const manifestPath = path.join(extRoot, "manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")); // let a broken manifest throw (exit 2)
    checkManifest(manifest, manifestPath, extRoot, findings);

    const astCache = new Map();
    for (const file of walk(extRoot, [".js", ".mjs"])) {
        try {
            const ast = parse(readFileSync(file, "utf8"));
            astCache.set(file, ast);
            checkCode(ast, file, findings);
        } catch (e) {
            findings.add("MV3-C5", file, e.lineNumber, `cannot be parsed, so it was not checked (${e.message})`);
        }
    }
    for (const file of walk(extRoot, [".html", ".htm"])) checkHtml(file, findings);

    const sw = manifest.background && manifest.background.service_worker;
    if (typeof sw === "string") {
        for (const file of serviceWorkerGraph(path.join(extRoot, sw), extRoot, astCache)) {
            const ast = astCache.get(file);
            if (ast) checkServiceWorkerGlobals(ast, file, findings);
        }
    }
    astCache.clear(); // release the parsed trees
    return findings.list;
}

function main() {
    const args = parseArgs(process.argv.slice(2));
    const extRoot = path.resolve(args.ext || DEFAULT_EXT_ROOT);
    if (!existsSync(path.join(extRoot, "manifest.json"))) {
        console.error(`check-mv3: no manifest.json in ${extRoot}`);
        process.exit(2);
    }
    let list;
    try { list = run(extRoot); }
    catch (e) { console.error(`check-mv3: could not run — ${e.message}`); process.exit(2); }

    if (args.json) {
        console.log(JSON.stringify({ extRoot, findings: list }, null, 2));
    } else if (list.length === 0) {
        console.log(`MV3 compliant: ${extRoot}`);
    } else {
        for (const f of list) console.log(`${f.rule}  ${f.file}${f.line ? `:${f.line}` : ""}  ${f.message}`);
        console.log(`${list.length} MV3 finding(s) in ${extRoot}`);
    }
    process.exit(list.length === 0 ? 0 : 1);
}

main();
