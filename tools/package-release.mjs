#!/usr/bin/env node
"use strict";

// tools/package-release.mjs
//
// v3.6.0 (from 3P Matrix 5.0.7: package-release.mjs + check-permission-additions.mjs) — THE declaration of what
// each of the three release zips holds, the guard that enforces it BEFORE anything is zipped, and the least-
// privilege check on manifest permissions. Since 3.6.0 the repo holds the unpacked source (tools/repoPaths.mjs),
// so the zips are cut from the repo tree instead of being three sibling folders.
//
//   EXTENSION  runtime files only (RUNTIME_EXTENSIONS) — the repo root minus tools/, the project documents
//              (DOC_FILES) and VCS housekeeping (REPO_ONLY_FILES). No changelog, README or dev config: an edited
//              non-runtime file inside the package only costs a Chrome Web Store review.
//   DOCS       the project documents (DOC_FILES), under DOCS/ (same shape as the 3.5.x DOCS zip).
//   TOOLS      the tools/ package (node_modules and test artefacts excluded), flat (same shape as before).
// Version congruence: manifest.json "version" = tools/package.json "version" = CHANGELOG.md's top "## x.y.z" heading,
// and CHANGELOG_HISTORY.md has a "## x.y.z" entry.
// Permissions (C36, least privilege): the manifest may not gain a permission the previous release (release-state.json,
// written by --record) did not ship, unless APPROVED_ADDITIONS lists it with its reason. Removals are reported only.
//
// Usage (from tools/):
//   node package-release.mjs                  guard only (also complete-check step 18)
//   node package-release.mjs --zip <outDir>   guard, then write the three zips to <outDir> (zip CLI)
//   node package-release.mjs --record         guard, then record this release's permissions in release-state.json
//                                             (run once per published release, after uploading to the CWS)
// Exit: 0 = as declared · 1 = problem found · 2 = could not run (C38)

import { readFileSync, writeFileSync, readdirSync, statSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, relative, resolve, sep, extname } from "node:path";
import { pathToFileURL } from "node:url";
import { tmpdir } from "node:os";

import { repoPaths, NON_EXTENSION_DIR_NAMES, DOC_FILES, REPO_ONLY_FILES, TOOLS_DIR_NAME } from "./repoPaths.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const EXIT = Object.freeze({ OK: 0, FOUND: 1, DID_NOT_RUN: 2 });
const { TOOLS_ROOT, REPO_ROOT, EXT_ROOT } = repoPaths(import.meta.url);
const MANIFEST_FILE = "manifest.json";
const TOOLS_PACKAGE_FILE = "package.json";
const CHANGELOG_FILE = "CHANGELOG.md";
const CHANGELOG_HISTORY_FILE = "CHANGELOG_HISTORY.md";
const CHANGELOG_VERSION_RE = /^##\s+(\d+\.\d+\.\d+)\b/m;                       // first "## x.y.z" heading
const RELEASE_STATE_FILE = join(TOOLS_ROOT, "release-state.json");
const RUNTIME_EXTENSIONS = Object.freeze([".js", ".html", ".css", ".png", ".json"]);
// Repo-root names that are neither extension nor docs: tools/run-knip.mjs's dev-only symlinks (see its header).
const DEV_LINK_NAMES = Object.freeze(["package.json", "node_modules"]);
const SKIP_NAMES = Object.freeze(new Set([".DS_Store", "Thumbs.db"]));        // OS litter, never part of a release
const TOOLS_EXCLUDED_DIRS = Object.freeze(new Set(["node_modules", "coverage", ".jscpd"]));
const PERMISSION_KEYS = Object.freeze(["permissions", "host_permissions", "optional_permissions", "optional_host_permissions"]);
// Approved permission additions since the recorded release: { "<key>:<value>": "<version> — <reason>" }.
// Empty = nothing new may appear.
const APPROVED_ADDITIONS = Object.freeze({});
const ZIP_NAME = Object.freeze({
    extension: (v) => `DownloadSentinel-EXTENSION-v${v}.zip`,
    docs:      (v) => `DownloadSentinel-DOCS-v${v}.zip`,
    tools:     (v) => `DownloadSentinel-TOOLS-v${v}.zip`,
});
const DOCS_ZIP_FOLDER = "DOCS";

// ── Trees ────────────────────────────────────────────────────────────────────
function walk(root, dir, skipDir) {
    return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
        if (SKIP_NAMES.has(e.name)) return [];
        const p = join(dir, e.name);
        if (e.isDirectory()) return skipDir(relative(root, p).split(sep).join("/"), e.name) ? [] : walk(root, p, skipDir);
        return e.isFile() ? [relative(root, p).split(sep).join("/")] : [];
    });
}

// Files of the extension zip, relative to the repo root.
export function extensionFiles() {
    const notExtensionRoot = new Set([...DOC_FILES, ...REPO_ONLY_FILES, ...DEV_LINK_NAMES]);
    return walk(EXT_ROOT, EXT_ROOT, (rel, name) => NON_EXTENSION_DIR_NAMES.has(name) || notExtensionRoot.has(rel))
        .filter((f) => !notExtensionRoot.has(f));
}
// Files of the tools zip, relative to tools/.
export function toolsFiles() {
    return walk(TOOLS_ROOT, TOOLS_ROOT, (rel, name) => TOOLS_EXCLUDED_DIRS.has(name));
}
// Files of the docs zip, relative to the repo root.
export function docsFiles() { return DOC_FILES.filter((f) => existsSync(join(REPO_ROOT, f))); }

// ── Guard ────────────────────────────────────────────────────────────────────
const flatten = (lists) => PERMISSION_KEYS.flatMap((k) => (Array.isArray(lists?.[k]) ? lists[k] : []).map((p) => `${k}:${p}`));

export function guardRelease() {
    const problems = [];
    const info = [];
    for (const f of extensionFiles()) {
        if (!RUNTIME_EXTENSIONS.includes(extname(f).toLowerCase())) {
            problems.push(`extension: "${f}" is not runtime code — move it to ${TOOLS_DIR_NAME}/ or declare it in DOC_FILES (tools/repoPaths.mjs)`);
        }
    }
    for (const f of [CHANGELOG_FILE, CHANGELOG_HISTORY_FILE]) if (!existsSync(join(REPO_ROOT, f))) problems.push(`docs: "${f}" is missing`);
    if (problems.length) return { problems, info };

    const manifest = JSON.parse(readFileSync(join(EXT_ROOT, MANIFEST_FILE), "utf8"));
    const toolsVersion = JSON.parse(readFileSync(join(TOOLS_ROOT, TOOLS_PACKAGE_FILE), "utf8")).version;
    const top = (readFileSync(join(REPO_ROOT, CHANGELOG_FILE), "utf8").match(CHANGELOG_VERSION_RE) || [])[1];
    if (top !== manifest.version) problems.push(`docs: ${CHANGELOG_FILE} top entry is ${top || "missing"}, manifest.json says ${manifest.version}`);
    if (toolsVersion !== manifest.version) problems.push(`tools: package.json is ${toolsVersion}, manifest.json says ${manifest.version}`);
    const historyRe = new RegExp(`^##\\s+${manifest.version.replace(/\./g, "\\.")}\\b`, "m");
    if (!historyRe.test(readFileSync(join(REPO_ROOT, CHANGELOG_HISTORY_FILE), "utf8"))) {
        problems.push(`docs: ${CHANGELOG_HISTORY_FILE} has no "## ${manifest.version}" entry`);
    }

    if (!existsSync(RELEASE_STATE_FILE)) {
        problems.push(`permissions: no previous release record (${relative(REPO_ROOT, RELEASE_STATE_FILE)})`);
    } else {
        const state = JSON.parse(readFileSync(RELEASE_STATE_FILE, "utf8"));
        const before = new Set(flatten(state.shippedPermissions));
        const now = flatten(manifest);
        for (const p of now.filter((x) => !before.has(x))) {
            if (APPROVED_ADDITIONS[p]) info.push(`${p} added — approved: ${APPROVED_ADDITIONS[p]}`);
            else problems.push(`permissions: ${p} was not shipped by ${state.version} and is not in APPROVED_ADDITIONS`);
        }
        for (const p of [...before].filter((x) => !now.includes(x))) info.push(`${p} removed since ${state.version}`);
    }
    return { problems, info, version: manifest.version, manifest };
}

// ── Actions ──────────────────────────────────────────────────────────────────
// zip CLI, run from `cwd` with relative names — every temp folder is released in finally (guard).
function zipFiles(outFile, cwd, files) {
    rmSync(outFile, { force: true });
    execFileSync("zip", ["-q", "-X", outFile, "-@"], { cwd, input: files.join("\n") });
}
function writeZips(outDir, version) {
    mkdirSync(outDir, { recursive: true });
    const out = (k) => join(outDir, ZIP_NAME[k](version));
    zipFiles(out("extension"), EXT_ROOT, extensionFiles());
    zipFiles(out("tools"), TOOLS_ROOT, toolsFiles());
    const staging = join(tmpdir(), `ds-docs-${process.pid}`);
    try {
        mkdirSync(join(staging, DOCS_ZIP_FOLDER), { recursive: true });
        for (const f of docsFiles()) writeFileSync(join(staging, DOCS_ZIP_FOLDER, f), readFileSync(join(REPO_ROOT, f)));
        zipFiles(out("docs"), staging, docsFiles().map((f) => `${DOCS_ZIP_FOLDER}/${f}`));
    } finally {
        rmSync(staging, { recursive: true, force: true });
    }
    return Object.keys(ZIP_NAME).map(out);
}
function recordRelease(version, manifest) {
    const shippedPermissions = Object.fromEntries(PERMISSION_KEYS.map((k) => [k, [...(manifest[k] || [])].sort()]));
    writeFileSync(RELEASE_STATE_FILE, JSON.stringify({ version, shippedPermissions }, null, 2) + "\n");
}

// ── CLI (only when run directly, not when imported) ─────────────────────────
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i === -1 ? null : (process.argv[i + 1] ?? ""); }

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
    let result;
    try { result = guardRelease(); }
    catch (e) { console.error(`package-release: DID NOT RUN — ${e.message}`); process.exit(EXIT.DID_NOT_RUN); }
    result.info.forEach((l) => console.log(`  info: ${l}`));
    if (result.problems.length) {
        console.log(`package-release: FAIL — ${result.problems.length} problem(s):`);
        result.problems.forEach((p) => console.log(`  ${p}`));
        process.exit(EXIT.FOUND);
    }
    console.log(`package-release: PASS — ${extensionFiles().length} runtime files in the extension, docs and tools complete, ` +
        `versions congruent (${result.version}), no unapproved permission`);
    const zipDir = arg("zip");
    if (zipDir !== null) {
        if (!zipDir) { console.error("package-release: --zip needs an output folder"); process.exit(EXIT.DID_NOT_RUN); }
        writeZips(resolve(zipDir), result.version).forEach((f) => console.log(`  wrote ${f}`));
    }
    if (process.argv.includes("--record")) {
        recordRelease(result.version, result.manifest);
        console.log(`  recorded ${result.version}'s permissions in ${relative(REPO_ROOT, RELEASE_STATE_FILE)}`);
    }
    process.exit(EXIT.OK);
}
