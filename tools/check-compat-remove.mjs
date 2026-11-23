#!/usr/bin/env node
"use strict";

// tools/check-compat-remove.mjs
//
// v3.2.0 (3P Matrix alignment §6) — process item ported from the 3P Matrix
// audit (Xplainer v10): a `COMPAT-REMOVE` tag convention for code kept only
// for a transitional/backward-compatibility reason, with a target version
// after which it's safe to delete.
//
// Convention: a single-line comment anywhere in the repo (extension or tools/),
//   // COMPAT-REMOVE(v3.3.0): <reason this exists and why it can go>
// `v3.3.0` is the version AT OR AFTER WHICH the tagged code is safe to
// remove (not "remove exactly at" — this script flags it "overdue" from
// that version onward, since removal usually happens in the next convenient
// release, not the instant the target is reached).
//
// This is advisory only, like tools/check-list-freshness.mjs — it never
// fails the build; it only lists what's tagged and whether any tag's target
// version has already been reached or passed, so a maintainer doesn't have
// to remember a removal by hand.
//
// Usage:
//   node tools/check-compat-remove.mjs

import { readFileSync, existsSync, readdirSync } from "node:fs";
import path from "node:path";

import { repoPaths } from "./repoPaths.mjs";

const { REPO_ROOT, EXT_ROOT } = repoPaths(import.meta.url);

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG — the tag pattern and the dirs this scans, in one place.
// ─────────────────────────────────────────────────────────────────────────────
const CONFIG = Object.freeze({
    TAG_RE: /\/\/\s*COMPAT-REMOVE\((v\d+\.\d+\.\d+)\):\s*(.+)$/,
    SCAN_DIRS: [REPO_ROOT],   // v3.6.0: one walk covers the extension (repo root) and tools/ (incl. tests/)
    EXCLUDED_DIR_NAMES: new Set(["node_modules", ".git", "coverage", ".jscpd", "lists-raw"]),
});

function parseVersion(v) {
    const m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(v);
    if (!m) return null;
    return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function compareVersions(a, b) {
    for (let i = 0; i < 3; i++) { if (a[i] !== b[i]) return a[i] - b[i]; }
    return 0;
}

function walkJsFiles(dir, out = []) {
    if (!existsSync(dir)) return out;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const abs = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            if (CONFIG.EXCLUDED_DIR_NAMES.has(entry.name)) continue;
            walkJsFiles(abs, out);
        } else if (entry.isFile() && entry.name.endsWith(".js")) {
            out.push(abs);
        }
    }
    return out;
}

function findTags() {
    const tags = [];
    for (const dir of CONFIG.SCAN_DIRS) {
        for (const file of walkJsFiles(dir)) {
            const lines = readFileSync(file, "utf8").split("\n");
            lines.forEach((line, i) => {
                const m = CONFIG.TAG_RE.exec(line);
                if (m) tags.push({ file: path.relative(REPO_ROOT, file), lineNo: i + 1, targetVersion: m[1], reason: m[2].trim() });
            });
        }
    }
    return tags;
}

function currentVersion() {
    const manifestPath = path.join(EXT_ROOT, "manifest.json");
    if (!existsSync(manifestPath)) return null;
    try { return JSON.parse(readFileSync(manifestPath, "utf8")).version || null; } catch { return null; }
}

function main() {
    const tags = findTags();
    const current = currentVersion();
    const currentParsed = current ? parseVersion(current) : null;

    if (tags.length === 0) {
        console.log("No COMPAT-REMOVE tags found — nothing pending removal.");
        return;
    }

    console.log(`Found ${tags.length} COMPAT-REMOVE tag(s) (current version: ${current ?? "unknown"}):\n`);
    let overdueCount = 0;
    for (const tag of tags) {
        const targetParsed = parseVersion(tag.targetVersion);
        const overdue = currentParsed && targetParsed && compareVersions(currentParsed, targetParsed) >= 0;
        if (overdue) overdueCount++;
        const marker = overdue ? "⚠ OVERDUE" : "·";
        console.log(`  ${marker} ${tag.file}:${tag.lineNo} — target ${tag.targetVersion} — ${tag.reason}`);
    }

    console.log("");
    if (overdueCount) {
        console.log(`${overdueCount} tag(s) have reached or passed their target version — safe to remove, review and delete.`);
    } else {
        console.log("No tags are overdue yet.");
    }
}

main();
