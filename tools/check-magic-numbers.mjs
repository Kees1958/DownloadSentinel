#!/usr/bin/env node
"use strict";

// tools/check-magic-numbers.mjs
//
// v3.2.0 (3P Matrix alignment §6) — process item ported from the 3P Matrix
// audit (Xplainer v10): this project's own standing convention — "every
// magic number lives in one named CONFIG/SCORING_CONFIG block with a
// comment, never scattered inline" (see any module's own "CONFIG — every
// magic number for this module, gathered here" header) — checked
// mechanically instead of only by human review.
//
// This is a GREP-LEVEL ADVISORY, not an AST-aware linter: it flags lines in
// protection/ and util/ that compare a variable against a bare numeric
// literal (>, <, >=, <=, ===, !==) OUTSIDE of a recognized CONFIG-block
// declaration, as candidates worth a human look — not a precise or
// exhaustive detector. Like tools/check-list-freshness.mjs and
// tools/check-compat-remove.mjs, it never fails the build.
//
// False positives are expected and fine (array index comparisons, loop
// bounds, string-length sanity checks) — this script's job is to produce a
// short, reviewable candidate list, not a verdict.
//
// Usage:
//   node tools/check-magic-numbers.mjs

import { readFileSync, existsSync, readdirSync } from "node:fs";
import path from "node:path";

import { repoPaths } from "./repoPaths.mjs";

const { EXT_ROOT, REPO_ROOT } = repoPaths(import.meta.url);

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG — every tunable for this scan, gathered here.
// ─────────────────────────────────────────────────────────────────────────────
const CONFIG = Object.freeze({
    SCAN_DIRS: [path.join(EXT_ROOT, "protection"), path.join(EXT_ROOT, "util")],
    // Numbers excluded as near-universally structural, not "magic": 0, 1, -1
    // (array/string bounds, "not found"/"first" sentinels) and 2 (halving/
    // pairing, also extremely common and rarely worth a named constant).
    ALLOWED_BARE_NUMBERS: new Set(["0", "1", "-1", "2"]),
    COMPARISON_RE: /(?<![=!<>])(?:[<>]=?|={2,3}|!={1,2})\s*(-?\d+(?:\.\d+)?)\b|\b(-?\d+(?:\.\d+)?)\s*(?:[<>]=?|={2,3}|!={1,2})(?!=)/g,
    // A line is considered "inside a CONFIG block" from the line declaring
    // `const X_CONFIG = Object.freeze({` / `const CONFIG = {` up to the
    // matching top-level `});` / `};` — tracked with a simple brace counter,
    // good enough for this codebase's consistent one-block-per-file style
    // (not a real parser, so deeply nested/multi-block edge cases can slip
    // through either direction — acceptable for an advisory scan).
    CONFIG_START_RE: /\b(?:const|export const)\s+\w*CONFIG\w*\s*=\s*(?:Object\.freeze\()?\{/,
});

function walkJsFiles(dir, out = []) {
    if (!existsSync(dir)) return out;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const abs = path.join(dir, entry.name);
        if (entry.isDirectory()) { walkJsFiles(abs, out); }
        else if (entry.isFile() && entry.name.endsWith(".js")) out.push(abs);
    }
    return out;
}

function scanFile(file) {
    const lines = readFileSync(file, "utf8").split("\n");
    const findings = [];
    let configDepth = 0; // > 0 means "currently inside a *CONFIG block"

    lines.forEach((line, i) => {
        const trimmed = line.trim();
        if (configDepth === 0 && CONFIG.CONFIG_START_RE.test(trimmed)) {
            configDepth = 1;
            return; // the declaration line itself is never a finding
        }
        if (configDepth > 0) {
            // Rough brace tracking — count net opens/closes on this line.
            const opens  = (line.match(/\{/g) || []).length;
            const closes = (line.match(/\}/g) || []).length;
            configDepth += opens - closes;
            if (configDepth <= 0) configDepth = 0;
            return; // everything inside the block is exempt by definition
        }
        if (trimmed.startsWith("//") || trimmed.startsWith("*")) return; // comment line

        CONFIG.COMPARISON_RE.lastIndex = 0;
        let m;
        while ((m = CONFIG.COMPARISON_RE.exec(line))) {
            const num = m[1] ?? m[2];
            if (num !== undefined && !CONFIG.ALLOWED_BARE_NUMBERS.has(num)) {
                findings.push({ lineNo: i + 1, text: trimmed, num });
            }
        }
    });
    return findings;
}

function main() {
    let totalFindings = 0, filesWithFindings = 0;
    const report = [];
    for (const dir of CONFIG.SCAN_DIRS) {
        for (const file of walkJsFiles(dir)) {
            const findings = scanFile(file);
            if (findings.length === 0) continue;
            filesWithFindings++;
            totalFindings += findings.length;
            const rel = path.relative(REPO_ROOT, file);
            for (const f of findings) report.push(`  ${rel}:${f.lineNo} — bare ${f.num} in: ${f.text}`);
        }
    }

    if (totalFindings === 0) {
        console.log("No bare-numeric comparisons found outside CONFIG blocks.");
        return;
    }

    console.log(`${totalFindings} candidate(s) across ${filesWithFindings} file(s) — grep-level advisory, review by hand:\n`);
    console.log(report.join("\n"));
}

main();
