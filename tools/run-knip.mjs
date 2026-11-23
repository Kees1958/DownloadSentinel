#!/usr/bin/env node
"use strict";

// tools/run-knip.mjs
//
// Thin wrapper around invoking knip, needed only because knip.json and
// package.json live in tools/ while the extension is the repo root (v3.6.0
// layout; before: the EXTENSION/TOOLS split): knip.json's "entry"/"project"
// patterns point at the repo root, and knip (as of the version pinned in package.json) does
// not reliably trace an import graph whose entry/project globs climb out of
// its own working directory with "../" — tested directly: the exact same
// config, run with the repo root as cwd instead (so the globs read
// "background.js", "**/*.js" with no "../"), traces the graph correctly with zero false
// "unused file" findings, but knip then also requires a package.json (and,
// to avoid spurious "unused devDependency"/"unlisted binary" noise, a
// node_modules) to exist AT that cwd.
//
// Rather than duplicate package.json/node_modules, or move knip.json/
// package.json out of tools/ (which would defeat the point of the
// restructure), this script creates two symlinks at the repo root —
// package.json -> tools/package.json and node_modules -> tools/node_modules
// — idempotently (checked every run, replaced only if not already the
// expected symlink), runs knip with the repo root as cwd, and leaves the
// symlinks in place afterward (so a plain `knip` re-run, or an editor's
// knip integration, keeps working without re-invoking this script). These
// two paths are dev-only link files, never shipped — see the root .gitignore and
// tools/repoPaths.mjs (REPO_ONLY_FILES / NON_EXTENSION_DIR_NAMES).
//
// Usage: node tools/run-knip.mjs [any extra knip CLI args]

import { existsSync, lstatSync, symlinkSync, unlinkSync, readlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";

import { repoPaths, TOOLS_DIR_NAME } from "./repoPaths.mjs";

const { TOOLS_ROOT, REPO_ROOT } = repoPaths(import.meta.url);

function ensureSymlink(target, linkPath) {
    // target is relative to REPO_ROOT (e.g. "tools/package.json").
    if (existsSync(linkPath) || isSymlinkPresent(linkPath)) {
        try {
            if (lstatSync(linkPath).isSymlink() && readlinkSync(linkPath) === target) {
                return; // already exactly what we want — leave it alone
            }
        } catch {
            // fall through to (re)create below
        }
        try { unlinkSync(linkPath); } catch { /* best-effort */ }
    }
    try {
        symlinkSync(target, linkPath);
    } catch (e) {
        console.log(`⚠ WARN  could not create ${path.relative(REPO_ROOT, linkPath)} -> ${target} (${e.message}) — ` +
            "knip needs this to resolve its graph from the repo root; " +
            "on a platform without symlink support, create it manually or skip this check.");
        return false;
    }
    return true;
}

function isSymlinkPresent(p) {
    try { lstatSync(p); return true; } catch { return false; }
}

const pkgOk = ensureSymlink(path.join(TOOLS_DIR_NAME, "package.json"), path.join(REPO_ROOT, "package.json"));
const nmOk  = ensureSymlink(path.join(TOOLS_DIR_NAME, "node_modules"), path.join(REPO_ROOT, "node_modules"));

if (pkgOk === false || nmOk === false) {
    process.exit(3); // distinct code — caller (complete-check.mjs) treats this as "skip, don't fail"
}

const knipBin = path.join(TOOLS_ROOT, "node_modules", ".bin", process.platform === "win32" ? "knip.cmd" : "knip");
const extraArgs = process.argv.slice(2);

// spawnSync (not execFileSync) deliberately — knip's own non-zero exit code
// on real findings is normal, expected output, not a crash; this just
// forwards it (same as plain `knip` always has), instead of throwing a
// Node stack trace on top of it.
const result = spawnSync(knipBin, ["--no-progress", "-c", path.join(TOOLS_DIR_NAME, "knip.json"), ...extraArgs], {
    cwd: REPO_ROOT,
    stdio: "inherit",
    env: { ...process.env, KNIP_DISABLE_RAW_TRANSFER: "1" },
});
process.exit(result.status ?? 1);
