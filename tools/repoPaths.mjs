"use strict";

// tools/repoPaths.mjs
//
// THE declaration of the repository layout (v3.6.0) — every tools/*.mjs script and test that reaches into the
// extension takes its roots and its "what is not extension code" rule from here (C21: one declaration).
//
// Layout (same as uBlock Dynamic and 3P Matrix on GitHub):
//   <repo root>/            the unpacked extension (manifest.json, background.js, util/, protection/, pages/, …)
//   <repo root>/tools/      this package: build, verification and test suite — never shipped
//   <repo root>/*.md, LICENSE  project documents (changelogs, README, privacy) — never shipped in the extension zip
// Before 3.6.0 the three release zips were three sibling folders (EXTENSION/, TOOLS/, DOCS/).
//
// Usage:
//   import { repoPaths, NON_EXTENSION_DIR_NAMES } from "./repoPaths.mjs";
//   const { TOOLS_ROOT, REPO_ROOT, EXT_ROOT } = repoPaths(import.meta.url);
//   TOOLS_ROOT = <repo>/tools · REPO_ROOT = <repo> · EXT_ROOT = <repo> (the extension IS the repo root)
// Works for scripts in tools/ and for tests in tools/tests/ alike (it walks up to the folder holding
// tools/package.json).
import path from "node:path";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

// ── Layout settings (one place) ──────────────────────────────────────────────
export const TOOLS_DIR_NAME = "tools";
const TOOLS_MARKER_FILE = "package.json";                      // marks TOOLS_ROOT when walking up
// Folders that are never extension code: this package, and build/test/VCS artefacts anywhere in the tree.
export const NON_EXTENSION_DIR_NAMES = Object.freeze(new Set([TOOLS_DIR_NAME, "node_modules", ".git", "coverage", ".jscpd"]));
// Repo-root files that are project documents (docs zip), never part of the extension zip.
export const DOC_FILES = Object.freeze(["CHANGELOG.md", "CHANGELOG_HISTORY.md", "README.md", "privacy.md", "LICENSE"]);
// Repo-root files that belong to neither zip (version control housekeeping).
export const REPO_ONLY_FILES = Object.freeze([".gitignore", ".gitattributes"]);

export function repoPaths(importMetaUrl) {
    let dir = path.dirname(fileURLToPath(importMetaUrl));
    // Walk up to tools/ (guard: stop at the filesystem root — a script outside the layout fails loudly).
    while (!(path.basename(dir) === TOOLS_DIR_NAME && existsSync(path.join(dir, TOOLS_MARKER_FILE)))) {
        const up = path.dirname(dir);
        if (up === dir) throw new Error(`repoPaths: ${fileURLToPath(importMetaUrl)} is not inside a ${TOOLS_DIR_NAME}/ package`);
        dir = up;
    }
    const TOOLS_ROOT = dir;
    const REPO_ROOT  = path.dirname(TOOLS_ROOT);
    const EXT_ROOT   = REPO_ROOT;
    return { TOOLS_ROOT, REPO_ROOT, EXT_ROOT };
}
