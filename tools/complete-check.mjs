#!/usr/bin/env node
"use strict";

// tools/complete-check.mjs
//
// A single local check run via `npm run check`, meant to catch the classes
// of regression that are easy to miss by eye in a browser extension: broken
// imports/paths, message types with no router case, JSON that fails to
// parse, a manifest/package.json version drift, and — as of the audit pass
// that added Part D — a real unit test suite plus static-analysis tooling
// for structure, duplication, and unused code.
//
// Repository layout (v3.6.0, tools/repoPaths.mjs): the unpacked extension IS
// the repo root (EXT_ROOT = REPO_ROOT: manifest.json, background.js,
// protection/, util/, pages/, assets/, data/); this package is tools/
// (TOOLS_ROOT: package.json, tests/, node_modules) and is never extension
// code (NON_EXTENSION_DIR_NAMES). Every step below is explicit about which
// root it's checking.
//
// Covers: syntax, ESLint, JSON validity, a file cross-reference (C20 —
// every manifest path / <script src> / import resolves to a real file),
// a message-routing cross-reference (C20a — every MSG.* has a router case
// and a real sender, or is in the documented BROADCAST_ONLY set with a
// reader), unit tests (node --test) against the pure/deterministic modules,
// a circular-dependency check (madge), unused-file/export detection (knip),
// unused-dependency detection (depcheck), a duplicate-code scan (jscpd), a
// manifest/package.json version-sync check, (v3.2.0, 3P Matrix alignment
// §5) an external-data-source freshness advisory against data-sources.json,
// and (v3.4.0) a Manifest V3 compliance gate (tools/check-mv3.mjs).
//
// Pass/fail semantics: syntax, ESLint, JSON validity, file cross-reference,
// message routing, unit tests, circular deps, version sync, MV3
// compliance, the false-positive sweep and (v3.5.5) the list snapshot rule are hard gates (FAIL blocks a release). knip, depcheck, jscpd, and list freshness
// are soft checks (WARN only) — their findings are worth reviewing but
// shouldn't block a zip on their own; see each step's own comment for why.
//
// Does NOT cover: a JSDOM dry-run, a functional smoke test against mocked
// chrome.storage beyond Settings/Storage's own unit tests, a CSS class
// cross-reference, or live-network tests against VirusTotal/Quad9/RDAP —
// deliberate scope limits: those need a real browser or real network access,
// neither of which belongs in a fast local check.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";

import { repoPaths, NON_EXTENSION_DIR_NAMES, TOOLS_DIR_NAME } from "./repoPaths.mjs";

const { TOOLS_ROOT, REPO_ROOT, EXT_ROOT } = repoPaths(import.meta.url);

let failed = false;
function ok(msg)   { console.log(`✓ OK    ${msg}`); }
function warn(msg)  { console.log(`⚠ WARN  ${msg}`); }
function fail(msg)  { console.log(`✗ FAIL  ${msg}`); failed = true; }

// Build/test/VCS artefacts — skipped by every walk. The extension walk also skips tools/ (NON_EXTENSION_DIR_NAMES).
const ARTEFACT_DIR_NAMES = new Set([...NON_EXTENSION_DIR_NAMES].filter((n) => n !== TOOLS_DIR_NAME));

function walk(dir, out = [], excluded = ARTEFACT_DIR_NAMES) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (excluded.has(entry.name)) continue;
      walk(abs, out, excluded);
    } else if (entry.isFile() && entry.name.endsWith(".js")) {
      out.push(abs);
    }
  }
  return out;
}

// Every .js file in the repo (the extension's shipped code AND tools/' tests/
// helpers) — same breadth the pre-restructure single-root version of this
// script had (it walked the whole repo root). Used by checkSyntax() and
// checkMessageRouting()'s source scan; checkFileReferences() below scopes
// itself to the extension tree only, since manifest-reachability is an
// extension-only concept.
function listAllJsFiles() {
  return existsSync(REPO_ROOT) ? walk(REPO_ROOT) : [];
}

// Just the extension's own .js files — what "reachable from manifest.json"
// means something for. Never includes tools/ (not shipped).
function listExtensionJsFiles() {
  return existsSync(EXT_ROOT) ? walk(EXT_ROOT, [], NON_EXTENSION_DIR_NAMES) : [];
}

// ── 1. Syntax check ─────────────────────────────────────────────────────────
function checkSyntax() {
  console.log("\n── 1. Syntax (node --check) ──");
  const files = listAllJsFiles();
  let count = 0;
  for (const file of files) {
    try {
      execFileSync(process.execPath, ["--check", file], { stdio: "pipe" });
      count++;
    } catch (e) {
      fail(`${path.relative(REPO_ROOT, file)} — ${e.stderr?.toString().split("\n")[0] || e.message}`);
    }
  }
  if (!failed) ok(`${count} files parsed cleanly`);
}

// ── 2. ESLint ────────────────────────────────────────────────────────────────
// Two invocations, one config each (v3.6.0: the extension's config moved out
// of the shipped tree to tools/eslint-extension.json — browser/webextensions
// env only; tools/.eslintrc.json — browser/webextensions + node, for the
// Node-run tests/tool scripts). Only .js
// files are linted (not tools/*.mjs), matching this project's
// established scope (package.json's own `lint` script has always used
// `--ext .js`, not `.mjs`, since v2.6.1).
const EXTENSION_ESLINT_CONFIG = "eslint-extension.json";
function checkLint() {
  console.log("\n── 2. ESLint ──");
  const localBin = path.join(TOOLS_ROOT, "node_modules", ".bin", process.platform === "win32" ? "eslint.cmd" : "eslint");
  if (!existsSync(localBin)) {
    warn("eslint not installed locally — run `npm install` first; skipping lint step");
    return;
  }
  try {
    // Extension code: its own config (tools/eslint-extension.json — browser only, kept out of the shipped tree).
    execFileSync(localBin, ["--no-eslintrc", "-c", path.join(TOOLS_ROOT, EXTENSION_ESLINT_CONFIG),
      "--ignore-pattern", `${TOOLS_DIR_NAME}/`, "--ext", ".js", "."], { cwd: EXT_ROOT, stdio: "pipe" });
    // This package: tools/.eslintrc.json (root: true, + node).
    execFileSync(localBin, [".", "--ext", ".js"], { cwd: TOOLS_ROOT, stdio: "pipe" });
    ok("eslint clean (extension + tools/)");
  } catch (e) {
    fail(`eslint found issues:\n${e.stdout?.toString() || e.message}`);
  }
}

// ── 3. JSON validity ─────────────────────────────────────────────────────────
function checkJson() {
  console.log("\n── 3. JSON validity ──");
  let manifest, pkg;
  try {
    manifest = JSON.parse(readFileSync(path.join(EXT_ROOT, "manifest.json"), "utf8"));
  } catch (e) {
    fail(`manifest.json — ${e.message}`);
  }
  try {
    pkg = JSON.parse(readFileSync(path.join(TOOLS_ROOT, "package.json"), "utf8"));
  } catch (e) {
    fail(`tools/package.json — ${e.message}`);
  }
  if (manifest && pkg) ok("manifest.json and package.json parse cleanly");
  return { manifest, pkg };
}

// ── 4. File cross-reference (C20) ───────────────────────────────────────────
// Scoped entirely to EXT_ROOT: manifest.json's own declared paths, and every
// .js/.html file it (transitively) imports/references, must resolve to a
// real file inside the extension — a path pointing into tools/ (or any
// NON_EXTENSION_DIR_NAMES folder) would mean the CWS package references a
// file that isn't shipped alongside it (v3.6.0: tools/ now sits inside the
// repo root, so existence alone no longer proves "shipped" — isShipped()).
function checkFileReferences(manifest) {
  console.log("\n── 4. File cross-reference (C20) ──");
  if (!manifest) { warn("manifest.json failed to parse — skipping"); return; }

  const visited = new Set();
  const declared = [];

  if (manifest.background?.service_worker) declared.push(manifest.background.service_worker);
  for (const page of [manifest.options_page, manifest.options_ui?.page].filter(Boolean)) declared.push(page);
  for (const action of [manifest.action?.default_popup].filter(Boolean)) declared.push(action);
  for (const war of manifest.web_accessible_resources || []) {
    for (const r of war.resources || []) declared.push(r);
  }

  const isShipped = (rel) => !rel.startsWith("..") && !NON_EXTENSION_DIR_NAMES.has(rel.split("/")[0]);

  function resolveImports(file, seen = visited) {
    const rel = path.relative(EXT_ROOT, file).split(path.sep).join("/");
    if (seen.has(rel)) return;
    seen.add(rel);
    if (!isShipped(rel)) { fail(`${rel} — referenced, but outside the shipped extension tree`); return; }
    if (!existsSync(file)) { fail(`${rel} — declared but does not exist`); return; }
    if (file.endsWith(".js")) {
      const src = readFileSync(file, "utf8");
      const importRe = /import\s+(?:[\s\S]*?\bfrom\s+)?["']([^"']+)["']/g;
      let m;
      while ((m = importRe.exec(src))) {
        const spec = m[1];
        if (!spec.startsWith(".")) continue;
        const resolved = path.resolve(path.dirname(file), spec);
        resolveImports(resolved, seen);
      }
    } else if (file.endsWith(".html")) {
      const src = readFileSync(file, "utf8");
      const scriptRe = /<script[^>]+src=["']([^"']+)["']/g;
      const linkRe = /<link[^>]+href=["']([^"']+)["']/g;
      let m;
      while ((m = scriptRe.exec(src))) {
        if (m[1].startsWith("http")) continue;
        resolveImports(path.resolve(path.dirname(file), m[1]), seen);
      }
      while ((m = linkRe.exec(src))) {
        if (m[1].startsWith("http")) continue;
        const resolved = path.resolve(path.dirname(file), m[1]);
        const relLink = path.relative(EXT_ROOT, resolved).split(path.sep).join("/");
        if (!seen.has(relLink)) {
          seen.add(relLink);
          if (!isShipped(relLink)) fail(`${relLink} — referenced, but outside the shipped extension tree`);
          else if (!existsSync(resolved)) fail(`${relLink} — referenced but does not exist`);
        }
      }
    }
  }

  for (const d of declared) resolveImports(path.join(EXT_ROOT, d));

  for (const file of listExtensionJsFiles()) {
    const rel = path.relative(EXT_ROOT, file).split(path.sep).join("/");
    if (!visited.has(rel)) warn(`${rel} is not reachable from manifest.json — orphaned file, or an untracked entry point`);
  }
  if (!failed) ok("all declared/imported/script-src paths resolve to real files inside the extension");
}

// ── 5. Message-routing cross-reference (C20a) ───────────────────────────────
// A KNOWN_UNSENT set of message types that are defined but deliberately not
// yet wired up to a sender (tracked, not a bug) — avoids false failures.
const KNOWN_UNSENT = new Set(["SUBMIT_URL_TO_VT"]);
const BROADCAST_ONLY = new Set(["SETTINGS_UPDATED"]);

function checkMessageRouting() {
  console.log("\n── 5. Message-routing cross-reference (C20a) ──");
  const msgFile = path.join(EXT_ROOT, "util", "MessageTypes.js");
  if (!existsSync(msgFile)) { warn("util/MessageTypes.js not found — skipping"); return; }

  const src = readFileSync(msgFile, "utf8");
  const msgTypeRe = /^\s*([A-Z0-9_]+):\s*["']([^"']+)["']/gm;
  const types = [];
  let m;
  while ((m = msgTypeRe.exec(src))) types.push(m[1]);

  const allSrc = listAllJsFiles().map(f => readFileSync(f, "utf8")).join("\n");

  let checked = 0, broadcastOnly = 0, knownUnsent = 0;
  for (const type of types) {
    // Two sender shapes are used in this codebase: MSG.X passed directly as
    // a sendMessage() argument, and MSG.X assigned to a "type:" field of a
    // message object built separately (then sent via a variable) — the
    // latter is how background.js pushes VT_RESULT_UPDATE.
    const hasSender = new RegExp(`sendMessage\\([^)]*MSG\\.${type}\\b`).test(allSrc)
      || new RegExp(`type:\\s*MSG\\.${type}\\b`).test(allSrc);
    // Two router shapes are used: a switch/case (background.js's central
    // router) and an if-guard comparing msg.type (WarningPage.js's push
    // listener, e.g. "if (msg.type !== MSG.X) return;").
    const hasRouter = new RegExp(`case\\s+MSG\\.${type}\\b`).test(allSrc)
      || new RegExp(`msg\\.type\\s*[=!]==\\s*MSG\\.${type}\\b`).test(allSrc);

    if (BROADCAST_ONLY.has(type)) {
      broadcastOnly++;
      if (!hasSender) warn(`MSG.${type}: documented broadcast-only but no sender found`);
      checked++;
      continue;
    }
    if (!hasSender && KNOWN_UNSENT.has(type)) {
      knownUnsent++;
      warn(`MSG.${type}: confirmed still unsent (tracked in KNOWN_UNSENT) — see CHANGELOG.md for status`);
      checked++;
      continue;
    }
    if (!hasSender) fail(`MSG.${type}: defined but never sent anywhere`);
    if (!hasRouter) fail(`MSG.${type}: sent but no router case handles it`);
    checked++;
  }
  if (!failed) ok(`${checked} message types checked (${broadcastOnly} broadcast-only, ${knownUnsent} known-unsent)`);
}

// ── 6. Unit tests (node --test) ─────────────────────────────────────────────
// Hard gate — a failing test means a real regression. Uses Node's built-in
// test runner (zero extra deps), covering the pure/deterministic modules:
// UrlUtils, DangerousExts, DangerousMimes, FilenameAnalysis, MimeCheck,
// FpReductionEngines, ScoringEngineV2 (both scoring axes), SketchyUrlCheck
// (brand-impersonation and fuzzy matching), LookalikeDomainCheck, RdapProtection
// (incl. domain-age not-applicable skip, v3.3.0), and Storage/Settings (via
// an in-memory chrome.storage mock — see tests/helpers/).
// Deliberately NOT covered: BrowserProtection.js's live VT/Quad9/RDAP fetch
// calls — same "no live network in the check suite" scope limit as the rest
// of this file.
function checkUnitTests() {
  console.log("\n── 6. Unit tests (node --test) ──");
  const testsDir = path.join(TOOLS_ROOT, "tests");
  if (!existsSync(testsDir)) { warn("no tests/ directory found — skipping"); return; }
  try {
    // No positional path argument: Node's test runner's own directory-arg
    // resolution has been observed to misbehave in this project's setup
    // (tries to require() the directory as CJS). Running with cwd=TOOLS_ROOT
    // and no argument uses Node's default recursive discovery of
    // **/*.test.js, which works reliably and finds the same tests/ files.
    const out = execFileSync(process.execPath, ["--test"], { cwd: TOOLS_ROOT, stdio: "pipe" }).toString();
    const summary = out.match(/# (pass|fail) \d+/g) || [];
    ok(`unit tests passed (${summary.join(", ")})`);
  } catch (e) {
    fail(`unit tests failed:\n${e.stdout?.toString() || e.message}`);
  }
}

// ── 7. Circular dependency check (madge) ────────────────────────────────────
// Hard gate — a circular import is a real structural problem (load-order
// bugs, partially-initialized modules) and is cheap to avoid entirely by
// design (C1/C3/C4 — clear module responsibilities and single owning layers
// already prevent this by construction; this step just confirms it stayed
// that way). Scans the whole repo in one invocation (tools/tests legitimately
// import across into the extension — this must trace those edges too, not
// just the extension's own internal graph).
function checkCircularDeps() {
  console.log("\n── 7. Circular dependency check (madge) ──");
  const localBin = path.join(TOOLS_ROOT, "node_modules", ".bin", process.platform === "win32" ? "madge.cmd" : "madge");
  if (!existsSync(localBin)) {
    warn("madge not installed locally — run `npm install` first; skipping");
    return;
  }
  try {
    // --json gives a reliable machine-readable result (an array of circular
    // chains, empty if none) — madge's plain-text success message is only
    // printed in an interactive TTY and is silently omitted when piped,
    // which made text-matching unreliable.
    const out = execFileSync(localBin, ["--circular", "--json", "--extensions", "js", "--exclude", "node_modules", "."], { cwd: REPO_ROOT, stdio: "pipe" }).toString();
    const chains = JSON.parse(out);
    if (Array.isArray(chains) && chains.length === 0) {
      ok("no circular dependencies");
    } else {
      fail(`madge found circular dependencies:\n${JSON.stringify(chains, null, 2)}`);
    }
  } catch (e) {
    fail(`madge reported circular dependencies:\n${e.stdout?.toString() || e.message}`);
  }
}

// ── 8. Unused files / exports (knip) ────────────────────────────────────────
// Soft check. Delegates to tools/run-knip.mjs, which exists only because
// knip.json/package.json live in tools/ while the extension is the repo root:
// knip does not reliably trace that graph when invoked with tools/ as cwd
// and "../" in the glob patterns — tracing only works with the repo root itself as
// knip's cwd, which in turn needs a package.json + node_modules to exist
// there. run-knip.mjs creates those as two idempotent symlinks back into
// tools/package.json and tools/node_modules (see that script's own header
// for the full story) and then runs knip from the repo root. Also sets
// KNIP_DISABLE_RAW_TRANSFER=1 — works around a real bug, not just an
// environment quirk: knip's oxc-parser integration defaults to an
// experimental "raw transfer" shared-buffer parsing mode for speed, and that
// fast path was reproduced crashing with "RangeError: Array buffer
// allocation failed" in at least one sandboxed build environment.
function checkUnusedCode() {
  console.log("\n── 8. Unused files / exports (knip) ──");
  const runner = path.join(TOOLS_ROOT, "run-knip.mjs");
  if (!existsSync(path.join(TOOLS_ROOT, "node_modules", ".bin", process.platform === "win32" ? "knip.cmd" : "knip"))) {
    warn("knip not installed locally — run `npm install` first; skipping");
    return;
  }
  try {
    const out = execFileSync(process.execPath, [runner], { cwd: TOOLS_ROOT, stdio: "pipe" }).toString();
    if (!out.trim()) ok("no unused files or exports");
    else warn(`knip findings (review, not blocking):\n${out}`);
  } catch (e) {
    const combined = (e.stdout?.toString() || "") + (e.stderr?.toString() || "") + e.message;
    warn(`knip findings (review, not blocking):\n${e.stdout?.toString() || combined}`);
  }
}

// ── 9. Unused dependencies (depcheck) ──────────────────────────────────────
// Soft check — depcheck has no usage-detector for CLI-only tools invoked
// purely via npm scripts (knip/depcheck/madge/jscpd/c8 itself), so those are
// pre-listed in .depcheckrc.json's "ignores". Anything else it flags is a
// genuine candidate for removal from package.json. Runs against TOOLS_ROOT
// only — the extension has no package.json/dependencies of its own to check.
function checkUnusedDeps() {
  console.log("\n── 9. Unused dependencies (depcheck) ──");
  const localBin = path.join(TOOLS_ROOT, "node_modules", ".bin", process.platform === "win32" ? "depcheck.cmd" : "depcheck");
  if (!existsSync(localBin)) {
    warn("depcheck not installed locally — run `npm install` first; skipping");
    return;
  }
  try {
    execFileSync(localBin, [], { cwd: TOOLS_ROOT, stdio: "pipe" });
    ok("no unused dependencies");
  } catch (e) {
    // depcheck exits non-zero whenever it reports anything — WARN, not FAIL,
    // since an unused devDependency doesn't affect the shipped extension.
    warn(`depcheck findings (review, not blocking):\n${e.stdout?.toString() || e.message}`);
  }
}

// ── 10. Duplicate code (jscpd) ───────────────────────────────────────────────
// Soft check, informational — flags candidates for the B2/B15 "consolidate
// near-duplicate logic" pattern. Never auto-fixed by this script: extracting
// a shared helper is a real code change that needs its own review, same as
// any other logic change (see Ground Rules). package-lock.json and the CSS
// files are excluded: lockfile duplication is npm's normal structure, and
// CSS token consolidation is tracked separately (style-guide adoption).
// Scans the whole repo (extension + tools/) in one invocation, same as madge.
const JSCPD_MIN_LINES = 5;   // below this, a "duplicate" is usually coincidence
const JSCPD_MIN_TOKENS = 40; // ditto — keeps trivial matches out of the report
function checkDuplicateCode() {
  console.log("\n── 10. Duplicate code (jscpd) ──");
  const localBin = path.join(TOOLS_ROOT, "node_modules", ".bin", process.platform === "win32" ? "jscpd.cmd" : "jscpd");
  if (!existsSync(localBin)) {
    warn("jscpd not installed locally — run `npm install` first; skipping");
    return;
  }
  const args = [
    "--min-lines", String(JSCPD_MIN_LINES),
    "--min-tokens", String(JSCPD_MIN_TOKENS),
    "--ignore", "**/node_modules/**,**/tests/**,**/package-lock.json,**/lists-raw/**,pages/**/*.css",
    "--reporters", "consoleFull",
    "."
  ];
  try {
    const out = execFileSync(localBin, args, { cwd: REPO_ROOT, stdio: "pipe" }).toString();
    if (/Found 0 clones/.test(out) || !/Found \d+ clones/.test(out)) ok("no duplicate code above threshold");
    else warn(`jscpd findings (review, not blocking):\n${out}`);
  } catch (e) {
    // jscpd's own exit code isn't a reliable success/failure signal across
    // versions — treat any output as informational rather than failing here.
    warn(`jscpd findings (review, not blocking):\n${e.stdout?.toString() || e.message}`);
  }
}

// ── 11. Version sync ──────────────────────────────────────────────────────────
function checkVersionSync(manifest, pkg) {
  console.log("\n── 11. Version sync ──");
  if (!manifest || !pkg) { warn("manifest.json or package.json failed to parse — skipping"); return; }
  if (manifest.version !== pkg.version) {
    fail(`manifest.json (${manifest.version}) and tools/package.json (${pkg.version}) are out of sync`);
    return;
  }
  ok(`manifest.json and package.json both at ${manifest.version}`);

  const lockPath = path.join(TOOLS_ROOT, "package-lock.json");
  if (existsSync(lockPath)) {
    try {
      const lock = JSON.parse(readFileSync(lockPath, "utf8"));
      if (lock.version !== pkg.version) {
        fail(`package-lock.json (${lock.version}) is out of sync — run \`npm install\``);
      } else {
        ok(`package-lock.json also at ${lock.version}`);
      }
    } catch {
      warn("package-lock.json failed to parse — skipping");
    }
  }
}

// ── 12. External data-source freshness (3P Matrix alignment §5, v3.2.0) ─────
// v3.5.5: + a HARD snapshot rule (see below and tools/source-snapshots.mjs). Age: soft check — delegates to tools/check-list-freshness.mjs (see that file's
// own header), which reads tools/data-sources.json and reports how old each
// cached external list (HaGeZi, Kees, PSL, CrUX) is. Never fails: a stale
// third-party list is worth a maintainer's attention, not a release blocker
// on its own (the data still loads — it's just not the newest available).
function checkListFreshness() {
  console.log("\n── 12. External data-source freshness ──");
  const script = path.join(TOOLS_ROOT, "check-list-freshness.mjs");
  if (!existsSync(script)) { warn("check-list-freshness.mjs not found — skipping"); return; }
  // v3.5.5: age stays a soft WARN; a snapshot mismatch (exit 1, "SNAPSHOT MISMATCH") is a hard FAIL, and a check
  // that could not run fails too (it has not passed — 3P Matrix C38).
  let out;
  try {
    out = execFileSync(process.execPath, [script], { cwd: TOOLS_ROOT, stdio: "pipe" }).toString();
  } catch (e) {
    const text = `${e.stdout || ""}${e.stderr || ""}`;
    if (text.includes("SNAPSHOT MISMATCH")) fail(`list built from an older raw snapshot than the one cached:\n${text}`);
    else fail(`check-list-freshness.mjs did not run: ${e.message}`);
    return;
  }
  if (out.includes("All cached sources are within the freshness window.")) {
    ok("all registered data sources are within the freshness window");
  } else {
    warn(`list-freshness findings (review, not blocking):\n${out}`);
  }
  ok("every list was built from the raw snapshot cached now");
}

// ── 13. Magic-number advisory (3P Matrix alignment §6, v3.2.0) ──────────────
// Soft check — delegates to tools/check-magic-numbers.mjs (grep-level
// advisory, not a precise linter; see that file's own header). Mechanically
// checks this project's own standing "every magic number lives in one named
// CONFIG block" convention over protection/ and util/.
function checkMagicNumbers() {
  console.log("\n── 13. Magic-number advisory ──");
  const script = path.join(TOOLS_ROOT, "check-magic-numbers.mjs");
  if (!existsSync(script)) { warn("check-magic-numbers.mjs not found — skipping"); return; }
  try {
    const out = execFileSync(process.execPath, [script], { cwd: TOOLS_ROOT, stdio: "pipe" }).toString();
    if (out.includes("No bare-numeric comparisons found")) ok("no bare-numeric comparisons found outside CONFIG blocks");
    else warn(`magic-number candidates (review, not blocking):\n${out}`);
  } catch (e) {
    warn(`check-magic-numbers.mjs failed to run: ${e.message}`);
  }
}

// ── 14. COMPAT-REMOVE tag audit (3P Matrix alignment §6, v3.2.0) ───────────
// Soft check — delegates to tools/check-compat-remove.mjs (see that file's
// own header for the tag convention). Reports any tag whose target version
// has been reached or passed, so a transitional shim is never forgotten.
function checkCompatRemove() {
  console.log("\n── 14. COMPAT-REMOVE tag audit ──");
  const script = path.join(TOOLS_ROOT, "check-compat-remove.mjs");
  if (!existsSync(script)) { warn("check-compat-remove.mjs not found — skipping"); return; }
  try {
    const out = execFileSync(process.execPath, [script], { cwd: TOOLS_ROOT, stdio: "pipe" }).toString();
    if (out.includes("No COMPAT-REMOVE tags found") || out.includes("No tags are overdue yet.")) {
      ok(out.includes("No COMPAT-REMOVE tags found") ? "no COMPAT-REMOVE tags present" : "COMPAT-REMOVE tags present, none overdue");
    } else {
      warn(`COMPAT-REMOVE findings (review, not blocking):\n${out}`);
    }
  } catch (e) {
    warn(`check-compat-remove.mjs failed to run: ${e.message}`);
  }
}

// ── 15. Derived-literal drift (3P Matrix alignment §6, v3.2.0) ──────────────
// Soft check — delegates to tools/check-derived-literals.mjs (see that
// file's own header). Flags a precise entry-count stated in a data module's
// own header comment that no longer matches its data/<Name>.json.
function checkDerivedLiterals() {
  console.log("\n── 15. Derived-literal drift ──");
  const script = path.join(TOOLS_ROOT, "check-derived-literals.mjs");
  if (!existsSync(script)) { warn("check-derived-literals.mjs not found — skipping"); return; }
  try {
    const out = execFileSync(process.execPath, [script], { cwd: TOOLS_ROOT, stdio: "pipe" }).toString();
    if (out.includes("every stated exact count matches its data file")) ok("every stated exact count matches its data file");
    else warn(`derived-literal findings (review, not blocking):\n${out}`);
  } catch (e) {
    warn(`check-derived-literals.mjs failed to run: ${e.message}`);
  }
}

// ── 16. Manifest V3 compliance (v3.4.0) ─────────────────────────────────────
// HARD gate — delegates to tools/check-mv3.mjs (see that file's header for
// the rule list). Exit 0 = compliant, 1 = findings (FAIL, listed), anything
// else = the check itself could not run, which also FAILS: a compliance
// gate that silently did not run must never read as a pass (C38).
const MV3_EXIT_FINDINGS = 1;
function checkMv3() {
  console.log("\n── 16. Manifest V3 compliance ──");
  const script = path.join(TOOLS_ROOT, "check-mv3.mjs");
  if (!existsSync(script)) { fail("check-mv3.mjs not found — MV3 compliance not checked"); return; }
  try {
    const out = execFileSync(process.execPath, [script, "--ext", EXT_ROOT], { cwd: TOOLS_ROOT, stdio: "pipe" }).toString();
    ok(out.trim());
  } catch (e) {
    const out = (e.stdout || "").toString() + (e.stderr || "").toString();
    if (e.status === MV3_EXIT_FINDINGS) fail(`MV3 compliance findings:\n${out}`);
    else fail(`check-mv3.mjs could not run: ${out || e.message}`);
  }
}

// ── 17. False-positive sweep (v3.4.0) ──────────────────────────────────────
// HARD gate — delegates to tools/fp-sweep.mjs. Its header always called it
// a hard gate, but nothing ran it (C38: a check that did not run). Exit 0 =
// pass; anything else = FAIL (regression, a knownGood entry at Suspicious or
// worse, a scenario variant at Malicious, or the sweep could not run).
function checkFpSweep() {
  console.log("\n── 17. False-positive sweep ──");
  const script = path.join(TOOLS_ROOT, "fp-sweep.mjs");
  if (!existsSync(script)) { fail("fp-sweep.mjs not found — false-positive sweep not run"); return; }
  try {
    const out = execFileSync(process.execPath, [script], { cwd: TOOLS_ROOT, stdio: "pipe" }).toString();
    const verdict = out.trim().split("\n").pop().replace(/^✓\s*/, "");
    ok(verdict);
  } catch (e) {
    fail(`fp-sweep failed:\n${(e.stdout || "").toString()}${(e.stderr || "").toString() || e.message}`);
  }
}

// ── Run ──────────────────────────────────────────────────────────────────────
checkSyntax();
checkLint();
const { manifest, pkg } = checkJson();
checkFileReferences(manifest);
checkMessageRouting();
checkUnitTests();
checkCircularDeps();
checkUnusedCode();
checkUnusedDeps();
checkDuplicateCode();
checkVersionSync(manifest, pkg);
checkListFreshness();
checkMagicNumbers();
checkCompatRemove();
checkDerivedLiterals();
checkMv3();
checkFpSweep();

console.log();
if (failed) {
  console.log("✗ complete-check FAILED — see above");
  process.exit(1);
} else {
  console.log("✓ complete-check passed");
}
