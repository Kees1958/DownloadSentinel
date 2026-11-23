"use strict";

// v3.5.5 — list snapshot rule (3P Matrix 4.5.4 parity: `sameSnapshotAs`), tools/source-snapshots.mjs +
// tools/check-list-freshness.mjs. Replays the real 3.5.1 gap in a throw-away copy of the tools: the cached
// public_suffix_list.dat is refreshed but the lists are not rebuilt → the check must FAIL (exit 1) and name BOTH
// lists built from that file; after recording again it passes. The real tools/ tree is never modified.

import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, cpSync, appendFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const TOOLS_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
// v3.6.0 layout: the copy is <tmp>/tools/ holding the scripts, the register, the raw lists and package.json (the
// marker tools/repoPaths.mjs walks up to).
const COPIED = Object.freeze(["repoPaths.mjs", "source-snapshots.mjs", "check-list-freshness.mjs", "data-sources.json", "package.json"]);
const PSL_RAW = "public_suffix_list.dat";
const PSL_SOURCES = Object.freeze(["Public Suffix List", "Public Suffix List — PRIVATE section (hosting-platform suffixes)"]);
const PSL_FEEDS = Object.freeze(["data/PublicSuffixList.json", "data/PlatformSuffixes.json"]);
const EXIT = Object.freeze({ OK: 0, SNAPSHOT_MISMATCH: 1 });

let tmp;                                       // guard: created in before(), always removed in after()
const runCheck = () => spawnSync(process.execPath, [path.join(tmp, "tools", "check-list-freshness.mjs")], { encoding: "utf8" });

describe("list snapshot rule (v3.5.5)", () => {
    before(() => {
        tmp = mkdtempSync(path.join(tmpdir(), "ds-snapshots-"));
        mkdirSync(path.join(tmp, "tools"));
        for (const f of COPIED) cpSync(path.join(TOOLS_ROOT, f), path.join(tmp, "tools", f));
        cpSync(path.join(TOOLS_ROOT, "lists-raw"), path.join(tmp, "tools", "lists-raw"), { recursive: true });
    });
    after(() => { if (tmp) rmSync(tmp, { recursive: true, force: true }); });

    test("the shipped register passes (every list built from the cached snapshot)", () => {
        const r = runCheck();
        assert.equal(r.status, EXIT.OK, r.stdout + r.stderr);
    });
    test("raw file refreshed, lists not rebuilt → FAIL naming both lists built from it", () => {
        appendFileSync(path.join(tmp, "tools", "lists-raw", PSL_RAW), "\n// refreshed upstream\n");
        const r = runCheck();
        assert.equal(r.status, EXIT.SNAPSHOT_MISMATCH);
        assert.match(r.stdout, /SNAPSHOT MISMATCH/);
        for (const name of PSL_SOURCES) assert.ok(r.stdout.includes(`${name}: built from`), name);
    });
    test("after the lists are rebuilt (snapshot recorded again) → passes", async () => {
        const mod = await import(pathToFileURL(path.join(tmp, "tools", "source-snapshots.mjs")).href);
        for (const feed of PSL_FEEDS) mod.recordBuiltFrom(feed);
        const r = runCheck();
        assert.equal(r.status, EXIT.OK, r.stdout);
        const reg = JSON.parse(readFileSync(path.join(tmp, "tools", "data-sources.json"), "utf8"));
        const snaps = new Set(reg.sources.filter(s => PSL_SOURCES.includes(s.name)).map(s => s.builtFromSnapshot));
        assert.equal(snaps.size, 1, "both lists from one raw file carry one snapshot");
    });
    test("snapshotId is deterministic and content-sensitive", async () => {
        const { snapshotId } = await import(pathToFileURL(path.join(TOOLS_ROOT, "source-snapshots.mjs")).href);
        assert.equal(snapshotId(Buffer.from("a")), snapshotId(Buffer.from("a")));
        assert.notEqual(snapshotId(Buffer.from("a")), snapshotId(Buffer.from("b")));
    });
});
