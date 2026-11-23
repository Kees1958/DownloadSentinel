"use strict";

// ── tools/source-snapshots.mjs ───────────────────────────────────────────────
// v3.5.5 (3P Matrix 4.5.4 parity — its list-modules.mjs snapshotId()/recordList() and check-list-freshness.mjs
// `sameSnapshotAs`): which snapshot of a cached raw file was each generated list built from?
//
//   snapshotId(buf)          → "sha256:<12 hex>" — fingerprint of a raw file's bytes
//   currentSnapshot(source)  → fingerprint of the source's cached raw file now, or null when it has none / is missing
//   recordBuiltFrom(feed)    → called by a build tool right after it writes `feed` (e.g. "data/HostList.json"):
//                              every register source that feeds it and has a rawFile gets
//                              `builtFromSnapshot` = the fingerprint of the raw file it was just built from.
//
// tools/check-list-freshness.mjs fails when a source's builtFromSnapshot differs from its raw file now (raw file
// refreshed, list not rebuilt). Sources sharing one raw file (the Public Suffix List and its PRIVATE section) must
// therefore carry the same fingerprint — the 3P Matrix twin rule, without a separate pairing to maintain. The real
// case: DS 3.5.1 refreshed public_suffix_list.dat and rebuilt PlatformSuffixes, but not PublicSuffixList.
//
// One writer for the register field (this module); no tool writes it by hand.
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";

import { repoPaths } from "./repoPaths.mjs";

// ── Settings (one place) ─────────────────────────────────────────────────────
const { TOOLS_ROOT } = repoPaths(import.meta.url);
export const REGISTER_FILE = path.join(TOOLS_ROOT, "data-sources.json");
const RAW_BASE           = TOOLS_ROOT;   // register rawFile paths are relative to tools/
const SNAPSHOT_HASH      = "sha256";
const SNAPSHOT_ID_LENGTH = 12;                                // hex chars kept of the digest
const JSON_INDENT        = 2;

export function snapshotId(buf) {
    return `${SNAPSHOT_HASH}:${createHash(SNAPSHOT_HASH).update(buf).digest("hex").slice(0, SNAPSHOT_ID_LENGTH)}`;
}

export function rawPathOf(source) {
    return source.rawFile ? path.join(RAW_BASE, source.rawFile) : null;
}

export function currentSnapshot(source) {
    const p = rawPathOf(source);
    return p && existsSync(p) ? snapshotId(readFileSync(p)) : null;
}

export function recordBuiltFrom(feed) {
    const register = JSON.parse(readFileSync(REGISTER_FILE, "utf8"));
    const touched = [];
    for (const source of register.sources) {
        if (!Array.isArray(source.feeds) || !source.feeds.includes(feed)) continue;
        const snap = currentSnapshot(source);
        if (snap === null) continue;                        // hand-curated source, or no raw file: nothing to record
        source.builtFromSnapshot = snap;
        touched.push(`${source.name} → ${snap}`);
    }
    if (touched.length === 0) throw new Error(`recordBuiltFrom: no register source with a raw file feeds ${feed}`);
    writeFileSync(REGISTER_FILE, JSON.stringify(register, null, JSON_INDENT) + "\n", "utf8");
    for (const line of touched) console.log(`  snapshot recorded: ${line}`);
}
