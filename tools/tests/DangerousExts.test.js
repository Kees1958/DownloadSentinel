"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { DangerousExts } from "../../util/DangerousExts.js";

describe("DangerousExts.DANGEROUS", () => {
    test("contains known executable extensions", () => {
        for (const ext of ["exe", "dll", "msi", "scr", "ps1", "sh", "desktop"]) {
            assert.ok(DangerousExts.DANGEROUS.set.has(ext), `expected DANGEROUS to include "${ext}"`);
        }
    });
    test("does not contain common safe extensions", () => {
        for (const ext of ["pdf", "jpg", "mp3", "txt"]) {
            assert.ok(!DangerousExts.DANGEROUS.set.has(ext), `expected DANGEROUS to exclude "${ext}"`);
        }
    });
    test(".list and .set agree", () => {
        assert.equal(DangerousExts.DANGEROUS.list.length, DangerousExts.DANGEROUS.set.size);
    });
});

describe("DangerousExts.ARCHIVE", () => {
    test("contains normalized lowercase entries only (regression: was 'Z'/'tar.Z')", () => {
        assert.ok(DangerousExts.ARCHIVE.set.has("z"));
        assert.ok(DangerousExts.ARCHIVE.set.has("tar.z"));
        assert.ok(!DangerousExts.ARCHIVE.set.has("Z"));
        assert.ok(!DangerousExts.ARCHIVE.set.has("tar.Z"));
    });
    test("contains compound extensions for two-label matching", () => {
        assert.ok(DangerousExts.ARCHIVE.set.has("tar.gz"));
        assert.ok(DangerousExts.ARCHIVE.set.has("tar.bz2"));
    });
});

describe("DangerousExts.DECOY", () => {
    test("sub-categories are disjoint from each other's obvious members", () => {
        assert.ok(DangerousExts.DECOY.documents.has("pdf"));
        assert.ok(!DangerousExts.DECOY.images.has("pdf"));
        assert.ok(DangerousExts.DECOY.images.has("jpg"));
        assert.ok(!DangerousExts.DECOY.documents.has("jpg"));
    });
    test("does not flag 'min' as a decoy (library.min.js false-positive guard)", () => {
        assert.ok(!DangerousExts.DECOY.set.has("min"));
    });
    test("top-level DECOY set is the union of every sub-category", () => {
        for (const sub of [DangerousExts.DECOY.documents, DangerousExts.DECOY.images,
            DangerousExts.DECOY.media, DangerousExts.DECOY.archives, DangerousExts.DECOY.packages]) {
            for (const ext of sub) {
                assert.ok(DangerousExts.DECOY.set.has(ext), `expected top-level DECOY to include "${ext}"`);
            }
        }
    });
});
