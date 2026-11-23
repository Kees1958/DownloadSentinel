"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { DangerousMimes } from "../../util/DangerousMimes.js";
import { DangerousExts } from "../../util/DangerousExts.js";

describe("DangerousMimes.normalize", () => {
    test("strips parameters, trims, and lowercases", () => {
        assert.equal(DangerousMimes.normalize(" APPLICATION/OCTET-STREAM ; charset=utf-8"), "application/octet-stream");
    });
    test("handles missing/falsy input", () => {
        assert.equal(DangerousMimes.normalize(null), "");
        assert.equal(DangerousMimes.normalize(undefined), "");
        assert.equal(DangerousMimes.normalize(""), "");
    });
});

describe("DangerousMimes.EXECUTABLE_MIMES (derived set)", () => {
    test("includes MIMEs previously only recognised by MimeCheck (DS-H008 regression guard)", () => {
        // These were the drifted cases called out in the module header: MimeCheck
        // recognised them via MIME_TO_EXTS but background.js's old hand-maintained
        // EXECUTABLE_MIMES list did not.
        for (const mime of ["text/x-sh", "text/x-python", "text/vbscript", "application/x-ms-shortcut"]) {
            assert.ok(DangerousMimes.EXECUTABLE_MIMES.has(mime), `expected EXECUTABLE_MIMES to include "${mime}"`);
        }
    });
    test("does not include a purely document/image MIME", () => {
        assert.ok(!DangerousMimes.EXECUTABLE_MIMES.has("application/pdf"));
        assert.ok(!DangerousMimes.EXECUTABLE_MIMES.has("image/png"));
    });
    test("every entry maps to at least one DANGEROUS extension (derivation invariant)", () => {
        for (const mime of DangerousMimes.EXECUTABLE_MIMES) {
            const exts = DangerousMimes.MIME_TO_EXTS[mime];
            assert.ok(exts.some(ext => DangerousExts.DANGEROUS.set.has(ext)),
                `"${mime}" is in EXECUTABLE_MIMES but none of its exts are DANGEROUS`);
        }
    });
});
