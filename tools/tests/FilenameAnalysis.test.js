"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { FilenameAnalysis } from "../../util/FilenameAnalysis.js";

describe("FilenameAnalysis.getExtFromFilename", () => {
    test("matches a simple dangerous extension", () => {
        assert.equal(FilenameAnalysis.getExtFromFilename("setup.exe"), "exe");
    });
    test("matches a compound archive extension before the single-label fallback", () => {
        assert.equal(FilenameAnalysis.getExtFromFilename("backup.tar.gz"), "tar.gz");
    });
    test("returns null for a filename with no extension", () => {
        assert.equal(FilenameAnalysis.getExtFromFilename("README"), null);
    });
    test("returns null for a benign extension (not monitored)", () => {
        assert.equal(FilenameAnalysis.getExtFromFilename("photo.jpg"), null);
    });
});

describe("FilenameAnalysis.getRawExt", () => {
    test("returns any extension, including benign ones", () => {
        assert.equal(FilenameAnalysis.getRawExt("photo.JPG"), "jpg");
    });
    test("strips path separators (both slash styles)", () => {
        assert.equal(FilenameAnalysis.getRawExt("C:\\Users\\me\\file.exe"), "exe");
        assert.equal(FilenameAnalysis.getRawExt("/home/me/file.exe"), "exe");
    });
    test("returns null when there is no extension or no filename", () => {
        assert.equal(FilenameAnalysis.getRawExt("README"), null);
        assert.equal(FilenameAnalysis.getRawExt(""), null);
        assert.equal(FilenameAnalysis.getRawExt(null), null);
    });
});

describe("FilenameAnalysis.extractFilenameFromUrl", () => {
    test("extracts and decodes the final path segment", () => {
        assert.equal(FilenameAnalysis.extractFilenameFromUrl("https://example.com/path/my%20file.exe"), "my file.exe");
    });
    test("returns null when the last segment has no dot", () => {
        assert.equal(FilenameAnalysis.extractFilenameFromUrl("https://example.com/download"), null);
    });
    test("returns null for an unparseable URL", () => {
        assert.equal(FilenameAnalysis.extractFilenameFromUrl("not a url"), null);
    });
});

describe("FilenameAnalysis.getDoubleExtension", () => {
    test("detects a classic decoy chain (invoice.pdf.exe)", () => {
        const r = FilenameAnalysis.getDoubleExtension("invoice.pdf.exe");
        assert.ok(r);
        assert.equal(r.decoy, ".pdf");
        assert.equal(r.dangerous, "exe");
        assert.equal(r.repeatedDots, false);
    });
    test("picks the decoy closest to the dangerous extension in a longer chain", () => {
        const r = FilenameAnalysis.getDoubleExtension("invoice.pdf.zip.exe");
        assert.ok(r);
        assert.equal(r.decoy, ".zip");
    });
    test("flags repeated/empty segments", () => {
        const r = FilenameAnalysis.getDoubleExtension("document.pdf...desktop");
        assert.ok(r);
        assert.equal(r.repeatedDots, true);
    });
    test("does not flag a legitimate compound extension (tar.gz)", () => {
        assert.equal(FilenameAnalysis.getDoubleExtension("backup.tar.gz"), null);
    });
    test("does not false-positive on library.min.js ('min' is not a decoy)", () => {
        assert.equal(FilenameAnalysis.getDoubleExtension("library.min.js"), null);
    });
    test("returns null when the final extension is not dangerous", () => {
        assert.equal(FilenameAnalysis.getDoubleExtension("invoice.pdf.txt"), null);
    });
    test("returns null for empty/falsy input", () => {
        assert.equal(FilenameAnalysis.getDoubleExtension(""), null);
        assert.equal(FilenameAnalysis.getDoubleExtension(null), null);
    });
});

describe("FilenameAnalysis.getBlockedExtension", () => {
    test("prefers the filename over the URL when both are present", () => {
        assert.equal(
            FilenameAnalysis.getBlockedExtension("https://example.com/other.txt", "setup.exe"),
            "exe"
        );
    });
    test("falls back to extracting from the URL when filename yields nothing", () => {
        assert.equal(
            FilenameAnalysis.getBlockedExtension("https://example.com/setup.exe", ""),
            "exe"
        );
    });
    test("returns null when neither source yields a monitored extension", () => {
        assert.equal(FilenameAnalysis.getBlockedExtension("https://example.com/photo.jpg", "photo.jpg"), null);
    });
});

describe("FilenameAnalysis.getExtCategory", () => {
    test("classifies each category correctly", () => {
        assert.equal(FilenameAnalysis.getExtCategory("desktop"), "launcher");
        assert.equal(FilenameAnalysis.getExtCategory("ps1"), "script");
        assert.equal(FilenameAnalysis.getExtCategory("exe"), "executable");
        assert.equal(FilenameAnalysis.getExtCategory("zip"), "archive");
        assert.equal(FilenameAnalysis.getExtCategory("pdf"), "document");
        assert.equal(FilenameAnalysis.getExtCategory("jpg"), "image");
        assert.equal(FilenameAnalysis.getExtCategory("mp3"), "audio-video");
        assert.equal(FilenameAnalysis.getExtCategory("xyz"), "none");
        assert.equal(FilenameAnalysis.getExtCategory(null), "none");
    });
    test("checks script before executable (both dangerous, script takes priority)", () => {
        // "js" is dangerous AND a script extension — must report "script"
        assert.equal(FilenameAnalysis.getExtCategory("js"), "script");
    });
});

describe("FilenameAnalysis.getObfuscationSignal", () => {
    test("UNKNOWN_REVEALED when no extension was visible at creation", () => {
        const r = FilenameAnalysis.getObfuscationSignal(null, "exe");
        assert.equal(r.type, "UNKNOWN_REVEALED");
        assert.equal(r.confirmedExt, "exe");
    });
    test("CATEGORY_CHANGED when the risk category switches", () => {
        const r = FilenameAnalysis.getObfuscationSignal("zip", "exe");
        assert.equal(r.type, "CATEGORY_CHANGED");
        assert.equal(r.fromCategory, "archive");
        assert.equal(r.toCategory, "executable");
    });
    test("null when the category is unchanged", () => {
        assert.equal(FilenameAnalysis.getObfuscationSignal("exe", "exe"), null);
    });
    test("null when the confirmed extension has no recognized category at all", () => {
        assert.equal(FilenameAnalysis.getObfuscationSignal(null, "xyz123"), null);
    });
    test("a recognized-but-benign confirmed category (e.g. image) still reports UNKNOWN_REVEALED", () => {
        // "jpg" is a recognized DECOY category ("image"), not toCategory === "none",
        // so hiding it counts as revealing a category, even a benign one.
        const r = FilenameAnalysis.getObfuscationSignal(null, "jpg");
        assert.equal(r.type, "UNKNOWN_REVEALED");
        assert.equal(r.toCategory, "image");
    });
    test("null when there is no confirmed extension at all", () => {
        assert.equal(FilenameAnalysis.getObfuscationSignal("exe", null), null);
    });
});

describe("FilenameAnalysis.classifyDownload", () => {
    test("classifies a plain executable", () => {
        const r = FilenameAnalysis.classifyDownload("https://example.com/setup.exe", "https://example.com/setup.exe", "setup.exe", "application/octet-stream");
        assert.ok(r);
        assert.equal(r.ext, "exe");
        assert.equal(r.isDangerous, true);
        assert.equal(r.isArchive, false);
        assert.equal(r.fileType, "executable");
        assert.equal(r.isScript, false);
        assert.equal(r.isLinuxLauncher, false);
    });

    test("classifies an archive", () => {
        const r = FilenameAnalysis.classifyDownload("https://example.com/backup.zip", "https://example.com/backup.zip", "backup.zip", "application/zip");
        assert.ok(r);
        assert.equal(r.isArchive, true);
        assert.equal(r.fileType, "archive");
    });

    test("classifies a script extension separately from generic executable", () => {
        const r = FilenameAnalysis.classifyDownload("https://example.com/install.ps1", "https://example.com/install.ps1", "install.ps1", "text/plain");
        assert.ok(r);
        assert.equal(r.isScript, true);
        assert.equal(r.fileType, "executable");
    });

    test("classifies a Linux .desktop launcher", () => {
        const r = FilenameAnalysis.classifyDownload("https://example.com/app.desktop", "https://example.com/app.desktop", "app.desktop", "application/x-desktop");
        assert.ok(r);
        assert.equal(r.isLinuxLauncher, true);
    });

    test("returns null for a benign, unmonitored file type", () => {
        const r = FilenameAnalysis.classifyDownload("https://example.com/photo.jpg", "https://example.com/photo.jpg", "photo.jpg", "image/jpeg");
        assert.equal(r, null);
    });

    test("an executable MIME with no recognizable extension is still caught (isMimeExec path)", () => {
        const r = FilenameAnalysis.classifyDownload("https://example.com/download", "https://example.com/download", "", "application/x-msdownload");
        assert.ok(r);
        assert.equal(r.isMimeExec, true);
        assert.equal(r.fileType, "executable");
    });

    test("falls back to the raw URL when the filename yields nothing", () => {
        const r = FilenameAnalysis.classifyDownload("https://example.com/redirect", "https://example.com/setup.exe", "", "application/octet-stream");
        assert.ok(r);
        assert.equal(r.ext, "exe");
    });
});
