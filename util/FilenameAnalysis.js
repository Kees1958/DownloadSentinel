"use strict";

/**
 * FilenameAnalysis.js — Pure filename/extension analysis helpers.
 *
 * Extracted from background.js (Chapter 2 / C1 — one module, one
 * responsibility) so this logic can be unit-tested directly, without a
 * chrome.* mock: every function here is a pure function of its arguments,
 * with no chrome API access and no shared mutable state.
 *
 * background.js still keeps its own local DANGEROUS_EXTS/ARCHIVE_EXTS/
 * SCRIPT_EXTS consts (used elsewhere in onCreated/onChanged) — both this
 * module and background.js derive them independently from the same
 * canonical source (DangerousExts.js / ScriptExts.js), so there is no risk
 * of the two ever drifting apart.
 *
 * No behavior change from the pre-extraction versions in background.js —
 * see CHANGELOG for the audit pass that moved this code.
 *
 * Public interface:
 *   FilenameAnalysis.getExtFromFilename(file)
 *   FilenameAnalysis.getRawExt(filename)
 *   FilenameAnalysis.extractFilenameFromUrl(url)
 *   FilenameAnalysis.getDoubleExtension(filename)
 *   FilenameAnalysis.getBlockedExtension(url, filename)
 *   FilenameAnalysis.getExtCategory(ext)
 *   FilenameAnalysis.getObfuscationSignal(originalExt, confirmedExt)
 *   FilenameAnalysis.getVisibleExt(filename)              v3.4.0
 *   FilenameAnalysis.findVisibleExt(url, rawUrl, filename) v3.4.0
 *   FilenameAnalysis.classifyDownload(url, rawUrl, filename, rawMime)
 *   FilenameAnalysis.FILE_TYPE   {Object} frozen enum of classifyDownload()'s fileType values
 */
import { DangerousExts } from "./DangerousExts.js";
import { ScriptExts } from "./ScriptExts.js";
import { DangerousMimes } from "./DangerousMimes.js";

export const FilenameAnalysis = (function () {

    const DANGEROUS_EXTS = DangerousExts.DANGEROUS.set;
    const ARCHIVE_EXTS   = DangerousExts.ARCHIVE.set;
    const DECOY_EXTS     = DangerousExts.DECOY.set;

    // ── File-type enum (v3.4.0) ──────────────────────────────────────────────
    // Single source of truth for classifyDownload()'s `fileType` values —
    // previously two string literals in that function. Never compare against
    // raw strings elsewhere; use FilenameAnalysis.FILE_TYPE.*.
    //   EXECUTABLE     dangerous extension, or an executable MIME type
    //   ARCHIVE        archive/disk-image extension, or (R4) an archive MIME
    //                  type behind a harmless-looking extension
    //   UNKNOWN_BINARY (R1) no extension anywhere + a generic binary MIME
    //                  type (DangerousMimes.GENERIC_BINARY_MIMES) — the
    //                  server hides what the file is
    const FILE_TYPE = Object.freeze({
        EXECUTABLE:     "executable",
        ARCHIVE:        "archive",
        UNKNOWN_BINARY: "unknown-binary",
    });

    // ── What counts as a visible extension (v3.4.0, R1/R4) ──────────────────
    // The text after the last dot only counts as a file extension when it
    // LOOKS like one: 1–10 lowercase letters/digits with at least one letter.
    // So "report.pdf", "data.json", "setup.exe" have one; "6962f1be0c" (no
    // dot), "tool-v1.2" ("2" — a version number) and
    // "rg-14.1.0-x86_64-linux" ("0-x86_64-linux" — has dashes) do not.
    const VISIBLE_EXT_PATTERN = /^(?=[a-z0-9]*[a-z])[a-z0-9]{1,10}$/;

    function getExtFromFilename(file) {
        const parts   = file.split(".");
        if (parts.length < 2) return null;
        const lastTwo = parts.slice(-2).join(".");
        const lastOne = parts[parts.length - 1];
        if (ARCHIVE_EXTS.has(lastTwo))   return lastTwo;
        if (DANGEROUS_EXTS.has(lastOne)) return lastOne;
        if (ARCHIVE_EXTS.has(lastOne))   return lastOne;
        return null;
    }

    // Lightweight, unfiltered "what's the last extension segment" helper — unlike
    // getExtFromFilename (which only returns dangerous/archive extensions, by
    // design, since it gates what gets monitored), this returns ANY extension so
    // it can be used purely for category comparison (see getExtCategory /
    // getObfuscationSignal — DS-H007). Never used to decide whether to monitor a
    // download, only to describe what category a filename's extension implies.
    function getRawExt(filename) {
        if (!filename) return null;
        const base  = filename.toLowerCase().split("/").pop().split("\\").pop();
        const parts = base.split(".");
        return parts.length > 1 ? parts[parts.length - 1] : null;
    }

    function extractFilenameFromUrl(url) {
        try {
            const path  = new URL(url).pathname;
            const parts = path.split("/");
            const last  = parts[parts.length - 1];
            return last.includes(".") ? decodeURIComponent(last) : null;
        } catch { return null; }
    }

    // ── Deceptive extension chain detector (DS-H003) ────────────────────────────
    // Detects filenames where a dangerous extension is hidden behind one or more
    // decoy extensions anywhere earlier in the chain — not just the immediately
    // preceding label. Examples: "invoice.pdf.exe", "invoice.pdf.zip.exe",
    // "document.pdf...desktop".
    //
    // Returns { decoy, dangerous, repeatedDots } or null if no deceptive chain
    // is found. Only triggers when the FINAL extension is dangerous; standard
    // compound formats (tar.gz, package-1.2.3.deb, library.min.js) must not
    // trigger — see the curated DECOY_EXTS set in util/DangerousExts.js, which
    // replaces the old "decoy = anything not dangerous/archive" heuristic that
    // false-positived on things like "library.min.js" ("min" was never a real
    // decoy extension).
    function getDoubleExtension(filename) {
        if (!filename) return null;
        const base  = filename.toLowerCase().split("/").pop().split("\\").pop();
        const parts = base.split(".");
        // Need at least three parts: name + at least one decoy + dangerous
        if (parts.length < 3) return null;

        const dangerous = parts[parts.length - 1];
        if (!DANGEROUS_EXTS.has(dangerous)) return null;

        // Preceding segments — everything between the basename and the final
        // (dangerous) extension. May contain empty entries from repeated dots
        // (e.g. "document.pdf...desktop" → ["document","pdf","","","desktop"]).
        const precedingSegments = parts.slice(1, -1);
        const repeatedDots      = precedingSegments.some(seg => seg.length === 0);

        // Find the first believable decoy among the preceding segments, scanning
        // from the one closest to the dangerous extension outward — that's the
        // one doing the actual visual deception (e.g. in "invoice.pdf.zip.exe"
        // either "pdf" or "zip" is a valid decoy; either is a correct answer).
        let decoy = null;
        for (let i = precedingSegments.length - 1; i >= 0; i--) {
            const seg = precedingSegments[i];
            if (seg && DECOY_EXTS.has(seg)) { decoy = seg; break; }
        }
        if (!decoy) return null; // no recognizable decoy — likely a legitimate compound extension

        return { decoy: "." + decoy, dangerous, repeatedDots };
    }

    function getBlockedExtension(url, filename) {
        if (filename) {
            const ext = getExtFromFilename(filename.toLowerCase());
            if (ext) return ext;
        }
        if (url) {
            const fromUrl = extractFilenameFromUrl(url);
            if (fromUrl) {
                const ext = getExtFromFilename(fromUrl.toLowerCase());
                if (ext) return ext;
            }
        }
        return null;
    }

    // ── Extension category classifier ─────────────────────────────────────────────
    // Maps a file extension to its risk category string.
    // Used to detect category changes between onCreated and onChanged (DS-H007).
    //   "launcher"    — .desktop
    //   "script"      — ScriptExts (checked before "executable" so interpreted
    //                   scripts get their own category rather than the generic
    //                   executable bucket)
    //   "executable"  — remaining DANGEROUS_EXTS (exe, dll, msi, scr, ...)
    //   "archive"     — ARCHIVE_EXTS
    //   "document"/"image"/"audio-video" — DangerousExts.DECOY sub-categories;
    //                   these are informational categories only, never monitored
    //                   at download-creation time on their own
    //   "none"        — not a recognized extension in any of the above
    function getExtCategory(ext) {
        if (!ext) return "none";
        if (ext === "desktop")        return "launcher";
        if (ScriptExts.set.has(ext))  return "script";
        if (DANGEROUS_EXTS.has(ext))  return "executable";
        if (ARCHIVE_EXTS.has(ext))    return "archive";
        if (DangerousExts.DECOY.documents.has(ext)) return "document";
        if (DangerousExts.DECOY.images.has(ext))    return "image";
        if (DangerousExts.DECOY.media.has(ext))     return "audio-video";
        return "none";
    }

    // ── Obfuscation signal builder ────────────────────────────────────────────────
    // Compares the extension known at onCreated time with the confirmed extension
    // from onChanged and returns an obfuscation descriptor, or null if clean.
    //
    //   UNKNOWN_REVEALED  : no extension at creation → dangerous ext confirmed
    //   CATEGORY_CHANGED  : extension known but switched risk category
    //   null              : no obfuscation (same category, or no change)
    function getObfuscationSignal(originalExt, confirmedExt) {
        if (!confirmedExt) return null; // still no ext — nothing to report

        const fromCategory = getExtCategory(originalExt);
        const toCategory   = getExtCategory(confirmedExt);

        if (toCategory === "none") return null; // confirmed ext is not dangerous

        if (!originalExt || fromCategory === "none") {
            // Extension was completely hidden at creation time
            return {
                type:         "UNKNOWN_REVEALED",
                confirmedExt,
                fromCategory: "none",
                toCategory
            };
        }

        if (fromCategory !== toCategory) {
            // Extension was known but changed risk category
            return {
                type:         "CATEGORY_CHANGED",
                originalExt,
                confirmedExt,
                fromCategory,
                toCategory
            };
        }

        return null; // same category — no obfuscation penalty
    }

    // ── Visible extension (v3.4.0) ──────────────────────────────────────────────
    // getRawExt() filtered through VISIBLE_EXT_PATTERN — "does this name show
    // a real-looking extension at all?", whatever its risk category.
    function getVisibleExt(filename) {
        const raw = getRawExt(filename);
        return raw && VISIBLE_EXT_PATTERN.test(raw) ? raw : null;
    }

    // First visible extension found in: the filename Chrome reports, then the
    // final URL's last path segment, then the original URL's. null = the
    // download shows no extension anywhere (heuristic R1's precondition).
    function findVisibleExt(url, rawUrl, filename) {
        return getVisibleExt(filename)
            || getVisibleExt(extractFilenameFromUrl(url || "") || "")
            || getVisibleExt(extractFilenameFromUrl(rawUrl || "") || "");
    }

    // True when the MIME table lists `ext` for `mime` — "name and type agree".
    function mimeAllowsExt(mime, ext) {
        const exts = DangerousMimes.MIME_TO_EXTS[mime];
        return !!(exts && exts.includes(ext));
    }

    // ── Combined download classifier ────────────────────────────────────────────
    // Extracted from background.js, where this exact 7-line sequence (ext →
    // isArchive/isDangerous/mime/isMimeExec → "is this even monitored?" guard
    // → fileType/isScript/isLinuxLauncher) was duplicated verbatim between the
    // onCreated listener and the onChanged late-entry path (jscpd-flagged
    // duplicate, audit pass). No behavior change: same inputs, same checks,
    // same guard — just called from one place now.
    //
    // Returns null when the file isn't a monitored type at all — callers
    // should treat that the same way the old inline `if (...) return;` guard
    // did. Monitored (v3.4.0 adds the last two):
    //   isDangerous     dangerous extension                 → EXECUTABLE
    //   isArchive       archive extension                   → ARCHIVE
    //   isMimeExec      executable MIME type                → EXECUTABLE
    //   isMimeArchive   (R4) archive MIME type, but the visible extension
    //                   is something the MIME table does not list for it
    //                   (e.g. "invoice.pdf" served as application/zip)
    //                                                       → ARCHIVE
    //   isUnknownBinary (R1) no visible extension anywhere AND a generic
    //                   binary MIME type                    → UNKNOWN_BINARY
    // visibleExt is returned for MimeCheck: the dangerous-only `ext` is null
    // for "invoice.pdf", so the name/type mismatch (R4) needs the visible one.
    // A still-empty MIME (common at onCreated) never triggers R1 — the
    // onChanged late-entry path re-classifies once Chrome knows the type.
    function classifyDownload(url, rawUrl, filename, rawMime) {
        const ext = getBlockedExtension(url, filename || "") || getBlockedExtension(rawUrl || "", "");
        const visibleExt  = findVisibleExt(url, rawUrl, filename);
        const isArchive   = !!(ext && ARCHIVE_EXTS.has(ext));
        const isDangerous = !!(ext && DANGEROUS_EXTS.has(ext));
        const mime        = DangerousMimes.normalize(rawMime);
        const extMonitored = isDangerous || isArchive;
        const isMimeExec  = !extMonitored && DangerousMimes.EXECUTABLE_MIMES.has(mime);
        const isMimeArchive = !extMonitored && !isMimeExec && !!visibleExt
            && DangerousMimes.ARCHIVE_MIMES.has(mime) && !mimeAllowsExt(mime, visibleExt);
        const isUnknownBinary = !extMonitored && !visibleExt
            && DangerousMimes.GENERIC_BINARY_MIMES.has(mime);

        if (!extMonitored && !isMimeExec && !isMimeArchive && !isUnknownBinary) return null; // not a monitored file type

        let fileType = FILE_TYPE.ARCHIVE;
        if (isDangerous || isMimeExec) fileType = FILE_TYPE.EXECUTABLE;
        else if (isUnknownBinary)      fileType = FILE_TYPE.UNKNOWN_BINARY;

        return {
            ext,
            visibleExt,
            isArchive,
            isDangerous,
            mime,
            isMimeExec,
            isMimeArchive,
            isUnknownBinary,
            fileType,
            isScript:        ScriptExts.set.has(ext),
            isLinuxLauncher: ext === "desktop" // DS-H001
        };
    }

    return {
        getExtFromFilename,
        getRawExt,
        extractFilenameFromUrl,
        getDoubleExtension,
        getBlockedExtension,
        getExtCategory,
        getObfuscationSignal,
        getVisibleExt,
        findVisibleExt,
        classifyDownload,
        FILE_TYPE
    };
})();
