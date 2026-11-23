"use strict";

/**
 * DangerousExts.js — Single source of truth for file-extension classification.
 *
 * Previously DANGEROUS_EXTS and ARCHIVE_EXTS lived only in background.js as
 * local consts (not duplicated elsewhere, but not centralized either — any
 * other module needing them would have had to copy them, exactly the
 * situation ScriptExts.js already solves for script extensions).
 *
 * Also fixes a normalization bug: the previous ARCHIVE_EXTS array contained
 * "Z" and "tar.Z" (uppercase) alongside otherwise-lowercase entries. Every
 * consumer compares against an already-lowercased filename, so the uppercase
 * entries could never match — a silent dead entry. Now lowercase throughout.
 *
 * All collections are exposed as both `.set` (Set<string>, O(1) lookups,
 * normalized lowercase, no leading dot) and `.list` (string[]) for callers
 * that need array semantics (e.g. spreading into another list).
 *
 * To add a new extension: add it here only. All checks pick it up
 * automatically on the next load.
 */
export const DangerousExts = (function () {

    // ── Extensions that indicate an executable or script payload ───────────────
    const dangerousList = [
        "bat","chm","cmd","com","cpl","dll","exe","hta",
        "jse","js","lnk","msc","msi","msp","mst",
        "pif","ps1","ps1xml","ps2","ps2xml","psc1",
        "psc2","scr","vb","vbe","vbs","wsf","wsh",
        "appimage","awk","bash","bin","csh","deb",
        "ksh","out","php","pl","pm","py","pyc",
        "pyo","rb","rpm","run","sed","sh","tcl",
        "tcsh","zsh","elf","jnlp",
        "action","app","applescript","command",
        "mpkg","pkg","scpt","tool","workflow",
        // DS-H001 — Linux .desktop launcher files: a .desktop file can define
        // an Exec= line that runs an arbitrary shell command when opened.
        "desktop",
        // Heuristics plan Step 2b (v2.8.0) — first-stage "staging" formats
        // used to bypass Windows' Mark-of-the-Web warning or launch the next
        // stage (Excel add-in, settings/search/library shortcuts, OneNote,
        // ClickOnce, legacy Office query/macro formats, a diagnostics
        // package). Added here (rather than left unmonitored) per the
        // explicit "widen DangerousExts" decision made alongside v2.8.0 —
        // see CHANGELOG. This is what makes
        // StagingCheck.checkFormat()'s HIGH/MED tiers reachable at all; none
        // of these overlap ScriptExts.js's set (lnk/hta/wsf/chm/msc), so
        // there is no double-count with SCRIPT_FORMAT_SCORE.
        "xll","settingcontent-ms","one","onepkg",
        "url","iqy","slk","library-ms","search-ms",
        "appref-ms","application","diagcab",
    ];

    // ── Archive / disk-image extensions ─────────────────────────────────────────
    // Includes both simple extensions and compound ones (e.g. "tar.gz") — the
    // compound entries are matched as a two-label suffix by getExtFromFilename
    // in background.js before falling back to the single-label check.
    const archiveList = [
        "zip","rar","7z","tar","iso","cab",
        "tar.gz","tar.bz2","tar.xz","tar.zst","tar.lz",
        "tar.lzma","tar.lzo","tar.z","tar.sz",
        "gz","tgz",
        "bz2","tbz","tbz2",
        "xz","txz",
        "zst","tzst",
        "lz","lzma","lzo","lz4","lz5",
        "z",                                    // fixed: was "Z" (never matched)
        "msix","msixbundle","appx","appxbundle","wim","swm",
        "img","dmg","vhd","vhdx","vmdk",
        "jar","war","ear","apk","ipa","xpi","crx",
        "ace","arc","arj","lha","lzh","sit","sitx","sea",
        "paq","pak","pk3","pk4","wad",
    ];

    // ── DS-H003 — Believable decoy extensions ───────────────────────────────────
    // Curated categories of extensions that a real, legitimate file might end
    // in — used to recognise "invoice.pdf.exe"-style deceptive chains where a
    // dangerous final extension is preceded by something that looks safe.
    // Deliberately NOT "anything that isn't dangerous/archive" (that heuristic
    // false-positives on things like "library.min.js", where "min" isn't a
    // real decoy extension at all — see acceptance criteria).
    const decoyDocuments = ["pdf","doc","docx","xls","xlsx","ppt","pptx","txt","rtf","odt","ods","odp","csv"];
    const decoyImages     = ["jpg","jpeg","png","gif","bmp","webp","svg","tif","tiff","heic","ico"];
    const decoyMedia      = ["mp3","wav","flac","aac","ogg","wma","mp4","avi","mov","mkv","wmv","flv","webm","m4a","m4v"];
    const decoyArchives   = ["zip","rar","7z","tar","iso","cab","dmg","gz","bz2","xz","tgz"];
    const decoyPackages   = ["deb","rpm","msi","apk","ipa","appx","msix","pkg"];

    const decoyList = [
        ...decoyDocuments, ...decoyImages, ...decoyMedia, ...decoyArchives, ...decoyPackages,
    ];

    function toSet(list) { return new Set(list); }

    return {
        DANGEROUS: { list: dangerousList, set: toSet(dangerousList) },
        ARCHIVE:   { list: archiveList,   set: toSet(archiveList) },
        DECOY: {
            list: decoyList,
            set:  toSet(decoyList),
            // Sub-categories exposed for messages/future use (e.g. "the decoy
            // looked like a document") — each also a normalized Set.
            documents: toSet(decoyDocuments),
            images:    toSet(decoyImages),
            media:     toSet(decoyMedia),
            archives:  toSet(decoyArchives),
            packages:  toSet(decoyPackages),
        },
    };
})();
