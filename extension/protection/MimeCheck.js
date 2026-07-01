"use strict";

/**
 * MimeCheck.js
 *
 * Checks whether a file's extension is consistent with its declared MIME type,
 * and whether the file size exceeds VirusTotal's maximum upload limit.
 *
 * MIME consistency:
 *   - "application/octet-stream" is treated as neutral (too common, server laziness)
 *   - A genuine mismatch (e.g. .exe served as image/jpeg) scores -60
 *   - A match scores 0 (reported as informational)
 *
 * File size:
 *   - Exceeds 650 MB → -20 (VT will skip scanning; antivirus evasion technique)
 */
const MimeCheck = (function () {

    const VT_MAX_BYTES = 650 * 1024 * 1024; // 650 MB

    // Map of MIME type → accepted extensions (lowercase, no dot)
    // Covers the file types DownloadSentinel intercepts (executables + archives)
    const MIME_TO_EXTS = {
        // Executables
        "application/x-msdownload":          ["exe", "dll", "com"],
        "application/x-msdos-program":       ["exe", "com"],
        "application/vnd.microsoft.portable-executable": ["exe", "dll"],
        "application/x-executable":          ["exe", "out", "bin"],
        "application/x-dosexec":             ["exe", "com"],
        "application/x-bat":                 ["bat"],
        "application/x-msi":                 ["msi"],
        "application/x-ms-installer":        ["msi", "msp"],
        "application/x-powershell":          ["ps1", "ps1xml", "ps2", "ps2xml", "psc1", "psc2"],
        "text/x-powershell":                 ["ps1"],
        "application/x-sh":                  ["sh", "bash", "ksh", "csh"],
        "text/x-sh":                         ["sh", "bash"],
        "application/x-python":              ["py", "pyc"],
        "text/x-python":                     ["py"],
        "application/x-perl":                ["pl", "pm"],
        "text/x-perl":                       ["pl"],
        "application/x-php":                 ["php"],
        "text/x-php":                        ["php"],
        "application/x-vbs":                 ["vbs", "vbe", "vb"],
        "text/vbscript":                     ["vbs", "vbe"],
        "application/x-javascript":          ["js"],
        "text/javascript":                   ["js"],
        "application/java-archive":          ["jar"],
        "application/x-java-archive":        ["jar"],
        "application/x-debian-package":      ["deb"],
        "application/x-rpm":                 ["rpm"],
        "application/x-appimage":            ["appimage"],
        "application/x-hta":                 ["hta"],
        "application/x-ms-shortcut":         ["lnk"],
        "application/x-mscf":               ["chm"],
        "application/x-java-vm":             ["class"],

        // Archives
        "application/zip":                   ["zip"],
        "application/x-zip-compressed":      ["zip"],
        "application/x-zip":                 ["zip"],
        "application/x-rar-compressed":      ["rar"],
        "application/vnd.rar":               ["rar"],
        "application/x-7z-compressed":       ["7z"],
        "application/x-tar":                 ["tar"],
        "application/gzip":                  ["gz", "tar"],
        "application/x-gzip":               ["gz", "tar"],
        "application/x-bzip2":              ["bz2", "tar"],
        "application/x-xz":                 ["xz", "tar"],
        "application/x-lzma":               ["lzma"],
        "application/x-lzip":               ["lz"],
        "application/x-compress":           ["z"],
        "application/x-iso9660-image":      ["iso"],
        "application/x-apple-diskimage":    ["dmg"],
        "application/x-cab-compressed":     ["cab"],
        "application/vnd.ms-cab-compressed":["cab"],

        // Documents sometimes abused as malware carriers
        "application/pdf":                   ["pdf"],
        "application/msword":                ["doc"],
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ["docx"],
        "application/vnd.ms-excel":          ["xls"],
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ["xlsx"],
        "application/vnd.ms-powerpoint":     ["ppt"],
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": ["pptx"],

        // Text / script types (often misused)
        "text/plain":                        ["txt", "log", "csv", "ini", "cfg", "conf"],
        "text/html":                         ["html", "htm"],
        "text/xml":                          ["xml"],
        "application/xml":                   ["xml"],
        "application/json":                  ["json"],

        // Images (should never be executables)
        "image/jpeg":                        ["jpg", "jpeg"],
        "image/png":                         ["png"],
        "image/gif":                         ["gif"],
        "image/bmp":                         ["bmp"],
        "image/webp":                        ["webp"],
        "image/svg+xml":                     ["svg"],

        // Audio / Video (should never be executables)
        "audio/mpeg":                        ["mp3"],
        "audio/wav":                         ["wav"],
        "video/mp4":                         ["mp4"],
        "video/x-msvideo":                   ["avi"],
    };

    // Build reverse map: ext → set of allowed MIME types
    const EXT_TO_MIMES = {};
    for (const [mime, exts] of Object.entries(MIME_TO_EXTS)) {
        for (const ext of exts) {
            if (!EXT_TO_MIMES[ext]) EXT_TO_MIMES[ext] = new Set();
            EXT_TO_MIMES[ext].add(mime);
        }
    }

    /**
     * Check MIME type consistency with the file extension.
     *
     * @param {string} ext       - file extension without dot, lowercase (e.g. "exe")
     * @param {string} mimeType  - MIME type from Content-Type header (e.g. "image/jpeg")
     * @returns {{ consistent: boolean|null, neutral: boolean, label: string, score: number }}
     */
    function checkMime(ext, mimeType) {
        if (!ext || !mimeType) {
            return { consistent: null, neutral: true,
                     label: "MIME type unavailable", score: 0 };
        }

        // Normalise — strip parameters like "; charset=utf-8"
        const mime = mimeType.split(";")[0].trim().toLowerCase();

        // application/octet-stream is a generic fallback — treat as neutral
        if (mime === "application/octet-stream" || mime === "binary/octet-stream") {
            return { consistent: null, neutral: true,
                     label: "MIME type is generic (application/octet-stream)", score: 0 };
        }

        const allowedMimes = EXT_TO_MIMES[ext];

        // Extension not in our map — can't evaluate
        if (!allowedMimes) {
            return { consistent: null, neutral: true,
                     label: `MIME type not evaluated for .${ext}`, score: 0 };
        }

        if (allowedMimes.has(mime)) {
            return { consistent: true, neutral: false,
                     label: `File extension ".${ext}" is consistent with MIME type "${mime}"`,
                     score: 0 };
        }

        // True mismatch
        return { consistent: false, neutral: false,
                 ext, mime,
                 label: `File extension ".${ext}" does not match MIME type "${mime}"`,
                 score: -60 };
    }

    /**
     * Check whether file size exceeds VirusTotal's maximum upload size (650 MB).
     *
     * @param {number|null} totalBytes
     * @returns {{ exceeds: boolean, label: string, score: number }}
     */
    function checkSize(totalBytes) {
        if (!totalBytes || totalBytes <= 0) {
            return { exceeds: false, label: "File size unknown", score: 0 };
        }
        if (totalBytes > VT_MAX_BYTES) {
            const mb = (totalBytes / (1024 * 1024)).toFixed(1);
            return { exceeds: true,
                     label: `File size ${mb} MB exceeds VirusTotal maximum (650 MB) — antivirus scan may be skipped`,
                     score: -20 };
        }
        return { exceeds: false, label: `File size within VirusTotal limit`, score: 0 };
    }

    return { checkMime, checkSize, VT_MAX_BYTES };

})();
