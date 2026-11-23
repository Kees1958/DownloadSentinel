"use strict";

/**
 * DangerousMimes.js — Single source of truth for dangerous MIME definitions.
 *
 * DS-H008 — Previously there were two independently-maintained MIME
 * collections that had silently drifted apart:
 *   - background.js: EXECUTABLE_MIMES (gates whether a MIME-only signal is
 *     treated as executable at all)
 *   - MimeCheck.js:   MIME_TO_EXTS   (used for extension/MIME mismatch scoring)
 *
 * WARNING FOR IMPLEMENTATION IMPACT: the two lists did not actually agree —
 * MIME_TO_EXTS already recognised things like "text/x-sh", "text/x-python",
 * "text/vbscript" and "application/x-ms-shortcut" that EXECUTABLE_MIMES did
 * not. A file served with one of those MIME types and no recognised
 * extension previously passed through onCreated/onChanged entirely
 * unevaluated. Consolidating onto one map means those cases are now caught —
 * this widens (not narrows) what gets flagged; nothing that was previously
 * flagged stops being flagged.
 *
 * EXECUTABLE_MIMES is derived automatically from MIME_TO_EXTS (any MIME
 * whose mapped extensions include a DangerousExts.DANGEROUS entry) rather
 * than hand-maintained, so the two collections can never drift apart again.
 *
 * Public interface:
 *   DangerousMimes.MIME_TO_EXTS   {Object<string,string[]>} mime -> exts (no dot)
 *   DangerousMimes.EXECUTABLE_MIMES {Set<string>}  derived — see above
 *   DangerousMimes.ARCHIVE_MIMES    {Set<string>}  derived — v3.4.0, see below
 *   DangerousMimes.GENERIC_BINARY_MIMES {Set<string>} v3.4.0 — "unknown binary" labels
 *   DangerousMimes.normalize(mimeType) -> string    lowercase, params stripped, trimmed
 */
import { DangerousExts } from "./DangerousExts.js";

export const DangerousMimes = (function () {

    // v3.4.0 (heuristic R4) — file formats that are zip archives inside, so a
    // server sending them as application/zip is telling the truth, not
    // disguising anything. Without this list R4 ("visible extension vs MIME
    // type") flagged e.g. a PyPI wheel or a Word document served as zip —
    // caught by fp-sweep's knownGood corpus (requests-…-none-any.whl).
    //   Office Open XML: docx docm xlsx xlsm pptx pptm   OpenDocument: odt ods odp odg
    //   E-books: epub   Packages: whl egg nupkg vsix aar   Java/Android: jar apk
    //   Browser add-ons: xpi   Geo/3D/print: kmz 3mf xps oxps
    // Order/format note: jar, apk, xpi are also archive extensions
    // (DangerousExts.ARCHIVE), so they never reach R4 anyway — listed for
    // completeness, so MimeCheck does not call "app.jar as application/zip"
    // a mismatch either.
    const ZIP_CONTAINER_EXTS = Object.freeze([
        "docx", "docm", "xlsx", "xlsm", "pptx", "pptm",
        "odt", "ods", "odp", "odg",
        "epub",
        "whl", "egg", "nupkg", "vsix", "aar",
        "jar", "apk", "xpi",
        "kmz", "3mf", "xps", "oxps",
    ]);

    // Map of MIME type -> accepted extensions (lowercase, no dot).
    // Covers the file types DownloadSentinel intercepts (executables + archives
    // + the document/image/media types MimeCheck.checkMime() also evaluates).
    const MIME_TO_EXTS = {
        // Executables
        "application/x-msdownload":          ["exe", "dll", "com"],
        "application/x-msdos-program":       ["exe", "com", "bat"], // v3.4.0: also .bat (Debian mime.types)
        "application/x-ms-dos-executable":   ["exe", "com"],   // alias seen in the wild
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
        "application/javascript":            ["js"], // v2.9.0 bug fix — this IS the
                                                        // standard JS MIME type (the
                                                        // one most CDNs, including
                                                        // jsdelivr/unpkg, actually send);
                                                        // its absence here made every
                                                        // .js served with it a false
                                                        // "mismatch" — see CHANGELOG
        "text/javascript":                   ["js"],
        "application/java-archive":          ["jar"],
        "application/x-java-archive":        ["jar"],
        "application/x-debian-package":      ["deb"],
        "application/x-rpm":                 ["rpm"],
        "application/x-appimage":            ["appimage"],
        // v3.4.0 weight review — official (IANA) or shared-mime-info types a
        // correctly configured server sends; missing here, each scored a FALSE
        // MimeCheck mismatch (e.g. Docker's own .deb in the fp-sweep corpus).
        "application/vnd.debian.binary-package": ["deb"],
        "application/x-redhat-package-manager":  ["rpm"],
        "application/vnd.appimage":              ["appimage"],
        "application/x-shellscript":             ["sh", "bash"],
        "application/x-ole-storage":             ["msi", "msp", "doc", "xls", "ppt", "msg"], // OLE compound file — see AMBIGUOUS_CONTAINER_MIMES
        "application/x-hta":                 ["hta"],
        "application/x-ms-shortcut":         ["lnk"],
        "application/x-mscf":                ["chm"],
        "application/x-java-vm":             ["class"],

        // DS-H001 — Linux desktop launcher files
        "application/x-desktop":             ["desktop"],
        "application/x-gnome-app-info":      ["desktop"],

        // Archives
        // v3.4.0 — the zip types also list ZIP_CONTAINER_EXTS (formats that
        // ARE zip files inside); see that constant above MIME_TO_EXTS.
        "application/zip":                   ["zip", ...ZIP_CONTAINER_EXTS],
        "application/x-zip-compressed":      ["zip", ...ZIP_CONTAINER_EXTS],
        "application/x-zip":                 ["zip", ...ZIP_CONTAINER_EXTS],
        "application/x-rar-compressed":      ["rar"],
        "application/vnd.rar":               ["rar"],
        "application/x-7z-compressed":       ["7z"],
        "application/x-tar":                 ["tar"],
        "application/gzip":                  ["gz", "tar"],
        "application/x-gzip":                ["gz", "tar"],
        "application/x-bzip2":               ["bz2", "tar"],
        "application/x-xz":                  ["xz", "tar"],
        "application/x-lzma":                ["lzma"],
        "application/x-lzip":                ["lz"],
        "application/x-compress":            ["z"],
        "application/x-iso9660-image":       ["iso"],
        "application/x-cd-image":            ["iso"],               // v3.4.0 — shared-mime-info name
        "application/vnd.android.package-archive": ["apk"],         // v3.4.0 — official APK type
        "application/x-xpinstall":           ["xpi"],               // v3.4.0 — Firefox add-on type
        "application/x-chrome-extension":    ["crx"],               // v3.4.0
        "application/x-apple-diskimage":     ["dmg"],
        "application/x-cab-compressed":      ["cab"],
        "application/vnd.ms-cab-compressed": ["cab"],

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

    // Derived, not hand-maintained: any MIME whose mapped extensions include
    // at least one DangerousExts.DANGEROUS entry counts as an executable MIME.
    // This is what background.js uses to gate isMimeExec — see module header.
    // v3.4.0 — container types that hold BOTH programs and ordinary documents
    // (an OLE compound file is an .msi as well as a legacy .doc/.xls/.ppt).
    // They stay in MIME_TO_EXTS, so MimeCheck accepts every listed extension,
    // but are never "executable MIMEs" — otherwise every legacy Office file
    // served with this type would open a warning page.
    const AMBIGUOUS_CONTAINER_MIMES = new Set(["application/x-ole-storage"]);

    const EXECUTABLE_MIMES = new Set(
        Object.entries(MIME_TO_EXTS)
            .filter(([mime, exts]) => !AMBIGUOUS_CONTAINER_MIMES.has(mime)
                && exts.some(ext => DangerousExts.DANGEROUS.set.has(ext)))
            .map(([mime]) => mime)
    );

    // v3.4.0 (heuristic R4) — derived the same way as EXECUTABLE_MIMES: any
    // MIME whose mapped extensions include an archive/disk-image extension.
    // Used by FilenameAnalysis.classifyDownload() to monitor a file whose
    // visible extension is harmless (e.g. "invoice.pdf") while the server
    // says it is an archive — the name and the type disagree.
    const ARCHIVE_MIMES = new Set(
        Object.entries(MIME_TO_EXTS)
            .filter(([, exts]) => exts.some(ext => DangerousExts.ARCHIVE.set.has(ext)))
            .map(([mime]) => mime)
    );

    // v3.4.0 (heuristic R1) — single source of truth for "the server did not
    // say what this is": content types that only mean "some bytes". A
    // download with NO extension anywhere (URL, original URL, filename) and
    // one of these types is monitored as FILE_TYPE.UNKNOWN_BINARY — see
    // FilenameAnalysis.classifyDownload(). Also the neutral set in
    // MimeCheck.checkMime(): a generic label is never a name/type mismatch.
    //   application/octet-stream  RFC 2046 default for unknown binary data
    //   binary/octet-stream       non-standard alias (S3 and some CDNs)
    //   application/x-octet-stream, application/binary, application/x-binary,
    //   application/unknown       non-standard aliases seen in the wild
    //   application/force-download, application/x-download,
    //   application/download      "make the browser save it" hacks —
    //                             they say nothing about the content
    const GENERIC_BINARY_MIMES = new Set([
        "application/octet-stream",
        "binary/octet-stream",
        "application/x-octet-stream",
        "application/binary",
        "application/x-binary",
        "application/unknown",
        "application/force-download",
        "application/x-download",
        "application/download",
    ]);

    /**
     * Normalize a raw Content-Type / downloadItem.mime value:
     *   - strip parameters after ";" (e.g. "; charset=utf-8")
     *   - trim whitespace
     *   - lowercase
     * Previously this exact three-step sequence was duplicated inline at
     * three separate call sites in background.js and once in MimeCheck.js.
     */
    function normalize(mimeType) {
        return (mimeType || "").split(";")[0].trim().toLowerCase();
    }

    return { MIME_TO_EXTS, EXECUTABLE_MIMES, ARCHIVE_MIMES, GENERIC_BINARY_MIMES, normalize };
})();
