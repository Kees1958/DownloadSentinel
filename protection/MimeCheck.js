"use strict";

/**
 * MimeCheck.js
 *
 * Checks whether a file's extension is consistent with its declared MIME type,
 * and whether the file size exceeds VirusTotal's maximum upload limit.
 *
 * MIME consistency:
 *   - "application/octet-stream" and "text/plain" are both treated as
 *     neutral for every extension (too common, server laziness — this
 *     includes script extensions as of v2.9.0; see that CHANGELOG entry for
 *     why the previous script-specific -20 penalty here was a bug)
 *   - A genuine mismatch (e.g. .exe served as image/jpeg) scores
 *     SCORING_CONFIG.MIME_MISMATCH_SCORE (−45 since v3.4.0; was a −60 literal)
 *   - A match scores 0 (reported as informational)
 *
 * File size:
 *   - Exceeds 650 MB → SCORING_CONFIG.SIZE_EXCEEDS_VT_SCORE (VT will skip
 *     scanning; antivirus evasion technique)
 */
import { DangerousMimes } from "../util/DangerousMimes.js";
import { SCORING_CONFIG } from "./ScoringEngineV2.js"; // MIME_MISMATCH_SCORE, SIZE_EXCEEDS_VT_SCORE (v3.4.0), VT_MAX_BYTES, BYTES_PER_MB (4.5.8)

export const MimeCheck = (function () {

    const VT_MAX_BYTES = SCORING_CONFIG.VT_MAX_BYTES; // 3P Matrix 4.5.8: one value, shared with Check 26's huge tier

    // Lazy-server default for text — neutral like GENERIC_BINARY_MIMES (see
    // the v2.9.0 note in checkMime()), but text, so not part of that set.
    const TEXT_PLAIN_MIME = "text/plain";

    // DS-H008: MIME_TO_EXTS is no longer defined here — single source of
    // truth is now util/DangerousMimes.js, shared with background.js's
    // EXECUTABLE_MIMES gate so the two can never drift apart again.
    const MIME_TO_EXTS = DangerousMimes.MIME_TO_EXTS;

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
        const mime = DangerousMimes.normalize(mimeType);

        // application/octet-stream and text/plain are common lazy server defaults —
        // both treated as neutral (too common, server laziness) for every
        // extension, scripts included.
        //
        // v2.9.0 bug fix: scripts used to get a special -20 "possible
        // misconfiguration" penalty here instead of the neutral treatment
        // every other extension gets for the exact same MIME type. In
        // practice "text/plain" is the single most common Content-Type raw
        // script hosting actually uses — raw.githubusercontent.com and
        // virtually every install-one-liner CDN serve .sh/.py/.ps1 etc. this
        // way as a matter of course, not as a misconfiguration. Under the
        // pre-v2.9.0 "worst signal wins" model this penalty was invisible
        // (ScriptFormat's -25 always dominated it); Step 3's combination
        // logic let it stack with ScriptFormat and push ordinary install
        // scripts (nvm, rustup, oh-my-zsh, docker, …) into a worse warning
        // tier than they deserve — caught by the fp-sweep known-good gate,
        // fixed here rather than worked around. See CHANGELOG.
        // v3.4.0 — the generic set now comes from DangerousMimes.GENERIC_BINARY_MIMES
        // (single source, shared with the R1 extensionless-binary gate) instead
        // of two literals here. This also makes the "force-download"-style
        // labels neutral: they never described the content, so an ".exe"
        // served as application/force-download was a false mismatch.
        if (DangerousMimes.GENERIC_BINARY_MIMES.has(mime) || mime === TEXT_PLAIN_MIME) {
            return { consistent: null, neutral: true,
                     label: `MIME type is generic (${mime}) — server default, not evaluated`, score: 0 };
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
                 score: SCORING_CONFIG.MIME_MISMATCH_SCORE };
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
            const mb = (totalBytes / SCORING_CONFIG.BYTES_PER_MB).toFixed(1);
            return { exceeds: true,
                     label: `File size ${mb} MB exceeds VirusTotal maximum (${VT_MAX_BYTES / SCORING_CONFIG.BYTES_PER_MB} MB) — antivirus scan may be skipped`,
                     score: SCORING_CONFIG.SIZE_EXCEEDS_VT_SCORE };
        }
        return { exceeds: false, label: `File size within VirusTotal limit`, score: 0 };
    }

    return { checkMime, checkSize, VT_MAX_BYTES };

})();
