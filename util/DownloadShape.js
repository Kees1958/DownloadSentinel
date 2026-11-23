"use strict";

/**
 * DownloadShape.js — v3.4.0 decisions for heuristics R1 and R4 that the
 * download glue (DS background.js, and 3P Matrix's own download module)
 * needs between classifyDownload() and the warning page.
 *
 * Pure: no chrome.* access, no shared mutable state — one implementation
 * both extensions call, unit-tested in tests/DownloadShapeHeuristics.test.js.
 *
 * Public interface:
 *   DownloadShape.OUTCOME           {Object} frozen enum — see reevaluate()
 *   DownloadShape.contextOf(source) -> { visibleExt, isUnknownBinary, fpLevel }
 *       the trailing `downloadContext` argument of
 *       BrowserProtection.checkHostReputation(); `source` is a
 *       classifyDownload() result or a pending-check record (v3.5.0: renamed
 *       from shapeOf and extended with fpLevel — the record's FP reduction
 *       level, which selects protection/DeliveryContext.js's strategy)
 *   DownloadShape.reevaluate(record, confirmedFilename)
 *       -> { outcome, classified }
 *       R1 re-check once Chrome knows the real filename (onChanged)
 *   DownloadShape.mustAlwaysWarn(record) -> boolean
 *       true = skip "Silent when probably safe" (autoAllow) for this record
 *
 * Dependencies: AppConstants.js (switch), FilenameAnalysis.js (classifier).
 */
import { APP } from "./AppConstants.js";
import { FilenameAnalysis } from "./FilenameAnalysis.js";

export const DownloadShape = (function () {

    // What reevaluate() decided for a record that was an extensionless
    // generic binary (R1) when the download started.
    //   KEEP          not an R1 record, or still extensionless — nothing changes
    //   RELEASE       the confirmed name is an ordinary file ("clip.mp4"):
    //                 not monitored after all — release it, show nothing
    //   BECAME_KNOWN  the confirmed name reveals a monitored type
    //                 ("setup.exe"): R1 no longer applies — update the record
    //                 from `classified` and re-score (the obfuscation signal
    //                 then reports the extension that was hidden)
    const OUTCOME = Object.freeze({
        KEEP:         "keep",
        RELEASE:      "release",
        BECAME_KNOWN: "became-known",
    });

    function contextOf(source) {
        return {
            visibleExt:      source?.visibleExt ?? null,
            isUnknownBinary: !!source?.isUnknownBinary,
            fpLevel:         source?.fpLevel ?? null,
        };
    }

    // record needs: fileType, url, originalUrl, mime, lateEntry.
    // Late-entry records were classified with the confirmed filename already.
    function reevaluate(record, confirmedFilename) {
        if (!record || record.lateEntry || record.fileType !== FilenameAnalysis.FILE_TYPE.UNKNOWN_BINARY) {
            return { outcome: OUTCOME.KEEP, classified: null };
        }
        const classified = FilenameAnalysis.classifyDownload(
            record.url || "", record.originalUrl || "", confirmedFilename || "", record.mime || "");
        if (!classified) return { outcome: OUTCOME.RELEASE, classified: null };
        if (classified.isUnknownBinary) return { outcome: OUTCOME.KEEP, classified };
        return { outcome: OUTCOME.BECAME_KNOWN, classified };
    }

    function mustAlwaysWarn(record) {
        return !!(APP.EXTENSIONLESS_BINARY_ALWAYS_WARN && record?.isUnknownBinary);
    }

    return { OUTCOME, contextOf, reevaluate, mustAlwaysWarn };
})();
