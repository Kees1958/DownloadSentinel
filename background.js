// ── ES module imports ─────────────────────────────────────────────────────────
// Each imported module pulls in its own transitive dependencies (e.g.
// BrowserProtection.js imports ProtectionResult, MimeCheck, DnsThreatProtection,
// etc. itself) — background.js only imports what it references directly.
import { APP } from "./util/AppConstants.js";       // all magic numbers and timing values
import { MSG } from "./util/MessageTypes.js";        // all message-type string constants
import { Settings } from "./util/Settings.js";        // user preferences (read/write)
import { UrlUtils } from "./util/UrlUtils.js";        // cleanUrl, getHostname, getTld, toVtUrlId
import { ScoringEngineV2 } from "./protection/ScoringEngineV2.js"; // evaluate, evaluateFromAnalysisResults, evaluateHostReputation, scaleHostScoreForUnknownVt
import { BrowserProtection } from "./protection/BrowserProtection.js"; // checkIfUrlIsMalicious, checkHostReputation
import { FilenameAnalysis } from "./util/FilenameAnalysis.js"; // pure filename/extension helpers, incl. classifyDownload — see that file's header
import { DownloadTrust } from "./util/DownloadTrust.js"; // isTrustedDomain, isPageMadeDownload — see that file's header (v3.3.0, item 26)
import { VtKeyPromptPolicy } from "./util/VtKeyPromptPolicy.js"; // shouldShowVtKeyPrompt() — v3.0.7 startup nudge popup
import { DnsDefaults } from "./util/DnsDefaults.js"; // region-aware DNS threat-intel defaults (v3.3.1)
import { DownloadShape } from "./util/DownloadShape.js"; // heuristics R1/R4 decisions (v3.4.0) — shared with 3P Matrix
import { WarnPolicy } from "./protection/WarnPolicy.js"; // v3.5.2 — window or quiet (thresholds + exceptions), shared with 3P Matrix
import { QuietLog } from "./util/QuietLog.js"; // v3.5.2 — quiet downloads: toolbar badge + popup list
import { ActiveThreatHosts } from "./util/ActiveThreatHosts.js"; // v3.5.4 — active-threat delivery floor (ported from 3P Matrix 4.5.1)
import { MessageGate } from "./util/MessageGate.js"; // v3.6.0 — router sender gate (3P Matrix 5.0.6 C46 / 5.0.7 C52)

// ─────────────────────────────────────────────────────────────────────────────
// background.js — Download Sentinel service worker
// ─────────────────────────────────────────────────────────────────────────────
//
// Public interface (message router — see onMessage switch below):
//   MSG.GET_PENDING_CHECK   — return pendingChecks record for downloadId
//   MSG.DISMISS_CHECK       — clean up a completed check
//   MSG.EXTENSION_TOGGLE    — update extension icon
//   MSG.SETTINGS_UPDATED    — reload custom domains
//   MSG.SUBMIT_URL_TO_VT    — submit URL for fresh VT analysis and poll
//
// STATE OVERVIEW — for troubleshooting service worker restarts and races
// ─────────────────────────────────────────────────────────────────────────────
//
// STATELESS (recomputed fresh every call, safe across SW restarts):
//   - FilenameAnalysis.classifyDownload() → derives DANGEROUS_EXTS/ARCHIVE_EXTS
//     (DS-H009) and EXECUTABLE_MIMES (DS-H008) internally from util/DangerousExts.js
//     and util/DangerousMimes.js — see util/FilenameAnalysis.js
//   - BUILTIN_DO_NOT_CHECK_DOMAINS  → from util/AppConstants.js
//     → static constants, never mutated
//   - getBlockedExtension(), isTrustedDomain(), buildVtBlockReason()
//     → pure functions, no shared state
//
// STATEFUL — IN-MEMORY ONLY (lost on every SW restart, ~30s idle timeout):
//   - pendingChecks (Map)         → NOT persisted. If SW restarts while a
//                                    download is in-flight, the check is simply
//                                    lost — onChanged will still fire when the
//                                    download completes, but with no pending
//                                    record it will be treated as a new check.
//                                    Safe: worst case user sees warning a few
//                                    seconds later than optimal.
//   - runtimeCustomDomains (let)  → reloaded from chrome.storage.local on every
//                                    SW startup via loadCustomDomains().
//
// STATEFUL — PERSISTED (chrome.storage):
//   - chrome.storage.local["Settings"]
//       User preferences (API key, FP level, custom domains, etc). Survives
//       browser restarts and extension updates. Read via Settings.get().
//
// ARCHITECTURE — V2.0+:
//   Two-listener model. No pause/resume/cancel. Download always completes.
//   Download Sentinel is an information/warning tool, not a blocker.
//
//   onCreated  → start VT + Quad9 + RDAP calls, record startedAt timestamp
//   onChanged  → download complete: wait remaining budget (APP.VT_WAIT_BUDGET_MS
//                - elapsed), run heuristics, calculate score, show warning or
//                auto-proceed
//
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// TIMER & WAIT-STATE REFERENCE
// ─────────────────────────────────────────────────────────────────────────────
//
// background.js
//   APP.VT_WAIT_BUDGET_MS          Total budget from startedAt to when we
//                                   give up waiting for VT in onChanged.
//                                   See AppConstants.js for breakdown.
//
//   APP.SWEEP_ALARM_NAME / _PERIOD  chrome.alarms recurring. Removes pendingChecks
//                                   entries older than APP.ENTRY_MAX_AGE_MS.
//
// BrowserProtection.js
//   APP.VT_FETCH_TIMEOUT_MS        AbortController timeout on the VT API GET.
//   APP.VT_FETCH_STARTUP_DELAY_MS  Small pause before VT fetch.
//
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// GUARDS REFERENCE
// ─────────────────────────────────────────────────────────────────────────────
//
// ── State guards ─────────────────────────────────────────────────────────────
//   checkedIds (Set)          onChanged dedup — onChanged can fire multiple
//                              times for the same download. This Set prevents
//                              double-processing. Cleaned up in onErased.
//                              Bounded: entries removed in onErased and DISMISS_CHECK;
//                              sweep removes orphaned entries via sweepStaleEntries().
//
// ── No loop guards needed ────────────────────────────────────────────────────
//   The architecture never calls pause()/resume(), so there is no
//   resume → onCreated loop to guard against.
//
// ─────────────────────────────────────────────────────────────────────────────

"use strict";

// Extension/MIME classification (DANGEROUS_EXTS, ARCHIVE_EXTS, SCRIPT_EXTS,
// EXECUTABLE_MIMES) now lives entirely inside FilenameAnalysis.classifyDownload()
// — see util/FilenameAnalysis.js. Nothing in this file needs those sets
// directly any more (jscpd-flagged duplication cleanup, audit pass).

// Built-in trusted domains — single source of truth is APP.BUILTIN_DO_NOT_CHECK_DOMAINS
// in AppConstants.js, shared with OptionsPage.js so the UI always reflects reality.
const BUILTIN_DO_NOT_CHECK_DOMAINS = APP.BUILTIN_DO_NOT_CHECK_DOMAINS;

let runtimeCustomDomains = [];
// NOTE: runtimeCustomDomains is reloaded on onStartup, onInstalled, AND at
// module load. The module-load call handles the case where the SW wakes via
// an alarm without firing either startup event.

// v3.3.0 (3P Matrix alignment item 25) — "Trust AI downloads" opt-in
// category (Settings.js's trustAiDownloads). Reloaded alongside
// runtimeCustomDomains in loadCustomDomains() below — same lifecycle, same
// reason (SW restarts routinely under MV3; nothing here is persisted
// in-memory across one).
let runtimeTrustAiDownloads = false;

// ── pendingChecks ─────────────────────────────────────────────────────────────
// Keyed by downloadId. Holds the async check results while the download runs.
// In-memory only — see STATE OVERVIEW above for why this is acceptable.
// Bounded: swept every APP.SWEEP_ALARM_PERIOD_MINUTES, max age APP.ENTRY_MAX_AGE_MS.
// Max concurrent entries is naturally limited by browser download concurrency.
const pendingChecks = new Map();
const checkedIds    = new Set(); // dedup guard for onChanged — see GUARDS REFERENCE

// v3.3.0 (3P Matrix alignment item 6) — windowId -> downloadId, so closing a
// warning window with its own ✕ (not a button in the page — that path never
// sends DISMISS_CHECK) still releases pendingChecks/checkedIds/abortControllers
// right away, instead of waiting out the up-to-APP.ENTRY_MAX_AGE_MS sweep.
// Released in the chrome.windows.onRemoved listener below; also cleaned up
// defensively whenever a download's own lifecycle ends through another path
// (onErased, DISMISS_CHECK, sweep) so this Map never outlives the download it
// tracks.
const openWindows = new Map();

function releaseDownload(downloadId, reason) {
    // v3.3.0 (item 16) — a VT timeout retry may still be silently running
    // for this download even though its warning window just closed (the
    // page's own OK/Dismiss, or the window's native ✕). Per the decided
    // design, that retry is never aborted just because the window closed —
    // so when one is in flight, keep the pendingChecks record alive (just
    // flag it as windowClosed) instead of deleting it, and skip aborting
    // the request. handleLateVtResult() below is what finally releases this
    // record for real, once the retry actually settles one way or another.
    if (BrowserProtection.isVtPending(downloadId)) {
        const record = pendingChecks.get(downloadId);
        if (record) record.windowClosed = true;
    } else {
        pendingChecks.delete(downloadId);
        BrowserProtection.abandonPendingRequests(downloadId, reason);
    }
    checkedIds.delete(downloadId);
    for (const [windowId, id] of openWindows) {
        if (id === downloadId) openWindows.delete(windowId);
    }
}

// ── Helper functions ──────────────────────────────────────────────────────────
// The pure filename/extension analysis functions formerly defined inline here
// (getExtFromFilename, getRawExt, extractFilenameFromUrl, getDoubleExtension,
// getBlockedExtension, getExtCategory, getObfuscationSignal) now live in
// util/FilenameAnalysis.js (C1 — one module, one responsibility) so they can
// be unit-tested without a chrome.* mock. Aliased to their original names
// here so every remaining call site below is unchanged — no behavior change.
// (getExtFromFilename and getExtCategory have no call site left in this file
// — they're now only called internally within FilenameAnalysis.js itself —
// so they are intentionally not aliased here; no-unused-vars would flag them.)
const getRawExt              = FilenameAnalysis.getRawExt;
const extractFilenameFromUrl = FilenameAnalysis.extractFilenameFromUrl;
const getDoubleExtension     = FilenameAnalysis.getDoubleExtension;
const getBlockedExtension    = FilenameAnalysis.getBlockedExtension;
const getObfuscationSignal   = FilenameAnalysis.getObfuscationSignal;

// Snapshot of the settings fields a pendingChecks record needs for later use
// in onChanged (scoring/auto-allow decisions happen after this snapshot is
// taken, potentially after the user has changed settings again — the record
// intentionally freezes the values as they were when the download started).
// Extracted from two identical inline copies in onCreated and the onChanged
// late-entry path (jscpd-flagged duplicate, audit pass) — no behavior change.
// Guard: a stored dnsFirst/dnsSecond value is user/storage data, never
// trusted blindly — validate against APP.DNS_PROVIDERS (+ the "none" id)
// and fall back to the app default for anything else (corrupt storage, a
// provider removed in a future version, etc.), so checkHostReputation()
// never gets handed an id it doesn't recognise.
const DNS_PROVIDER_IDS = new Set([...Object.keys(APP.DNS_PROVIDERS), APP.DNS_NONE]);
function validDnsProviderId(id, fallback) {
    return DNS_PROVIDER_IDS.has(id) ? id : fallback;
}

function buildSettingsSnapshot(settings) {
    return {
        fpLevel:            settings.fpReductionLevel ?? "MEDIUM",
        silentWhenInconclusive: !!settings.silentWhenInconclusive,   // off by default (user decision)
        autoAllow:          !!settings.autoAllow,
        autoAllowThreshold: settings.autoAllowThreshold ?? APP.AUTO_ALLOW_THRESHOLD_DEFAULT,
        vtApiKeySet:        !!(settings.isVtApiKeySet && settings.vtApiKey),
        dnsFirst:           validDnsProviderId(settings.dnsFirst,  DnsDefaults.get().first),
        dnsSecond:          validDnsProviderId(settings.dnsSecond, DnsDefaults.get().second),
    };
}

// v3.4.0 — release a download that turned out NOT to need a warning after
// all (onChanged), without touching checkedIds: onChanged's dedup must keep
// ignoring this id; onErased / the sweep clean checkedIds as before. Aborts
// any still-running VT request so nothing outlives the record.
function releaseWithoutWarning(downloadId, reason) {
    pendingChecks.delete(downloadId);
    BrowserProtection.abandonPendingRequests(downloadId, reason);
}

function getAllDoNotCheckDomains() {
    // v3.3.0 (item 25) — AI_DOWNLOAD_DOMAINS only joins the effective
    // trusted set when the user has opted in via trustAiDownloads; unlike
    // the built-in app-store domains, these are not trusted unconditionally.
    const aiDomains = runtimeTrustAiDownloads ? APP.AI_DOWNLOAD_DOMAINS : [];
    return [...BUILTIN_DO_NOT_CHECK_DOMAINS, ...aiDomains, ...runtimeCustomDomains];
}

// v3.5.4 — the ONE entry point to host reputation (all three call sites:
// onCreated, late entry, re-check at completion). Runs DownloadSentinel's own
// check unchanged, then applies the active-threat delivery floor
// (util/ActiveThreatHosts.js) to its result — after the engine, never inside
// CombinationScoring (see that module's header). Same signature as
// BrowserProtection.checkHostReputation(). Both the final URL and the original
// link are offered to the floor: a github.com/…/releases/download/…/tool.exe
// link redirects to a release-assets CDN path WITHOUT an extension, so the
// final URL alone would miss it (same redirect gap as the v2.0.1 fix).
function checkHostReputationFloored(url, fileType, ext, mime, totalBytes, originalUrl, ...rest) {
    return BrowserProtection.checkHostReputation(url, fileType, ext, mime, totalBytes, originalUrl, ...rest)
        .then(hostResult => ActiveThreatHosts.applyFloor(hostResult, [url, originalUrl]));
}

// v3.3.0 (item 16) — extracted from onChanged's own inline math (previously
// the only call site) so handleLateVtResult() can recompute the identical
// combined score from a record a late VT retry just updated, in one place.
//
// When VT has no data, negative heuristic signals are scaled by the FP
// reduction level (High = conservative/less alarming, None = aggressive/more
// alarming) — see SCORING_CONFIG.FP_UNKNOWN_MULTIPLIERS in ScoringEngineV2.js
// for the rationale. The combined score is VT + the (possibly scaled) host
// score, clamped to [-100, 100].
// v3.5.6 — the host verdict that applies is chosen here too (ScoringEngineV2.hostVerdict):
// VirusTotal unknown → heuristics only, small signals stack on a dubious source.
function computeCombinedScore(record) {
    const vtUnknown = record.vtDone && record.vtScore === null;
    const hostVerdict = ScoringEngineV2.hostVerdict(record.hostResult, vtUnknown);
    const hostScore = hostVerdict?.score ?? 0;
    // v3.5.0 — the scaling itself is shared with tools/fp-sweep.mjs.
    const { scaled: scaledHostScore, multiplier: fpMultiplier } =
        ScoringEngineV2.scaleHostScoreForUnknownVt(hostScore, record.fpLevel, vtUnknown);
    const vtScore  = record.vtScore ?? 0;
    const combined = Math.max(-100, Math.min(100, vtScore + scaledHostScore));
    return { combined, scaledHostScore, fpMultiplier, vtUnknown, hostVerdict };
}

// v3.3.0 (item 26) — isTrustedDomain/isPageMadeDownload are now pure
// functions in util/DownloadTrust.js (unit-tested there without a chrome.*
// mock); these two thin wrappers just supply this module's own mutable
// trusted-domain list so every call site below reads exactly as before.
function isTrustedDomain(url, referrerUrl = null) {
    return DownloadTrust.isTrustedDomain(url, getAllDoNotCheckDomains(), referrerUrl);
}
function isPageMadeDownload(url) {
    return DownloadTrust.isPageMadeDownload(url);
}

function setExtensionIcon(enabled) {
    const suffix = enabled ? "" : "_OFF";
    chrome.action.setIcon({
        path: {
            "16":  chrome.runtime.getURL(`assets/icons/icon16${suffix}.png`),
            "24":  chrome.runtime.getURL(`assets/icons/icon24${suffix}.png`),
            "32":  chrome.runtime.getURL(`assets/icons/icon32${suffix}.png`),
            "48":  chrome.runtime.getURL(`assets/icons/icon48${suffix}.png`),
            "128": chrome.runtime.getURL(`assets/icons/icon128${suffix}.png`)
        }
    }).catch(err => console.warn("[DS] setIcon failed:", err?.message));
}

function loadCustomDomains() {
    Settings.get(settings => {
        runtimeCustomDomains = Array.isArray(settings.customDomains)
            ? settings.customDomains : [];
        runtimeTrustAiDownloads = !!settings.trustAiDownloads; // v3.3.0 (item 25)
        setExtensionIcon(settings.extensionEnabled !== false);
    });
}

function openWarningPage(downloadId) {
    chrome.windows.create({
        url:   chrome.runtime.getURL(`pages/warning/WarningPage.html?downloadId=${downloadId}`),
        type:  "popup",
        state: "maximized"
    }).then(win => {
        // v3.3.0 (item 6) — track this window so its own ✕ releases resources
        // immediately via chrome.windows.onRemoved, not just the sweep.
        if (win && win.id !== undefined) openWindows.set(win.id, downloadId);
    }).catch(err => {
        // If the popup fails to open, log and clean up — user cannot act on it
        console.error("[DS] openWarningPage failed:", err?.message);
        releaseDownload(downloadId, "warning page open failed");
    });
}

// v3.3.0 (item 6) — release everything tied to a download the instant its
// warning window is closed any way at all (the page's own OK/Dismiss button,
// or the window's native ✕, which never sends DISMISS_CHECK).
chrome.windows.onRemoved.addListener(windowId => {
    const downloadId = openWindows.get(windowId);
    if (downloadId === undefined) return;
    openWindows.delete(windowId);
    releaseDownload(downloadId, "warning window closed");
});

// v3.5.2 — WarnPolicy's download decision for a record and a combined score
// (one place for onChanged and the late-VirusTotal path).
function warnDecision(record, combined) {
    return WarnPolicy.downloadDecision({
        combinedScore: combined,
        fpLevel:       record.fpLevel,
        entries:       (record.hostVerdict ?? record.hostResult)?.breakdown,   // v3.5.6 — the verdict that applies
        vtMalicious:   record.vtRawStats?.malicious,
    });
}

// v3.5.2 — display data for the popup's quiet list (no record kept).
function quietEntryOf(record, combined) {
    return {
        filename: (record.confirmedFilename || record.filename || "").split(/[\\/]/).pop(),
        host:     UrlUtils.getHostname(record.url) || "",
        verdict:  ScoringEngineV2.classifyByScore(combined),
        score:    combined,
        at:       Date.now(),
    };
}

// v3.3.0 (item 16) — handles a VT verdict that arrives AFTER the original
// VT_FETCH_TIMEOUT_MS deadline already told the user "unknown" (passed as
// onCreated's onLateResult callback to BrowserProtection.checkIfUrlIsMalicious
// below). Only called at all when BrowserProtection actually got a definite
// verdict on retry — see that function's own doc comment for when it stays
// silent instead.
function handleLateVtResult(downloadId, result) {
    const record = pendingChecks.get(downloadId);
    if (!record) return; // fully released already (e.g. swept) — nothing to update

    record.vtDone         = true;
    record.vtScore         = result?.score           ?? null;
    record.vtConfidence    = result?.confidence      ?? null;
    record.vtBreakdown     = result?.breakdown       ?? null;
    record.vtHardRule      = result?.hardRuleApplied ?? null;
    record.vtRawStats      = result?.rawStats        ?? null;
    record.vtFilteredStats = result?.filteredStats   ?? null;
    record.vtFpLevel       = result?.fpLevel         ?? null;

    const previousCombined = record.combinedScore; // undefined if the page never finished rendering yet
    const { combined, hostVerdict } = computeCombinedScore(record);
    record.combinedScore = combined;
    record.hostVerdict   = hostVerdict;   // v3.5.6 — VirusTotal's answer can switch the host verdict

    if (!record.windowClosed) {
        // Warning page is (most likely) still open — push a live update
        // through the same MSG.VT_RESULT_UPDATE channel the SUBMIT_URL_TO_VT
        // flow already uses; WarningPage.js's existing listener re-renders
        // in place, no separate wiring needed on that side.
        chrome.runtime.sendMessage({
            type:            MSG.VT_RESULT_UPDATE,
            downloadId,
            vtScore:         record.vtScore,
            vtConfidence:    record.vtConfidence,
            vtBreakdown:     record.vtBreakdown,
            vtHardRule:      record.vtHardRule,
            vtRawStats:      record.vtRawStats,
            vtFilteredStats: record.vtFilteredStats,
            vtFpLevel:       record.vtFpLevel,
            hostVerdict:     record.hostVerdict,   // v3.5.6
        }).catch(() => {}); // ignore — page closed in the gap between check and here
        return;
    }

    // The warning page was already closed when this late result arrived.
    // Per the decided design: only worth re-interrupting the user when the
    // new verdict makes things WORSE than what they already saw and
    // dismissed — a late "actually it's fine" is not worth a surprise
    // popup, but a late "actually it's worse" is.
    // v3.5.2: a download that was quiet (record.quiet) opens only when the new
    // verdict now warrants a window (warnDecision); a dismissed window reopens
    // when the verdict got worse, as before.
    const isEscalation = previousCombined !== undefined &&
        (record.quiet ? warnDecision(record, combined).warn : combined < previousCombined);
    if (isEscalation) {
        record.quiet = false;
        record.windowClosed = false; // a fresh window is about to open for it
        openWarningPage(downloadId); // re-fetches this same (now-updated) record via GET_PENDING_CHECK
    } else {
        releaseDownload(downloadId, "late VT result — no escalation, releasing retained record");
    }
}

// ── VT-key nudge popup (v3.0.7) ─────────────────────────────────────────────
// "Get a free VirusTotal API Key" — shown once per browser start when no VT
// key is set and the user hasn't opted out (pages/vtkeyprompt/). The actual
// show/don't-show decision is VtKeyPromptPolicy.shouldShowVtKeyPrompt() —
// pure logic, unit-tested on its own (tests/VtKeyPromptPolicy.test.js).

function openVtKeyPrompt() {
    chrome.windows.create({
        url:    chrome.runtime.getURL("pages/vtkeyprompt/VtKeyPrompt.html"),
        type:   "popup",
        width:  APP.VT_KEY_PROMPT_WINDOW_WIDTH,
        height: APP.VT_KEY_PROMPT_WINDOW_HEIGHT
    }).catch(err => console.error("[DS] openVtKeyPrompt failed:", err?.message));
}

function maybeShowVtKeyPrompt() {
    Settings.get(settings => {
        if (VtKeyPromptPolicy.shouldShowVtKeyPrompt(settings)) openVtKeyPrompt();
    });
}

// ── Startup ───────────────────────────────────────────────────────────────────

QuietLog.init(); // v3.5.2 — restore the quiet-download badge after a service-worker restart
chrome.runtime.onStartup.addListener(loadCustomDomains);
chrome.runtime.onInstalled.addListener(loadCustomDomains);
chrome.runtime.onStartup.addListener(maybeShowVtKeyPrompt); // real browser start only — a plain SW restart or install does not re-nudge
loadCustomDomains();

// ── Sweep stale entries ───────────────────────────────────────────────────────

function sweepStaleEntries() {
    const cutoff = Date.now() - APP.ENTRY_MAX_AGE_MS;
    for (const [id, item] of pendingChecks) {
        if ((item.startedAt || 0) < cutoff) {
            releaseDownload(id, "stale entry swept");
        }
    }
    // Also sweep any checkedIds orphaned by a SW restart (no matching pendingCheck)
    for (const id of checkedIds) {
        if (!pendingChecks.has(id)) {
            checkedIds.delete(id);
        }
    }
}

chrome.alarms.create(APP.SWEEP_ALARM_NAME, { periodInMinutes: APP.SWEEP_ALARM_PERIOD_MINUTES });
chrome.alarms.onAlarm.addListener(alarm => {
    if (alarm.name === APP.SWEEP_ALARM_NAME) sweepStaleEntries();
});

// ─────────────────────────────────────────────────────────────────────────────
// onCreated — start API checks immediately, record timestamp
// ─────────────────────────────────────────────────────────────────────────────

chrome.downloads.onCreated.addListener(async downloadItem => {

    const settings = await new Promise(resolve => Settings.get(resolve));
    if (!settings.extensionEnabled) return;

    // v3.3.0 (item 7) — a very small download can complete (and be picked up
    // by onChanged's late-entry path, setting checkedIds/pendingChecks)
    // before this handler's own Settings.get() await above resolves; without
    // this guard, onCreated would then build a SECOND record for the same
    // download, double-checking it and possibly opening two warning windows.
    if (checkedIds.has(downloadItem.id) || pendingChecks.has(downloadItem.id)) return;

    const url = downloadItem.finalUrl || downloadItem.url || "";
    if (!url) return;
    if (isTrustedDomain(url, downloadItem.referrer)) return;

    const classified = FilenameAnalysis.classifyDownload(url, downloadItem.url || "", downloadItem.filename || "", downloadItem.mime);
    if (!classified) return;
    const { ext, fileType, isScript, isLinuxLauncher, visibleExt, isUnknownBinary } = classified;

    // Record startedAt BEFORE API calls so the budget covers all setup time
    const record = {
        id:         downloadItem.id,
        startedAt:  Date.now(),
        url,
        originalUrl: (downloadItem.url && downloadItem.url !== url) ? downloadItem.url : url,
        ext,
        fileType,
        isScript,
        visibleExt,         // v3.4.0 — R4 name/type mismatch input
        isUnknownBinary,    // v3.4.0 — R1; re-evaluated in onChanged with the confirmed filename
        filename:   downloadItem.filename   || "",
        mime:       downloadItem.mime        || "",
        totalBytes: downloadItem.totalBytes  || 0,
        // referrer (v2.11.0 — FilenameUrlHeuristics.checkReferrerMismatch()):
        // chrome.downloads.DownloadItem.referrer, when Chrome reports one.
        referrer:   downloadItem.referrer    || null,
        // sizeKnown (v2.8.0 — StagingCheck container-size check): Chrome
        // typically reports totalBytes as 0 at onCreated time; sizeKnown
        // tracks whether the figure above is a real, confirmed size so the
        // onChanged recheck below knows whether a newly-nonzero size is
        // actually NEW information worth re-scoring on.
        sizeKnown:  (downloadItem.totalBytes || 0) > 0,

        // VT result — filled when check completes
        vtDone:          false,
        vtScore:         null,
        vtConfidence:    null,
        vtBreakdown:     null,
        vtHardRule:      null,
        vtRawStats:      null,
        vtFilteredStats: null,
        vtFpLevel:       null,

        // Host result — filled when check completes
        hostDone:   false,
        hostResult: null,

        // Download metadata for new heuristics
        // (danger field removed — Chrome Safe Browsing already blocks/warns on
        //  serious cases before our warning page opens; redundant to re-score it)

        // Settings snapshot for use in onChanged
        ...buildSettingsSnapshot(settings),
    };

    pendingChecks.set(downloadItem.id, record);

    // ── A. Host reputation (fast, no API key needed) ──────────────────────
    checkHostReputationFloored(
        url, fileType, ext, record.mime, record.totalBytes, record.originalUrl, isScript,
        null,                                   // obfuscation — not yet known at creation time
        getDoubleExtension(downloadItem.filename || ""), // double-extension check
        isLinuxLauncher,
        record.filename,                        // v2.8.0 — StagingCheck.checkKeywords() filename
        record.sizeKnown,                       // v2.8.0 — StagingCheck.checkFormat() sizeKnown
        record.referrer,                        // v2.11.0 — FilenameUrlHeuristics.checkReferrerMismatch()
        { first: record.dnsFirst, second: record.dnsSecond }, // v3.0.6 — user's chosen DNS threat-intel checks
        DownloadShape.contextOf(record)                 // v3.4.0 — R1/R4
    ).then(hostResult => {
        const r = pendingChecks.get(downloadItem.id);
        if (!r) return;
        r.hostDone   = true;
        r.hostResult = hostResult;
    });

    // ── B. VT check ───────────────────────────────────────────────────────
    if (!settings.isVtApiKeySet || !settings.vtApiKey) {
        record.vtDone = true; // no key — treat as done immediately
        return;
    }

    BrowserProtection.checkIfUrlIsMalicious(downloadItem.id, url, result => {
        const r = pendingChecks.get(downloadItem.id);
        if (!r) return;
        r.vtDone         = true;
        r.vtScore         = result?.score           ?? null;
        r.vtConfidence    = result?.confidence      ?? null;
        r.vtBreakdown     = result?.breakdown       ?? null;
        r.vtHardRule      = result?.hardRuleApplied ?? null;
        r.vtRawStats      = result?.rawStats        ?? null;
        r.vtFilteredStats = result?.filteredStats   ?? null;
        r.vtFpLevel       = result?.fpLevel         ?? null;
    }, record.originalUrl, settings,
    // v3.3.0 (item 16) — only downloads get this silent VT timeout-retry;
    // see BrowserProtection.checkIfUrlIsMalicious's own doc comment.
    result => handleLateVtResult(downloadItem.id, result));
});

// ─────────────────────────────────────────────────────────────────────────────
// onChanged — download complete: wait remaining budget, then act
// ─────────────────────────────────────────────────────────────────────────────

chrome.downloads.onChanged.addListener(async delta => {
    if (!delta.state || delta.state.current !== "complete") return;
    if (checkedIds.has(delta.id)) return; // dedup guard
    checkedIds.add(delta.id);

    let record = pendingChecks.get(delta.id);

    // ── Late-entry: filename was unknown at onCreated time ────────────────
    // Some downloads (e.g. Google Drive) go through a redirect chain so
    // Chrome does not know the filename when onCreated fires. The extension
    // gate in onCreated returns early (ext = null), so no pendingChecks entry
    // is created. Here we pick up those downloads once Chrome has the confirmed
    // filename, build a minimal record, and run host reputation synchronously.
    // VT is skipped (no time budget), but the host check still catches
    // dangerous file types from suspicious or user-controlled sources.
    if (!record) {
        const settings = await new Promise(resolve => Settings.get(resolve));
        if (!settings.extensionEnabled) return;

        let downloadItem;
        try {
            const results = await chrome.downloads.search({ id: delta.id });
            downloadItem = results?.[0];
        } catch { return; }
        if (!downloadItem) return;

        const url = downloadItem.finalUrl || downloadItem.url || "";
        if (!url || isTrustedDomain(url, downloadItem.referrer)) return;

        const confirmedFilename = downloadItem.filename || "";
        const classified = FilenameAnalysis.classifyDownload(url, downloadItem.url || "", confirmedFilename, downloadItem.mime);
        if (!classified) return;
        const { ext, fileType, isScript, isLinuxLauncher, visibleExt, isUnknownBinary } = classified;
        const originalUrl = (downloadItem.url && downloadItem.url !== url)
            ? downloadItem.url : url;

        // Build a minimal record — VT fields left null (no time to fetch)
        // lateEntry: true means onCreated had no monitored (dangerous/archive)
        // ext. Usually still UNKNOWN_REVEALED (the common case — the original
        // URL was opaque, e.g. Google Drive), but see DS-H007 below.
        // Best-effort "what did the ORIGINAL url suggest" — getRawExt() is
        // unfiltered (unlike getBlockedExtension), so it can surface a
        // harmless-looking suggested extension (e.g. "pdf") that
        // getObfuscationSignal can compare against the confirmed one.
        // v3.3.0 (item 22) — a page-made (blob:/data:) download never has a
        // real "extension in the URL" to hide in the first place, so the
        // obfuscation signal is skipped for those rather than always firing.
        const suggestedExt    = getRawExt(extractFilenameFromUrl(downloadItem.url || ""));
        const lateObfuscation = isPageMadeDownload(downloadItem.url) ? null : getObfuscationSignal(suggestedExt, ext);
        record = {
            id:               delta.id,
            startedAt:        Date.now(),
            url,
            originalUrl,
            ext,
            confirmedExt:     ext,
            confirmedFilename,
            fileType,
            isScript,
            visibleExt,                   // v3.4.0 — R4
            isUnknownBinary,              // v3.4.0 — R1 (filename already confirmed here)
            filename:         confirmedFilename,
            mime:             downloadItem.mime || "",
            totalBytes:       downloadItem.fileSize || 0,
            referrer:         downloadItem.referrer || null, // v2.11.0 — FilenameUrlHeuristics.checkReferrerMismatch()
            sizeKnown:        true,  // late-entry runs at onChanged/complete — fileSize is final
            vtDone:           true,   // skip VT — no budget
            vtScore:          null,
            vtConfidence:     null,
            vtBreakdown:      null,
            vtHardRule:       null,
            vtRawStats:       null,
            vtFilteredStats:  null,
            vtFpLevel:        null,
            vtUnknown:        true,
            hostDone:         false,
            hostResult:       null,
            ...buildSettingsSnapshot(settings),
            state:            "complete",
            lateEntry:        true,       // diagnostic flag
            obfuscation:      lateObfuscation,  // UNKNOWN_REVEALED, or CATEGORY_CHANGED when
                                                 // the original URL hinted at a harmless ext (DS-H007)
        };

        // Run host reputation now, including the obfuscation signal
        record.hostResult = await checkHostReputationFloored(
            url, fileType, ext, record.mime, record.totalBytes, originalUrl, isScript, lateObfuscation,
            getDoubleExtension(confirmedFilename),            // double extension
            isLinuxLauncher,
            confirmedFilename,                                // v2.8.0 — StagingCheck filename
            record.sizeKnown,                                 // v2.8.0 — StagingCheck sizeKnown
            record.referrer,                                  // v2.11.0 — FilenameUrlHeuristics.checkReferrerMismatch()
            { first: record.dnsFirst, second: record.dnsSecond }, // v3.0.6 — user's chosen DNS threat-intel checks
            DownloadShape.contextOf(record)                           // v3.4.0 — R1/R4
        );
        record.hostDone = true;
        pendingChecks.set(delta.id, record);
    }

    // ── Conditional wait: only wait what's left of the budget ─────────────
    const elapsed  = Date.now() - record.startedAt;
    const waitLeft = Math.max(0, APP.VT_WAIT_BUDGET_MS - elapsed);
    if (waitLeft > 0) await new Promise(r => setTimeout(r, waitLeft));

    // ── Get confirmed filename + size from Chrome (download now complete) ──
    // sizeKnown (v2.8.0): totalBytes is typically still 0 at onCreated time
    // for many downloads — fileSize here is the real, final figure, used
    // below both to decide whether a staging-format container recheck is
    // needed and, when a recheck does run, to score it (and the pre-existing
    // SizeCheck vs-VT-maximum signal) against the real size rather than 0.
    let confirmedFilename   = record.filename;
    let confirmedTotalBytes = record.totalBytes;
    try {
        const results = await chrome.downloads.search({ id: delta.id });
        confirmedFilename   = results?.[0]?.filename || record.filename;
        confirmedTotalBytes = results?.[0]?.fileSize ?? record.totalBytes;
    } catch { /* use original */ }

    // ── R1 re-evaluation with the confirmed filename (v3.4.0) ─────────────
    // An extensionless generic binary at onCreated may get a real name now
    // (Content-Disposition, or Chrome's own naming): classify it again.
    //   no longer monitored (e.g. "clip.mp4") → it was just an unnamed URL
    //       of an ordinary file: release silently, no warning.
    //   still monitored, now with an extension (e.g. "setup.exe") → it is
    //       an executable/archive now; R1 no longer applies, and the
    //       obfuscation signal below reports the hidden extension instead.
    //   still extensionless → unchanged, R1 stays.
    // The decision itself is DownloadShape.reevaluate() (pure, shared).
    const shape = DownloadShape.reevaluate(record, confirmedFilename);
    if (shape.outcome === DownloadShape.OUTCOME.RELEASE) {
        releaseWithoutWarning(delta.id, "extensionless binary got an ordinary file name");
        return;
    }
    const shapeChanged = shape.outcome === DownloadShape.OUTCOME.BECAME_KNOWN;
    if (shapeChanged) {
        record.fileType        = shape.classified.fileType;
        record.isScript        = shape.classified.isScript;
        record.visibleExt      = shape.classified.visibleExt;
        record.isUnknownBinary = false;
    }

    // ── Re-check extension with confirmed filename ─────────────────────────
    const confirmedExt = getBlockedExtension(record.url, confirmedFilename) || record.ext;

    // ── Obfuscation signal ────────────────────────────────────────────────
    // Compare what was known at onCreated (record.ext) with the confirmed ext.
    // If the extension was hidden or changed category, re-run host reputation
    // with the obfuscation signal so it is included in the breakdown and score.
    // v3.3.0 (item 22) — same page-made exemption as the late-entry path above.
    const obfuscation = record.lateEntry || isPageMadeDownload(record.originalUrl)
        ? null  // late-entry already passed obfuscation at host-check time; page-made files have no extension to hide
        : getObfuscationSignal(record.ext, confirmedExt);

    // ── Size-newly-known signal (v2.8.0) ────────────────────────────────────
    // WARNING FOR IMPLEMENTATION IMPACT: this recheck condition is new in
    // v2.8.0. Previously, when obfuscation was null, host reputation was
    // never re-run at onChanged — record.totalBytes (often still 0 from
    // onCreated) was the only figure ever scored. Re-running now when the
    // size has gone from unknown to known also makes the pre-existing
    // SizeCheck (file size vs VirusTotal's scan maximum) signal accurate
    // for downloads where Chrome never reported a size until completion,
    // not just the new StagingCheck.checkFormat() container-size tiers.
    const sizeNewlyKnown = !record.lateEntry && !record.sizeKnown && confirmedTotalBytes > 0;

    if ((obfuscation || sizeNewlyKnown || shapeChanged) && record.hostDone) {
        // Re-run host reputation synchronously with the obfuscation and/or
        // confirmed-size signal added. The prior result is discarded.
        const isLinuxLauncher = confirmedExt === "desktop"; // DS-H001
        record.hostResult = await checkHostReputationFloored(
            record.url,
            record.fileType,
            confirmedExt,
            record.mime,
            confirmedTotalBytes,
            record.originalUrl,
            record.isScript,
            obfuscation,
            getDoubleExtension(confirmedFilename),   // double extension
            isLinuxLauncher,
            confirmedFilename,                       // v2.8.0 — StagingCheck filename
            true,                                    // v2.8.0 — size is now known
            record.referrer,                         // v2.11.0 — FilenameUrlHeuristics.checkReferrerMismatch()
            { first: record.dnsFirst, second: record.dnsSecond }, // v3.0.6 — user's chosen DNS threat-intel checks
            DownloadShape.contextOf(record)                  // v3.4.0 — R1/R4 (after the re-evaluation above)
        );
        record.totalBytes = confirmedTotalBytes;
        record.sizeKnown  = true;
    }

    // ── Calculate combined score ───────────────────────────────────────────
    // v3.3.0 (item 16) — factored out into computeCombinedScore() below so
    // handleLateVtResult() can recompute the exact same combined score from
    // a record a late VT retry just updated, without duplicating this math.
    const { combined, scaledHostScore, fpMultiplier, vtUnknown, hostVerdict } = computeCombinedScore(record);
    record.hostVerdict = hostVerdict;   // v3.5.6 — before warnDecision() and the warning page read it

    // ── Auto-proceed check — silent, no notification ────────────────────────
    // v3.4.0 — an extensionless generic binary (R1) always warns while
    // APP.EXTENSIONLESS_BINARY_ALWAYS_WARN is on (see that switch's comment).
    const mustWarn = DownloadShape.mustAlwaysWarn(record);
    if (!mustWarn && record.autoAllow && combined >= record.autoAllowThreshold) {
        pendingChecks.delete(delta.id);
        return;
    }

    // Store the final record (the warning page reads it via GET_PENDING_CHECK;
    // v3.5.2: a late VirusTotal verdict compares against combinedScore too).
    record.confirmedExt      = confirmedExt;
    record.confirmedFilename = confirmedFilename;
    record.scaledHostScore   = scaledHostScore;
    record.combinedScore     = combined;
    record.fpMultiplier      = fpMultiplier;
    record.vtUnknown         = vtUnknown;
    record.state             = "complete";

    // ── Window or quiet (v3.5.2, protection/WarnPolicy.js) ─────────────────
    // Staged by the FP reduction level, with exceptions that always open the
    // window. Quiet → listed in the popup + toolbar badge (util/QuietLog.js);
    // releaseDownload() keeps the record while a silent VirusTotal retry still
    // runs, so a late verdict that now warrants a window still opens one.
    // v3.5.3 (user request, "Silent when inconclusive"): this whole staged-quiet behaviour is now
    // its own toggle, separate from "Silent when probably safe" above — off means every download
    // that reaches this point (not auto-allowed, no exception) always gets the window.
    if (!mustWarn && record.silentWhenInconclusive && !warnDecision(record, combined).warn) {
        record.quiet = true;
        QuietLog.add(quietEntryOf(record, combined));
        releaseDownload(delta.id, "quiet: below the warning threshold, no exception");
        return;
    }

    openWarningPage(delta.id);
});

// ── Cleanup on erase ─────────────────────────────────────────────────────────

chrome.downloads.onErased.addListener(downloadId => {
    releaseDownload(downloadId, "download erased");
});

// ─────────────────────────────────────────────────────────────────────────────
// VT submit-and-poll helper  (extracted from inline IIFE — audit item C1/C11)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Submit a URL to VirusTotal for fresh analysis and poll until results arrive.
 * Updates the pendingChecks record when results are available and broadcasts
 * a VT_RESULT_UPDATE message to any open warning pages.
 *
 * SCOPE: submits the download URL only — never the downloaded file itself.
 * Uploading the actual file to a third party is a meaningfully bigger
 * privacy/exposure decision than checking a URL, so that step is
 * intentionally left to the user's own choice, not automated here (see
 * pages/warning/WarningPage.js's "Check download at VT" button, which just
 * opens virustotal.com/hybrid-analysis.com for the user to upload manually).
 *
 * TIMING: the submit + poll round trip is short — typically ~2-3 seconds —
 * so no timer/progress state is needed by callers; VT_RESULT_UPDATE arrives
 * quickly enough that a simple "request sent, wait for the broadcast" is
 * sufficient (see the SUBMIT_URL_TO_VT catch path below for the failure case).
 *
 * STATUS: intended, working, currently unwired to any UI trigger — see
 * CHANGELOG (V2.5.3) and util/MessageTypes.js's SUBMIT_URL_TO_VT comment.
 *
 * @param {number} downloadId  — key into pendingChecks
 * @param {string} cleanUrl    — query-stripped URL to submit
 * @param {string} urlId       — base64url VT URL identifier
 * @param {object} settings    — current settings snapshot
 */
async function submitAndPollVt(downloadId, cleanUrl, urlId, settings) {
    const fpLevel = settings.fpReductionLevel ?? "MEDIUM";

    // Helper: send a result update (or null result on failure) to the warning page
    function broadcastVtUpdate(fields) {
        chrome.runtime.sendMessage({
            type:       MSG.VT_RESULT_UPDATE,
            downloadId,
            ...fields
        }).catch(() => {}); // ignore — warning page may have closed
    }

    try {
        // ── Submit URL for (re-)analysis ──────────────────────────────────
        const formData = new URLSearchParams();
        formData.append("url", cleanUrl);

        const submitResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
            method:  "POST",
            headers: {
                "x-apikey":     settings.vtApiKey,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: formData.toString()
        });

        if (!submitResponse.ok) {
            // Submission failed — notify warning page so it does not wait forever
            const r = pendingChecks.get(downloadId);
            if (r) r.vtDone = true;
            broadcastVtUpdate({ vtScore: null, vtRawStats: null });
            return;
        }

        // ── Poll for analysis results ──────────────────────────────────────
        const deadline = Date.now() + APP.VT_SUBMIT_POLL_DEADLINE_MS;
        while (Date.now() < deadline) {
            await new Promise(r => setTimeout(r, APP.VT_SUBMIT_POLL_INTERVAL_MS));

            const getResponse = await fetch(
                `https://www.virustotal.com/api/v3/urls/${urlId}`,
                { method: "GET", headers: { "x-apikey": settings.vtApiKey } }
            );
            if (!getResponse.ok) continue;

            const data    = await getResponse.json();
            const attrs   = data?.data?.attributes ?? {};
            const results = attrs.last_analysis_results ?? {};
            if (Object.keys(results).length === 0) continue; // not yet analysed

            const { eval: eval_, raw, filtered } = ScoringEngineV2.evaluateFromAnalysisResults(
                results, fpLevel, attrs.first_submission_date
            );

            const r = pendingChecks.get(downloadId);
            if (r) {
                r.vtDone         = true;
                r.vtScore         = eval_.score;
                r.vtConfidence    = eval_.confidence;
                r.vtBreakdown     = eval_.breakdown;
                r.vtHardRule      = eval_.hardRuleApplied;
                r.vtRawStats      = raw;
                r.vtFilteredStats = filtered;
                r.vtFpLevel       = fpLevel;
            }

            broadcastVtUpdate({
                vtScore:         eval_.score,
                vtConfidence:    eval_.confidence,
                vtBreakdown:     eval_.breakdown,
                vtHardRule:      eval_.hardRuleApplied,
                vtRawStats:      raw,
                vtFilteredStats: filtered,
                vtFpLevel:       fpLevel
            });
            return; // done
        }

        // Deadline exceeded — analysis never completed within the time budget
        const r = pendingChecks.get(downloadId);
        if (r) r.vtDone = true;
        broadcastVtUpdate({ vtScore: null, vtRawStats: null });

    } catch (err) {
        console.error("[DS:submitAndPollVt] error:", err?.message);
        const r = pendingChecks.get(downloadId);
        if (r) r.vtDone = true;
        // Notify warning page even on error so it does not wait indefinitely
        broadcastVtUpdate({ vtScore: null, vtRawStats: null });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Message router — single switch (audit item C3)
// ─────────────────────────────────────────────────────────────────────────────

// v3.3.0 (item 9) — the warning page's own URL is the only source of truth
// for "which download is this message about": it is set once, by this
// extension, when the window is created (openWarningPage above), and the
// sender can't rewrite it. A downloadId carried in the message body instead
// would let any of this extension's own pages read or dismiss ANY pending
// check just by naming its id. WARNING_PAGE_PATH is the single place that
// path is spelled out — both here and in openWarningPage() above.
const WARNING_PAGE_PATH = "pages/warning/WarningPage.html";
function downloadIdFromWarningPageSender(sender) {
    if (!sender?.url) return null;
    let parsed;
    try { parsed = new URL(sender.url); } catch { return null; }
    if (!parsed.pathname.endsWith("/" + WARNING_PAGE_PATH)) return null;
    const raw = parsed.searchParams.get("downloadId");
    const id  = Number.parseInt(raw, 10);
    return Number.isFinite(id) ? id : null;
}

// This extension's own origin ("chrome-extension://<id>/") — an extension-page sender's URL starts with it.
const EXTENSION_ORIGIN = chrome.runtime.getURL("");

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

    // Guard 1 — v3.3.0 (item 8) — fail CLOSED: a missing sender.id used to pass this
    // check (sender.extensionId && ... was only ever checked when the field
    // was present at all); only a confirmed match to our own extension id
    // is accepted now.
    if (!sender || sender.id !== chrome.runtime.id) return;

    // Guard 2 — v3.6.0 (3P Matrix 5.0.6 C46): the id alone is not enough — a content script carries it too.
    // Only this extension's own pages may talk to the router, and only with a known message type. A refusal is
    // logged with the sender's origin only (3P Matrix 5.0.7 C52 — a full address can carry a token).
    if (!MessageGate.isMessageAllowed(msg?.type, MessageGate.senderKind(sender, EXTENSION_ORIGIN))) {
        console.warn("[DS:router] refused", String(msg?.type), "from", MessageGate.senderLabel(sender));
        return;
    }

    switch (msg.type) {

        case MSG.GET_PENDING_CHECK: {
            const downloadId = downloadIdFromWarningPageSender(sender);
            sendResponse(downloadId === null ? null : (pendingChecks.get(downloadId) || null));
            return true;
        }

        case MSG.DISMISS_CHECK: {
            // User clicked OK or Check at VT — clean up all resources for this download
            const downloadId = downloadIdFromWarningPageSender(sender);
            if (downloadId === null) { sendResponse({ success: false, error: "not the warning page" }); return true; }
            releaseDownload(downloadId, "user dismissed");
            sendResponse({ success: true });
            return true;
        }

        case MSG.EXTENSION_TOGGLE:
            setExtensionIcon(msg.enabled);
            return true;

        case MSG.SETTINGS_UPDATED:
            loadCustomDomains();
            return true;

        case MSG.SUBMIT_URL_TO_VT: {
            // v3.6.0 — like GET_PENDING_CHECK / DISMISS_CHECK: the download is the one in the warning page's
            // own URL (v3.3.0 item 9), never a downloadId from the message body (3P Matrix C28).
            const downloadId = downloadIdFromWarningPageSender(sender);
            if (downloadId === null) { sendResponse({ success: false, error: "not the warning page" }); return true; }
            const record = pendingChecks.get(downloadId);
            if (!record) {
                sendResponse({ success: false, error: "Download not found" });
                return true;
            }

            Settings.get(settings => {
                if (!settings.isVtApiKeySet || !settings.vtApiKey) {
                    sendResponse({ success: false, error: "No VT API key" });
                    return;
                }

                const cleanUrl = UrlUtils.cleanUrl(record.url);
                const urlId    = UrlUtils.toVtUrlId(cleanUrl);

                record.vtDone = false;
                sendResponse({ success: true });

                // Delegate to the named helper (audit item C1 — no more inline IIFE)
                submitAndPollVt(downloadId, cleanUrl, urlId, settings);
            });
            return true;
        }

        default:
            // Unknown message type — ignore silently
            break;
    }
});
