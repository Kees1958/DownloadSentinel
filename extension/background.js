importScripts(
    "util/Storage.js",
    "util/Settings.js",
    "util/UrlUtils.js",
    "util/SuspiciousDomains.js",
    "util/SuspiciousTlds.js",
    "util/RiskyHostingSites.js",
    "util/FpReductionEngines.js",
    "protection/ProtectionResult.js",
    "protection/ScoringEngineV2.js",
    "protection/SketchyUrlCheck.js",
    "protection/MimeCheck.js",
    "protection/Quad9Protection.js",
    "protection/RdapProtection.js",
    "protection/BrowserProtection.js"
);

// ─────────────────────────────────────────────────────────────────────────────
// STATE OVERVIEW — for troubleshooting service worker restarts and races
// ─────────────────────────────────────────────────────────────────────────────
//
// STATELESS (recomputed fresh every call, safe across SW restarts):
//   - DANGEROUS_EXTS, ARCHIVE_EXTS, EXECUTABLE_MIMES, BUILTIN_DO_NOT_CHECK_DOMAINS
//     → static constants, never mutated
//   - getBlockedExtension(), isTrustedDomain(), buildVtBlockReason()
//     → pure functions, no shared state
//
// STATEFUL — IN-MEMORY ONLY (lost on every SW restart, ~30s idle timeout):
//   - blockedDownloads (Map)      → mirrored to chrome.storage.session, see below
//   - handledByOnCreated (Set)    → short-lived dedup flag between onCreated and
//                                    onDeterminingFilename for the same downloadId.
//                                    NOT persisted — safe to lose, worst case a
//                                    download gets checked by both listeners once.
//   - allowedDomains (Map)        → one-time bypass flags with 10s TTL, NOT
//                                    persisted. Safe to lose — only affects the
//                                    rare re-trigger-after-failed-resume path.
//   - runtimeCustomDomains (let)  → reloaded from chrome.storage.local on every
//                                    SW startup via loadCustomDomains(), so losing
//                                    it in-memory is harmless.
//
// STATEFUL — PERSISTED (chrome.storage):
//   - chrome.storage.session["blockedDownloads"]
//       Survives SW restart within the same browser session, lost on browser
//       close. Restored via restoreBlockedDownloads() at SW startup, exposed
//       as startupRestorePromise so listeners can await it before touching
//       the in-memory blockedDownloads map (avoids a restore-vs-new-download race).
//   - chrome.storage.local["Settings"]
//       User preferences (API key, FP level, custom domains, etc). Survives
//       browser restarts and extension updates. Read via Settings.get().
//
// CLEANUP / BOUNDS:
//   - blockedDownloads + handledByOnCreated: cleaned on cancel/allow button click,
//     on chrome.downloads.onErased, AND swept every 5 min for entries older than
//     30 min (sweepStaleEntries) as a safety net against orphaned popup windows
//     closed via the X button instead of Cancel/Proceed.
//   - allowedDomains: self-expiring via 10s TTL, also cleared on browser startup/install.
// ─────────────────────────────────────────────────────────────────────────────

const DANGEROUS_EXTS = [
    "bat","chm","cmd","com","cpl","dll","exe","hta",
    "jse","js","lnk","msc","msi","msp","mst",
    "pif","ps1","ps1xml","ps2","ps2xml","psc1",
    "psc2","scr","vb","vbe","vbs","wsf","wsh",
    "appimage","awk","bash","bin","csh","deb",
    "ksh","out","php","pl","pm","py","pyc",
    "pyo","rb","rpm","run","sed","sh","tcl",
    "tcsh","zsh","elf","jnlp",
    "action","app","applescript","command",
    "mpkg","pkg","scpt","tool","workflow"
];

// Subset of DANGEROUS_EXTS that are interpreted scripts rather than compiled
// binaries — these are commonly abused as LOLBins (Living Off The Land
// Binaries) since they execute via a trusted system interpreter (powershell,
// wscript, bash, python, etc.) rather than running as a standalone .exe.
// A script masquerading as a software download is a stronger anomaly signal
// than a plain executable, since legitimate installers are almost always
// compiled binaries, not raw scripts.
const SCRIPT_EXTS = [
    "bat","chm","cmd","hta","jse","js","lnk","msc",
    "ps1","ps1xml","ps2","ps2xml","psc1","psc2",
    "vb","vbe","vbs","wsf","wsh",
    "awk","bash","csh","ksh","php","pl","pm","py",
    "pyc","pyo","rb","sed","sh","tcl","tcsh","zsh",
    "applescript","command","scpt","workflow"
];

const ARCHIVE_EXTS = [
    "zip","rar","7z","tar","iso","cab",
    "tar.gz","tar.bz2","tar.xz","tar.zst","tar.lz",
    "tar.lzma","tar.lzo","tar.Z","tar.sz",
    "gz","tgz",
    "bz2","tbz","tbz2",
    "xz","txz",
    "zst","tzst",
    "lz","lzma","lzo","lz4","lz5",
    "Z",
    "msix","msixbundle","appx","appxbundle","wim","swm",
    "apk","snap","flatpak","cpio",
    "dmg","pkg","xip","sit","sitx","sea",
    "jar","war","ear",
    "arj","ace","arc","lha","lzh","zoo","alz",
    "pak","cba","cbr","cbz"
];

// MIME types that indicate executable content regardless of file extension
const EXECUTABLE_MIMES = new Set([
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/vnd.microsoft.portable-executable",
    "application/x-executable",
    "application/x-dosexec",
    "application/x-bat",
    "application/x-msi",
    "application/x-ms-installer",
    "application/x-powershell",
    "application/x-sh",
    "application/x-python",
    "application/x-perl",
    "application/x-php",
    "application/x-vbs",
    "application/x-javascript",
    "application/java-archive",
    "application/x-java-archive",
    "application/x-debian-package",
    "application/x-rpm",
    "application/x-appimage",
    "application/x-hta",
]);

// Built-in trusted domains — never checked
const BUILTIN_DO_NOT_CHECK_DOMAINS = [
    "chromewebstore.google.com",
    "drive.google.com",
    "apps.microsoft.com",
    "onedrive.live.com",
    "sharepoint.com",
    "apps.apple.com",
    "icloud.com"
];

let runtimeCustomDomains = [];

// Map of currently blocked downloads (keyed by downloadId)
const blockedDownloads = new Map();

// ── Persist blockedDownloads to session storage so it survives SW restart ──
function persistBlockedDownloads() {
    const obj = {};
    for (const [id, item] of blockedDownloads) obj[id] = item;
    chrome.storage.session.set({ blockedDownloads: obj }).catch(() => {});
}

async function restoreBlockedDownloads() {
    try {
        const result = await chrome.storage.session.get("blockedDownloads");
        const stored = result?.blockedDownloads || {};
        for (const [id, item] of Object.entries(stored)) {
            const numId = Number(id);
            if (!blockedDownloads.has(numId)) {
                blockedDownloads.set(numId, item);
            }
        }
    } catch { /* session storage unavailable */ }
}

// On SW startup, restore state and cancel any orphaned paused downloads.
// Exposed as a promise so onCreated/onDeterminingFilename can await it —
// without this, a download arriving in the brief restore window could have
// its fresh blockedDownloads entry silently overwritten by stale restored data.
const startupRestorePromise = (async () => {
    await restoreBlockedDownloads();
    // Cancel any downloads that were blocked but whose warning page is now gone
    for (const [id, item] of blockedDownloads) {
        if (item.state === "blocked") {
            chrome.downloads.cancel(id).catch(() => {});
            blockedDownloads.delete(id);
        }
    }
    persistBlockedDownloads();
})();

// Domains the user has explicitly allowed this session
// allowedDomains: one-time bypass flags for the re-triggered download fallback
// (see ALLOW_DOWNLOAD handler). Each entry has a short TTL so a stale flag can
// never silently bypass checks for more than a few seconds, even if some edge
// case prevents the normal delete-on-consume from firing.
const allowedDomains = new Map(); // domain -> expiry timestamp
const ALLOWED_DOMAIN_TTL_MS = 10000; // 10 s — long enough for the re-trigger to fire

function addAllowedDomain(domain) {
    if (!domain) return;
    allowedDomains.set(domain, Date.now() + ALLOWED_DOMAIN_TTL_MS);
}
function consumeAllowedDomain(domain) {
    if (!domain) return false;
    const expiry = allowedDomains.get(domain);
    allowedDomains.delete(domain);
    return expiry !== undefined && Date.now() < expiry;
}

// ── Icon helpers ──────────────────────────────────────────────────────────────

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

// ── Startup ───────────────────────────────────────────────────────────────────

function loadCustomDomains() {
    Settings.get(settings => {
        runtimeCustomDomains = Array.isArray(settings.customDomains)
            ? settings.customDomains
            : [];
        setExtensionIcon(settings.extensionEnabled !== false);
    });
}

chrome.runtime.onStartup.addListener(() => { allowedDomains.clear(); loadCustomDomains(); });
chrome.runtime.onInstalled.addListener(() => { allowedDomains.clear(); loadCustomDomains(); });
loadCustomDomains();

// ── Domain helpers ────────────────────────────────────────────────────────────

function getAllDoNotCheckDomains() {
    return [...BUILTIN_DO_NOT_CHECK_DOMAINS, ...runtimeCustomDomains];
}

function extractFilenameFromUrl(url) {
    try {
        const clean = url.split("#")[0];
        const qIdx  = clean.indexOf("?");
        const path  = qIdx === -1 ? clean : clean.substring(0, qIdx);
        const fromPath = path.substring(path.lastIndexOf("/") + 1).toLowerCase();

        if (fromPath.includes(".")) {
            const ext = getExtFromFilename(fromPath);
            if (ext !== null) return fromPath;
        }

        if (qIdx === -1) return fromPath || null;

        const qs = clean.substring(qIdx + 1);
        for (const param of qs.split("&")) {
            const [key, ...rest] = param.split("=");
            const k = key.toLowerCase();
            if (k === "response-content-disposition" || k === "rscd" || k === "content-disposition") {
                const val = decodeURIComponent(rest.join("=").replace(/\+/g, " "));
                const m   = val.match(/filename\s*=\s*["']?([^"';\s]+)/i);
                if (m) return m[1].toLowerCase();
            }
        }

        return fromPath || null;
    } catch {
        return null;
    }
}

function getExtFromFilename(file) {
    const parts   = file.split(".");
    if (parts.length < 2) return null;
    const lastTwo = parts.slice(-2).join(".");
    const lastOne = parts[parts.length - 1];
    if (ARCHIVE_EXTS.includes(lastTwo))   return lastTwo;
    if (DANGEROUS_EXTS.includes(lastOne)) return lastOne;
    if (ARCHIVE_EXTS.includes(lastOne))   return lastOne;
    return null;
}

function getBlockedExtension(url, filename) {
    if (filename) {
        const ext = getExtFromFilename(filename.toLowerCase());
        if (ext) return ext;
    }
    if (url) {
        const fromUrl = extractFilenameFromUrl(url);
        if (fromUrl) {
            const ext = getExtFromFilename(fromUrl);
            if (ext) return ext;
        }
    }
    return null;
}

function isTrustedDomain(url) {
    try {
        const hostname = new URL(url).hostname.toLowerCase();
        return getAllDoNotCheckDomains().some(d =>
            hostname === d || hostname.endsWith("." + d)
        );
    } catch { return false; }
}

function buildVtBlockReason(vtResult, defaultReason) {
    const verdict = vtResult?.result ?? ProtectionResult.ResultType.UNKNOWN;
    if (verdict === ProtectionResult.ResultType.UNKNOWN) {
        return `Unknown reputation — ${defaultReason}`;
    }
    const hasScore  = typeof vtResult?.score === "number";
    const scoreText = hasScore
        ? ` (score ${vtResult.score}, ${vtResult.confidence ?? "Low"} confidence)`
        : "";
    return `${verdict}${scoreText} — ${defaultReason}`;
}

function openWarningPage(downloadId) {
    chrome.windows.create({
        url:   chrome.runtime.getURL(`pages/warning/WarningPage.html?downloadId=${downloadId}`),
        type:  "popup",
        state: "maximized"
    });
}

// ── Download listener ─────────────────────────────────────────────────────────

chrome.downloads.onCreated.addListener(async downloadItem => {

    // ── KNOWN LIMITATION ─────────────────────────────────────────────────────
    // onCreated fires AFTER Chrome has already started the download. For very
    // small files (e.g. EICAR at 68 bytes) on a fast connection, the download
    // can COMPLETE before our pause() call is processed — meaning the file is
    // already on disk by the time we try to intercept it.
    //
    // Attempts to fix this via onDeterminingFilename + withheld suggest() were
    // made but broke normal downloads. The pendingBlock flag approach also failed
    // because the warning page opened before blockedDownloads was populated,
    // leaving the page stuck on "Loading...".
    //
    // Current mitigation: the warning page still opens and shows VT results,
    // and the disclaimer directs the user to check the file manually at VT.
    // A proper fix would require declarativeNetRequest to intercept the request
    // before it starts, rather than trying to pause after the fact.
    // ─────────────────────────────────────────────────────────────────────────

    // Mark synchronously before any await so onDeterminingFilename
    // sees it immediately and does not double-process this download.
    handledByOnCreated.add(downloadItem.id);

    // Guard against the SW-restart restore race: ensure blockedDownloads
    // has finished restoring before we read/write it below.
    await startupRestorePromise;

    const settings = await new Promise(resolve => Settings.get(resolve));
    if (!settings.extensionEnabled) {
        handledByOnCreated.delete(downloadItem.id); // not actually intercepting
        return;
    }

    const url         = downloadItem.finalUrl || downloadItem.url || "";
    const originalUrl = (downloadItem.url && downloadItem.url !== url) ? downloadItem.url : null;
    const domain = UrlUtils.getHostname(url);

    if (consumeAllowedDomain(domain)) {
        handledByOnCreated.delete(downloadItem.id);
        return;
    }

    if (isTrustedDomain(url)) {
        handledByOnCreated.delete(downloadItem.id);
        return;
    }

    const ext = getBlockedExtension(url, downloadItem.filename || "");

    const isArchive   = ext && ARCHIVE_EXTS.includes(ext);
    const isDangerous = ext && DANGEROUS_EXTS.includes(ext);

    // Even if extension is not blocked, intercept when MIME type reveals executable content
    const downloadMime   = (downloadItem.mime || "").split(";")[0].trim().toLowerCase();
    const isMimeExec     = !isDangerous && !isArchive && EXECUTABLE_MIMES.has(downloadMime);

    if (!isDangerous && !isArchive && !isMimeExec) {
        handledByOnCreated.delete(downloadItem.id); // not intercepting — let onDeterminingFilename handle if needed
        return;
    }

    const fileType      = (isDangerous || isMimeExec) ? "executable" : "archive";
    const defaultReason = (isDangerous || isMimeExec) ? "executable download" : "archive download";

    try {
        await chrome.downloads.pause(downloadItem.id);
    } catch (err) {
        console.warn("[DS] Could not pause download:", err);
    }

    // Initialise the blocked-download record
    blockedDownloads.set(downloadItem.id, {
        id:          downloadItem.id,
        createdAt:   Date.now(),
        url,
        originalUrl: originalUrl || url,
        ext,
        fileType,
        filename:   downloadItem.filename   || "",
        mime:       downloadItem.mime        || "",
        totalBytes: downloadItem.totalBytes  || 0,

        // VT fields
        vtStatus:               "pending",
        browserProtectionResult: "Blocked pending reputation check...",
        vtScore:                null,
        vtConfidence:           null,
        vtBreakdown:            null,
        vtHardRule:             null,
        vtRawStats:             null,
        vtFilteredStats:        null,
        vtFpLevel:              null,

        // Host-reputation fields
        hostStatus:             "pending",
        hostResult:             null,

        state: "blocked"
    });
    persistBlockedDownloads();

    openWarningPage(downloadItem.id);

    // ── Run VT and host-reputation checks simultaneously ──────────────────

    // A. Host reputation (Quad9 + RDAP + domain list + TLD list) — no API key needed
    BrowserProtection.checkHostReputation(url, fileType, ext, downloadItem.mime || "", downloadItem.totalBytes || 0, originalUrl, SCRIPT_EXTS.includes(ext)).then(hostResult => {
        const item = blockedDownloads.get(downloadItem.id);
        if (!item || item.state === "allowed") return;

        item.hostStatus = "done";
        item.hostResult = hostResult;

        chrome.runtime.sendMessage({
            type:       "HOST_RESULT_UPDATE",
            downloadId: downloadItem.id,
            hostResult
        }).catch(() => {});
    });

    // B. VT check — skip if no API key
    if (!settings.isVtApiKeySet || !settings.vtApiKey) {
        const item = blockedDownloads.get(downloadItem.id);
        if (item) {
            item.vtStatus                = "done";
            item.browserProtectionResult = `Reputation check not enabled — ${defaultReason}`;
        }
        return;
    }

    BrowserProtection.checkIfUrlIsMalicious(downloadItem.id, url, result => {
        const item = blockedDownloads.get(downloadItem.id);
        if (!item || item.state === "allowed") return;

        item.browserProtectionResult = buildVtBlockReason(result, defaultReason);
        item.vtStatus        = "done";
        item.vtScore         = result?.score           ?? null;
        item.vtConfidence    = result?.confidence      ?? null;
        item.vtBreakdown     = result?.breakdown       ?? null;
        item.vtHardRule      = result?.hardRuleApplied ?? null;
        item.vtRawStats      = result?.rawStats        ?? null;
        item.vtFilteredStats = result?.filteredStats   ?? null;
        item.vtFpLevel       = result?.fpLevel         ?? null;

        chrome.runtime.sendMessage({
            type:       "VT_RESULT_UPDATE",
            downloadId: downloadItem.id,
            browserProtectionResult: item.browserProtectionResult,
            vtScore:         item.vtScore,
            vtConfidence:    item.vtConfidence,
            vtBreakdown:     item.vtBreakdown,
            vtHardRule:      item.vtHardRule,
            vtRawStats:      item.vtRawStats,
            vtFilteredStats: item.vtFilteredStats,
            vtFpLevel:       item.vtFpLevel
        }).catch(() => {});
    }, originalUrl);
});


// Track download IDs already handled by onCreated (extension found in URL/filename)
// so onDeterminingFilename does not double-process them.
const handledByOnCreated = new Set();
const slippedThroughHandled = new Set(); // dedupe for post-download safety net — onChanged can fire multiple times per download

// ── Stale-entry sweep ────────────────────────────────────────────────────
// blockedDownloads and handledByOnCreated are only reliably cleaned up via
// onErased (fires when the user clears download history) or the cancel/allow
// button handlers. If a user closes the warning popup with the window X
// button instead of clicking a button, neither fires and the entries leak
// for the lifetime of the service worker. A periodic sweep removes anything
// older than 30 minutes as a safety net.
const ENTRY_MAX_AGE_MS = 30 * 60 * 1000; // 30 min

function sweepStaleEntries() {
    const cutoff = Date.now() - ENTRY_MAX_AGE_MS;
    for (const [id, item] of blockedDownloads) {
        const ts = item.createdAt || 0;
        if (ts && ts < cutoff) {
            blockedDownloads.delete(id);
            handledByOnCreated.delete(id);
            slippedThroughHandled.delete(id);
            BrowserProtection.abandonPendingRequests(id, "stale entry swept");
        }
    }
    // handledByOnCreated entries without a matching blockedDownloads record
    // (e.g. early-return paths that somehow missed cleanup) — safe to drop
    // anything not actively tracked, since handledByOnCreated is only a
    // short-lived dedup flag during the onCreated/onDeterminingFilename race.
    for (const id of handledByOnCreated) {
        if (!blockedDownloads.has(id)) handledByOnCreated.delete(id);
    }
    persistBlockedDownloads();
}
// chrome.alarms instead of setInterval — setInterval does NOT survive MV3
// service worker restarts (Chrome terminates the SW after ~30s idle), so the
// "every 5 min" guarantee was unreliable in practice. Alarms persist across
// SW restarts and are the MV3-correct way to schedule recurring background work.
chrome.alarms.create("sweepStaleEntries", { periodInMinutes: 5 });
chrome.alarms.onAlarm.addListener(alarm => {
    if (alarm.name === "sweepStaleEntries") sweepStaleEntries();
});

chrome.downloads.onDeterminingFilename.addListener((downloadItem, suggest) => {
    // Check if this is a dangerous file BEFORE calling suggest()
    // so we can set a pendingBlock flag that onCreated can read.
    const filename    = downloadItem.filename || "";
    const url         = downloadItem.finalUrl || downloadItem.url || "";
    const originalUrl = (downloadItem.url && downloadItem.url !== url) ? downloadItem.url : null;

    // Always let Chrome proceed with its suggested filename immediately
    suggest();

    // Skip if onCreated already intercepted this download
    if (handledByOnCreated.has(downloadItem.id)) return;

    // Only act when the resolved filename reveals a blocked extension
    const ext = getBlockedExtension(url, filename);
    if (!ext) return;

    const isArchive   = ARCHIVE_EXTS.includes(ext);
    const isDangerous = DANGEROUS_EXTS.includes(ext);
    const resolveMime = (downloadItem.mime || "").split(";")[0].trim().toLowerCase();
    const isMimeExec  = !isDangerous && !isArchive && EXECUTABLE_MIMES.has(resolveMime);

    if (!isDangerous && !isArchive && !isMimeExec) return;

    // ── Full sanitizing pass (mirrors onCreated) ──────────────────────────

    Settings.get(async settings => {
        if (!settings.extensionEnabled) return;

        // Domain-level checks
        const domain = UrlUtils.getHostname(url);

        if (consumeAllowedDomain(domain)) {
            return;
        }

        if (isTrustedDomain(url)) return;

        // At this point we know it should be intercepted
        const fileType      = (isDangerous || isMimeExec) ? "executable" : "archive";
        const defaultReason = (isDangerous || isMimeExec) ? "executable download" : "archive download";

        try {
            await chrome.downloads.pause(downloadItem.id);
        } catch (err) {
            console.warn("[DS] onDeterminingFilename: could not pause download:", err);
        }

        blockedDownloads.set(downloadItem.id, {
            id:          downloadItem.id,
        createdAt:   Date.now(),
            url,
            originalUrl: originalUrl || url,
            ext,
            fileType,
            filename,
            mime:       downloadItem.mime       || "",
            totalBytes: downloadItem.totalBytes || 0,

            // VT fields
            vtStatus:                "pending",
            browserProtectionResult: "Blocked pending reputation check...",
            vtScore:                 null,
            vtConfidence:            null,
            vtBreakdown:             null,
            vtHardRule:              null,

            // Host-reputation fields
            hostStatus:  "pending",
            hostResult:  null,

            state: "blocked"
        });
        persistBlockedDownloads();

        openWarningPage(downloadItem.id);

        // A. Host reputation
        BrowserProtection.checkHostReputation(url, fileType, ext, downloadItem.mime || "", downloadItem.totalBytes || 0, originalUrl, SCRIPT_EXTS.includes(ext)).then(hostResult => {
            const item = blockedDownloads.get(downloadItem.id);
            if (!item || item.state === "allowed") return;

            item.hostStatus = "done";
            item.hostResult = hostResult;

            chrome.runtime.sendMessage({
                type:       "HOST_RESULT_UPDATE",
                downloadId: downloadItem.id,
                hostResult
            }).catch(() => {});
        });

        // B. VT check — skip if no API key
        if (!settings.isVtApiKeySet || !settings.vtApiKey) {
            const item = blockedDownloads.get(downloadItem.id);
            if (item) {
                item.vtStatus                = "done";
                item.browserProtectionResult = `Reputation check not enabled — ${defaultReason}`;
            }
            return;
        }

        BrowserProtection.checkIfUrlIsMalicious(downloadItem.id, url, result => {
            const item = blockedDownloads.get(downloadItem.id);
            if (!item || item.state === "allowed") return;

            item.browserProtectionResult = buildVtBlockReason(result, defaultReason);
            item.vtStatus        = "done";
            item.vtScore         = result?.score           ?? null;
            item.vtConfidence    = result?.confidence      ?? null;
            item.vtBreakdown     = result?.breakdown       ?? null;
            item.vtHardRule      = result?.hardRuleApplied ?? null;
            item.vtRawStats      = result?.rawStats        ?? null;
            item.vtFilteredStats = result?.filteredStats   ?? null;
            item.vtFpLevel       = result?.fpLevel         ?? null;

            chrome.runtime.sendMessage({
                type:       "VT_RESULT_UPDATE",
                downloadId: downloadItem.id,
                browserProtectionResult: item.browserProtectionResult,
                vtScore:         item.vtScore,
                vtConfidence:    item.vtConfidence,
                vtBreakdown:     item.vtBreakdown,
                vtHardRule:      item.vtHardRule,
                vtRawStats:      item.vtRawStats,
                vtFilteredStats: item.vtFilteredStats,
                vtFpLevel:       item.vtFpLevel
            }).catch(() => {});
        }, originalUrl);
    });
});

chrome.downloads.onErased.addListener(downloadId => {
    blockedDownloads.delete(downloadId);
    handledByOnCreated.delete(downloadId);
    BrowserProtection.abandonPendingRequests(downloadId, "download erased");
});

// ── Post-download safety net ────────────────────────────────────────────────
//
// Covers the known race condition (see onCreated comment above) where small
// or fast-completing files finish downloading before pause() can intercept
// them. This cannot prevent the file from landing on disk, but it gives the
// user a clear after-the-fact warning and the same VT/heuristics breakdown
// they'd have seen if the pause had succeeded.
//
// Detection: a download is "slipped through" if it has a dangerous extension
// or executable MIME type, has reached state "complete", and was never
// properly intercepted (no blockedDownloads entry — onCreated either never
// fired in time, or fired but the pause lost the race before it landed in
// the map).
//
// We deliberately do NOT attempt a file-hash VT lookup here: reading the
// downloaded file's bytes would require chrome.fileSystem or native messaging,
// a much broader permission than this extension currently requests. The
// safety net reuses the existing URL-based VT/heuristics check instead.
chrome.downloads.onChanged.addListener(async delta => {
    if (!delta.state || delta.state.current !== "complete") return;
    if (slippedThroughHandled.has(delta.id)) return;

    // If we already have a record for this download, it was handled normally
    // (cancelled, allowed, or still legitimately pending) — nothing to do.
    if (blockedDownloads.has(delta.id)) return;
    if (handledByOnCreated.has(delta.id)) return; // currently being processed

    try {
        const results = await chrome.downloads.search({ id: delta.id });
        const item = results?.[0];
        if (!item) return;

        const settings = await new Promise(resolve => Settings.get(resolve));
        if (!settings.extensionEnabled) return;

        const url    = item.finalUrl || item.url || "";
        const domain = UrlUtils.getHostname(url);
        if (isTrustedDomain(url)) return;

        const ext = getBlockedExtension(url, item.filename || "");
        const isArchive   = ext && ARCHIVE_EXTS.includes(ext);
        const isDangerous = ext && DANGEROUS_EXTS.includes(ext);
        const downloadMime = (item.mime || "").split(";")[0].trim().toLowerCase();
        const isMimeExec   = !isDangerous && !isArchive && EXECUTABLE_MIMES.has(downloadMime);

        if (!isDangerous && !isArchive && !isMimeExec) return;

        slippedThroughHandled.add(delta.id);

        // Build a minimal blockedDownloads-style record so the warning page's
        // existing rendering logic (VT details, heuristics, score) works
        // unmodified — state "slipped_through" disables Cancel/Proceed since
        // the file already exists on disk.
        const fileType = (isDangerous || isMimeExec) ? "executable" : "archive";
        blockedDownloads.set(delta.id, {
            id:          delta.id,
            url,
            originalUrl: url,
            ext,
            fileType,
            filename:    item.filename || "",
            mime:        item.mime || "",
            totalBytes:  item.totalBytes || item.fileSize || 0,
            createdAt:   Date.now(),

            vtStatus:                "pending",
            browserProtectionResult: "Checking after-the-fact (file already downloaded)...",
            vtScore: null, vtConfidence: null, vtBreakdown: null, vtHardRule: null,
            vtRawStats: null, vtFilteredStats: null, vtFpLevel: null,

            hostStatus: "pending",
            hostResult: null,

            slippedThrough: true, // tells WarningPage.js to show the post-download disclaimer
            state: "slipped_through"
        });
        persistBlockedDownloads();

        chrome.windows.create({
            url:   chrome.runtime.getURL(`pages/warning/WarningPage.html?downloadId=${delta.id}`),
            type:  "popup",
            state: "maximized"
        });

        // Run the same checks as a normal interception — host reputation first
        BrowserProtection.checkHostReputation(url, fileType, ext, item.mime || "", item.totalBytes || 0, null, SCRIPT_EXTS.includes(ext)).then(hostResult => {
            const record = blockedDownloads.get(delta.id);
            if (!record) return;
            record.hostStatus = "done";
            record.hostResult = hostResult;
            chrome.runtime.sendMessage({
                type: "HOST_RESULT_UPDATE", downloadId: delta.id, hostResult
            }).catch(() => {});
        });

        if (!settings.isVtApiKeySet || !settings.vtApiKey) {
            const record = blockedDownloads.get(delta.id);
            if (record) {
                record.vtStatus = "done";
                record.browserProtectionResult = "Reputation check not enabled — file already downloaded";
            }
            return;
        }

        BrowserProtection.checkIfUrlIsMalicious(delta.id, url, result => {
            const record = blockedDownloads.get(delta.id);
            if (!record) return;

            record.browserProtectionResult = buildVtBlockReason(result, "file already downloaded");
            record.vtStatus        = "done";
            record.vtScore         = result?.score           ?? null;
            record.vtConfidence    = result?.confidence       ?? null;
            record.vtBreakdown     = result?.breakdown        ?? null;
            record.vtHardRule      = result?.hardRuleApplied  ?? null;
            record.vtRawStats      = result?.rawStats         ?? null;
            record.vtFilteredStats = result?.filteredStats    ?? null;
            record.vtFpLevel       = result?.fpLevel          ?? null;

            chrome.runtime.sendMessage({
                type:       "VT_RESULT_UPDATE",
                downloadId: delta.id,
                browserProtectionResult: record.browserProtectionResult,
                vtScore: record.vtScore, vtConfidence: record.vtConfidence,
                vtBreakdown: record.vtBreakdown, vtHardRule: record.vtHardRule,
                vtRawStats: record.vtRawStats, vtFilteredStats: record.vtFilteredStats,
                vtFpLevel: record.vtFpLevel
            }).catch(() => {});
        }, null);

    } catch (err) {
        console.warn("[DS] Post-download safety net error:", err);
    }
});

// ── Message listener ──────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

    if (msg.type === "GET_BLOCKED_DOWNLOAD") {
        sendResponse(blockedDownloads.get(msg.downloadId) || null);
        return true;
    }

    if (msg.type === "EXTENSION_TOGGLE") {
        setExtensionIcon(msg.enabled);
        return true;
    }

    if (msg.type === "SETTINGS_UPDATED") {
        loadCustomDomains();
        return true;
    }

    // ── Submit URL to VT for fresh analysis ───────────────────────────────
    if (msg.type === "SUBMIT_URL_TO_VT") {
        const item = blockedDownloads.get(msg.downloadId);
        if (!item) { sendResponse({ success: false, error: "Download not found" }); return true; }

        Settings.get(settings => {
            if (!settings.isVtApiKeySet || !settings.vtApiKey) {
                sendResponse({ success: false, error: "No VT API key" });
                return;
            }

            const cleanUrl = UrlUtils.cleanUrl(item.url);
            const urlId    = UrlUtils.toVtUrlId(cleanUrl);
            const defaultReason = ARCHIVE_EXTS.includes(item.ext)
                ? "archive download" : "executable download";

            item.vtStatus                = "pending";
            item.browserProtectionResult = "Submitting URL to VirusTotal...";
            sendResponse({ success: true });

            (async () => {
                try {
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
                        item.vtStatus                = "done";
                        item.browserProtectionResult = `Submission failed — ${defaultReason}`;
                        chrome.runtime.sendMessage({
                            type: "VT_RESULT_UPDATE", downloadId: msg.downloadId,
                            browserProtectionResult: item.browserProtectionResult,
                            vtScore: null, vtConfidence: null, vtBreakdown: null, vtHardRule: null
                        }).catch(() => {});
                        return;
                    }

                    // Poll VT until at least one engine has responded (max 15 s)
                    const deadline  = Date.now() + 15000;
                    let evaluation  = null;

                    while (Date.now() < deadline) {
                        await new Promise(r => setTimeout(r, 1000));

                        const getResponse = await fetch(
                            `https://www.virustotal.com/api/v3/urls/${urlId}`,
                            { method: "GET", headers: { "x-apikey": settings.vtApiKey } }
                        );
                        if (!getResponse.ok) continue;

                        const data       = await getResponse.json();
                        const attributes = data?.data?.attributes || {};
                        const stats      = attributes.last_analysis_stats || {};

                        const totalEngines = Object.values(stats).reduce((s, v) => s + v, 0);
                        if (totalEngines === 0) continue;

                        evaluation = ScoringEngineV2.evaluate({
                            stats,
                            firstSubmissionDate: attributes.first_submission_date || null
                        });
                        break;
                    }

                    if (!evaluation) {
                        item.vtStatus                = "done";
                        item.browserProtectionResult = `Reputation check timed out — ${defaultReason}`;
                        chrome.runtime.sendMessage({
                            type: "VT_RESULT_UPDATE", downloadId: msg.downloadId,
                            browserProtectionResult: item.browserProtectionResult,
                            vtScore: null, vtConfidence: null, vtBreakdown: null, vtHardRule: null
                        }).catch(() => {});
                        return;
                    }

                    item.vtStatus        = "done";
                    item.vtScore         = evaluation.score;
                    item.vtConfidence    = evaluation.confidence;
                    item.vtBreakdown     = evaluation.breakdown;
                    item.vtHardRule      = evaluation.hardRuleApplied;
                    item.browserProtectionResult = buildVtBlockReason(
                        { result: evaluation.classification, score: evaluation.score, confidence: evaluation.confidence },
                        defaultReason
                    );

                    chrome.runtime.sendMessage({
                        type: "VT_RESULT_UPDATE", downloadId: msg.downloadId,
                        browserProtectionResult: item.browserProtectionResult,
                        vtScore:      item.vtScore,
                        vtConfidence: item.vtConfidence,
                        vtBreakdown:  item.vtBreakdown,
                        vtHardRule:   item.vtHardRule
                    }).catch(() => {});

                } catch (err) {
                    console.error("[DS:submit] error:", err?.message, err?.stack);
                    item.vtStatus                = "done";
                    item.browserProtectionResult = `Submission error — ${defaultReason}`;
                    chrome.runtime.sendMessage({
                        type: "VT_RESULT_UPDATE", downloadId: msg.downloadId,
                        browserProtectionResult: item.browserProtectionResult,
                        vtScore: null, vtConfidence: null, vtBreakdown: null, vtHardRule: null
                    }).catch(() => {});
                }
            })();
        });

        return true;
    }

    // ── Cancel / Allow ────────────────────────────────────────────────────

    if (msg.type === "CANCEL_DOWNLOAD") {
        const item = blockedDownloads.get(msg.downloadId);
        if (!item) { sendResponse({ success: false }); return true; }

        // Slipped-through downloads already completed — nothing to cancel.
        // Just clean up the record so the popup can close cleanly.
        if (item.state === "slipped_through") {
            BrowserProtection.abandonPendingRequests(msg.downloadId, "slipped-through review closed");
            blockedDownloads.delete(msg.downloadId);
            persistBlockedDownloads();
            sendResponse({ success: true });
            return true;
        }

        BrowserProtection.abandonPendingRequests(msg.downloadId, "user cancelled download");
        item.state = "cancelled";
        chrome.downloads.cancel(msg.downloadId, () => {
            blockedDownloads.delete(msg.downloadId);
            persistBlockedDownloads();
            sendResponse({ success: true });
        });
        return true;
    }

    if (msg.type === "ALLOW_DOWNLOAD") {
        const item = blockedDownloads.get(msg.downloadId);
        if (!item) { sendResponse({ success: false }); return true; }

        BrowserProtection.abandonPendingRequests(item.id, "user allowed download");
        item.state = "allowed";
        persistBlockedDownloads();

        chrome.downloads.resume(msg.downloadId, () => {
            if (chrome.runtime.lastError) {
                const domain = UrlUtils.getHostname(item.url);
                addAllowedDomain(domain);
                chrome.downloads.download({ url: item.url }, newId => {
                    // Always remove the one-time bypass flag — whether the
                    // re-triggered download succeeded or failed. Previously this
                    // only deleted on error, leaving the domain permanently
                    // whitelisted on success and silently bypassing all future
                    // downloads from that domain (no warning page at all).
                    // Also backstopped by a 10s TTL in case this delete is ever skipped.
                    allowedDomains.delete(domain);
                    if (chrome.runtime.lastError) {
                        sendResponse({ success: false, error: chrome.runtime.lastError.message });
                        return;
                    }
                    blockedDownloads.delete(msg.downloadId);
                    sendResponse({ success: true, downloadId: newId });
                });
                return;
            }
            blockedDownloads.delete(msg.downloadId);
            sendResponse({ success: true, downloadId: msg.downloadId });
        });

        return true;
    }
});
