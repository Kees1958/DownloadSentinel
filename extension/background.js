importScripts(
  "util/Storage.js",
  "util/Settings.js",
  "protection/ProtectionResult.js",
  "protection/ScoringEngine.js",
  "protection/BrowserProtection.js"
);

const DANGEROUS_EXTS = [
    "bat","chm","cmd","com","cpl","dll","exe","hta",
    "jse","js","lnk","msc","msi","msp","mst",
    "pif","ps1","ps1xml","ps2","ps2xml","psc1",
    "psc2","scr","vb","vbe","vbs","wsf","wsh",
    "appimage","awk","bash","bin","csh","deb",
    "ksh","out","php","pl","pm","py","pyc",
    "pyo","rb","rpm","run","sed","sh","tcl",
    "tcsh","zsh","elf","jar","java","dmg","jnlp",
    "action","app","applescript","command",
    "mpkg","pkg","scpt","tool","workflow"
];

const ARCHIVE_EXTS = [
  "zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "iso",
  "cab", "msi", "msix", "msixbundle", "appx", "appxbundle",
  "deb", "rpm", "apk", "snap", "flatpak", "appimage",
  "dmg", "pkg", "mpkg", "xip"
];

// Built-in domains that are never checked
const BUILTIN_DO_NOT_CHECK_DOMAINS = [
    "chromewebstore.google.com",
    "drive.google.com",
    "apps.microsoft.com",
    "onedrive.live.com",
    "sharepoint.com",
    "apps.apple.com",
    "icloud.com"
];

// Runtime cache of custom domains from settings (refreshed on startup + settings update)
let runtimeCustomDomains = [];

// Map to keep track of blocked downloads
const blockedDownloads = new Map();

// Set of domains that the user has explicitly allowed (per-session)
const allowedDomains = new Set();

// ── Icon helpers ───────────────────────────────────────────────────────────────

function setExtensionIcon(enabled) {
    const suffix = enabled ? "" : "_OFF";
    chrome.action.setIcon({
        path: {
            "16":  `assets/icons/icon16${suffix}.png`,
            "24":  `assets/icons/icon24${suffix}.png`,
            "32":  `assets/icons/icon32${suffix}.png`,
            "48":  `assets/icons/icon48${suffix}.png`,
            "128": `assets/icons/icon128${suffix}.png`
        }
    });
}

// ── Startup ────────────────────────────────────────────────────────────────────

function loadCustomDomains() {
    Settings.get(settings => {
        runtimeCustomDomains = Array.isArray(settings.customDomains)
            ? settings.customDomains
            : [];
        setExtensionIcon(settings.extensionEnabled !== false);
    });
}

chrome.runtime.onStartup.addListener(() => {
    allowedDomains.clear();
    loadCustomDomains();
});

chrome.runtime.onInstalled.addListener(() => {
    allowedDomains.clear();
    loadCustomDomains();
});

// Load immediately when the service worker starts
loadCustomDomains();

// ── Domain helpers ─────────────────────────────────────────────────────────────

function getAllDoNotCheckDomains() {
    return [...BUILTIN_DO_NOT_CHECK_DOMAINS, ...runtimeCustomDomains];
}

function getBlockedExtension(url) {
    if (!url) return null;
    try {
        const clean = url.split("#")[0].split("?")[0];
        const file  = clean.substring(clean.lastIndexOf("/") + 1);
        const dot   = file.lastIndexOf(".");
        if (dot === -1) return null;
        const ext = file.substring(dot + 1).toLowerCase();
        return (DANGEROUS_EXTS.includes(ext) || ARCHIVE_EXTS.includes(ext)) ? ext : null;
    } catch {
        return null;
    }
}

function isTrustedDomain(url) {
    try {
        const hostname = new URL(url).hostname.toLowerCase();
        return getAllDoNotCheckDomains().some(d =>
            hostname === d || hostname.endsWith("." + d)
        );
    } catch { return false; }
}

function getDomain(url) {
    try { return new URL(url).hostname.toLowerCase(); }
    catch { return null; }
}

function buildBlockReason(vtResult, defaultReason) {
    const verdict = vtResult?.result || "Unknown";

    if (verdict === ProtectionResult.ResultType.FAILED) {
        return `Reputation check failed — ${defaultReason}`;
    }
    if (verdict === ProtectionResult.ResultType.UNKNOWN) {
        return `Unknown reputation — ${defaultReason}`;
    }

    // One of the four scored classifications (Probably Safe / Questionable / Suspicious / Malicious)
    const hasScore = typeof vtResult?.score === "number";
    const scoreText = hasScore
        ? ` (score ${vtResult.score}, ${vtResult.confidence || "Low"} confidence)`
        : "";

    return `${verdict}${scoreText} — ${defaultReason}`;
}

function openWarningPage(downloadId) {
    chrome.windows.create({
        url: chrome.runtime.getURL(
            `pages/warning/WarningPage.html?downloadId=${downloadId}`
        ),
        type: "popup",
        state: "maximized"
    });
}

// ── Download listener ──────────────────────────────────────────────────────────

chrome.downloads.onCreated.addListener(async downloadItem => {

    // ── FIRST CHECK: is extension enabled? ──
    const settings = await new Promise(resolve => Settings.get(resolve));
    if (!settings.extensionEnabled) return;

    const url = downloadItem.finalUrl || downloadItem.url || "";

    const domain = getDomain(url);
    if (domain && allowedDomains.has(domain)) {
        allowedDomains.delete(domain);
        return;
    }

    if (isTrustedDomain(url)) return;

    const ext         = getBlockedExtension(url);
    const isArchive   = ext && ARCHIVE_EXTS.includes(ext);
    const isDangerous = ext && DANGEROUS_EXTS.includes(ext);

    if (!isDangerous && !isArchive) return;

    const defaultReason = isDangerous
        ? "executable download"
        : "archive download";

    try {
        await chrome.downloads.cancel(downloadItem.id);
    } catch (err) {
        console.warn("[DownloadProtection] Could not cancel download", err);
    }

    blockedDownloads.set(downloadItem.id, {
        id: downloadItem.id,
        url,
        ext,
        filename: downloadItem.filename || "",
        browserProtectionResult: "Blocked pending reputation check...",
        vtStatus: "pending",
        vtScore: null,
        vtConfidence: null,
        vtBreakdown: null,
        vtHardRule: null,
        state: "blocked"
    });

    openWarningPage(downloadItem.id);

    // VT check — skip entirely if no API key; mark done so the warning page stops polling
    if (!settings.isVtApiKeySet || !settings.vtApiKey) {
        const item = blockedDownloads.get(downloadItem.id);
        if (item) {
            item.vtStatus = "done";
            item.browserProtectionResult = `Reputation check not enabled — ${defaultReason}`;
        }
        return;
    }

    BrowserProtection.checkIfUrlIsMalicious(downloadItem.id, url, (result) => {
        const item = blockedDownloads.get(downloadItem.id);
        if (!item || item.state === "allowed") return;

        item.browserProtectionResult = buildBlockReason(result, defaultReason);
        item.vtStatus = "done";
        item.vtScore = result?.score ?? null;
        item.vtConfidence = result?.confidence ?? null;
        item.vtBreakdown = result?.breakdown ?? null;
        item.vtHardRule = result?.hardRuleApplied ?? null;

        chrome.runtime.sendMessage({
            type: "VT_RESULT_UPDATE",
            downloadId: downloadItem.id,
            browserProtectionResult: item.browserProtectionResult,
            vtScore: item.vtScore,
            vtConfidence: item.vtConfidence,
            vtBreakdown: item.vtBreakdown,
            vtHardRule: item.vtHardRule
        }).catch(() => {});
    });
});

chrome.downloads.onErased.addListener(downloadId => {
    blockedDownloads.delete(downloadId);
    BrowserProtection.abandonPendingRequests(downloadId, "download erased");
});

// ── Message listener ───────────────────────────────────────────────────────────

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

    if (msg.type === "ALLOW_DOWNLOAD") {
        const item = blockedDownloads.get(msg.downloadId);
        if (!item) { sendResponse({ success: false }); return true; }

        BrowserProtection.abandonPendingRequests(item.id, "user allowed download");
        item.state = "allowed";

        const domain = getDomain(item.url);
        if (domain) allowedDomains.add(domain);

        chrome.downloads.download({ url: item.url }, newId => {
            if (chrome.runtime.lastError) {
                if (domain) allowedDomains.delete(domain);
                sendResponse({ success: false, error: chrome.runtime.lastError.message });
                return;
            }
            blockedDownloads.delete(msg.downloadId);
            sendResponse({ success: true, downloadId: newId });
        });

        return true;
    }
});


