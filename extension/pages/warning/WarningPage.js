// ── Setup ──────────────────────────────────────────────────────────────────────

const params     = new URLSearchParams(location.search);
const downloadId = Number(params.get("downloadId"));

// Mirrors SCRIPT_EXTS in background.js — used here only to decide whether to
// show the executable-specific "check at VirusTotal" nudge (scripts already
// get their own dedicated negative-signal bullet from ScoringEngineV2, so we
// avoid showing both for the same file).
const SCRIPT_EXTS_CLIENT = [
    "bat","chm","cmd","hta","jse","js","lnk","msc",
    "ps1","ps1xml","ps2","ps2xml","psc1","psc2",
    "vb","vbe","vbs","wsf","wsh",
    "awk","bash","csh","ksh","php","pl","pm","py",
    "pyc","pyo","rb","sed","sh","tcl","tcsh","zsh",
    "applescript","command","scpt","workflow"
];

if (!downloadId) {
    document.body.innerHTML = "<p style='color:white;padding:2rem'>Invalid warning page — no download ID found.</p>";
    throw new Error("[DownloadSentinel] WarningPage opened without a valid downloadId");
}

// ── DOM refs ───────────────────────────────────────────────────────────────────

const reasonText            = document.getElementById("reasonText");
const srcUrl                = document.getElementById("srcUrl");

// Host reputation summary
const hostBox               = document.getElementById("hostBox");
const hostResult            = document.getElementById("hostResult");
const hostLabel             = document.getElementById("hostLabel");

// Combined details box
const combinedDetailsBox    = document.getElementById("combinedDetailsBox");
const vtSectionHeader       = document.getElementById("vtSectionHeader");
const vtUnknownLine         = document.getElementById("vtUnknownLine");
const vtDetailsList         = document.getElementById("vtDetailsList");
const vtClassificationLine  = document.getElementById("vtClassificationLine");
const heuristicsBox         = document.getElementById("heuristicsBox");
const hostDetailsList       = document.getElementById("hostDetailsList");

// Score bar
const worstScoreBox         = document.getElementById("worstScoreBox");
const worstScoreValue       = document.getElementById("worstScoreValue");
const worstScoreBarFill     = document.getElementById("worstScoreBarFill");
const scoreExplanation      = document.getElementById("scoreExplanation");

const btnBack               = document.getElementById("btn-back");
const btnAllow              = document.getElementById("btn-allow");
const disclaimer            = document.getElementById("disclaimerText");

let vtDone   = false;
let hostDone = false;

let currentVtScore   = null;
let currentHostScore = null;
let lastHostData     = null;
let lastVtData       = null;  // last full VT data received

// ── Settings ───────────────────────────────────────────────────────────────────

function applySettings(settings) {
    const r = settings.warningColorR ?? 179;
    const g = settings.warningColorG ?? 38;
    const b = settings.warningColorB ?? 30;
    document.body.style.backgroundColor = `rgb(${r}, ${g}, ${b})`;

    if (settings.isVtApiKeySet && settings.vtApiKey) {
        disclaimer.innerHTML =
            '<span style="color:#fff;">This is what VT knows about the download URL, please </span>' +
            vtManualCheckLink('https://www.virustotal.com/gui/home/url') +
            'check the download manually at VT</a>';
    } else {
        disclaimer.innerHTML =
            '<span style="color:#fff;">Reputation check not activated, please </span>' +
            '<a href="https://www.virustotal.com/gui/join-us" target="_blank" ' +
            'style="color:rgb(243,186,34);font-weight:600;text-decoration:none;">' +
            'get a free VT API key</a>' +
            '<span style="color:#fff;"> or </span>' +
            vtManualCheckLink('https://www.virustotal.com/gui/home/file') +
            'check the download manually at VT</a>';
    }
}

function applyVtUnknownDisclaimer() {
    disclaimer.innerHTML =
        '<span style="color:#fff;">Download URL unknown at VirusTotal, please </span>' +
        vtManualCheckLink('https://www.virustotal.com/gui/home/file') +
        'check the download manually at VT</a>';
}


Settings.get(applySettings);

// ── Manual VT check — cancel download first, then open VT ────────────────────
function vtManualCheckLink(vtUrl) {
    return `<a href="#" class="vt-manual-link" data-vt-url="${vtUrl}" ` +
           'style="color:rgb(243,186,34);font-weight:600;text-decoration:none;">';
}

document.addEventListener("click", e => {
    const link = e.target.closest(".vt-manual-link");
    if (!link) return;
    e.preventDefault();
    const vtUrl = link.dataset.vtUrl;
    // Cancel the paused download and clean up, then open VT
    chrome.runtime.sendMessage({ type: "CANCEL_DOWNLOAD", downloadId }, () => {
        if (vtUrl) chrome.tabs.create({ url: vtUrl });
        window.close();
    });
});

// ── Score bar ──────────────────────────────────────────────────────────────────

function renderScoreBar(valueEl, fillEl, score) {
    const isPositive = score >= 0;
    const magnitude  = Math.min(100, Math.abs(score));
    valueEl.textContent = `${isPositive ? "+" : ""}${score}%`;
    valueEl.className   = "score-bar-value " + (isPositive ? "positive" : "negative");
    fillEl.className    = "score-bar-fill "  + (isPositive ? "positive" : "negative");
    fillEl.style.width  = `${magnitude}%`;
}

function confidenceLabel(score) {
    const sign = score >= 0 ? "+" : "";
    return `${sign}${score}%`;
}

function confidenceColor(score) {
    if (score >= 30)  return "#34d399"; // green
    if (score >= -30) return "#ffffff"; // white — inconclusive
    if (score >= -60) return "#fbbf24"; // yellow — suspicious
    return "#ef4444";                   // red — malicious
}

function updateCombinedScore() {
    // Overall score = VT score + host score (additive).
    // Shows progressively: host score first, updates when VT arrives.
    const hasVt   = currentVtScore   !== null;
    const hasHost = currentHostScore !== null;

    if (!hasVt && !hasHost) {
        worstScoreBox.style.display = "none";
        return;
    }

    const combined = Math.max(-100, Math.min(100,
        (hasVt   ? currentVtScore   : 0) +
        (hasHost ? currentHostScore : 0)
    ));

    worstScoreBox.style.display = "";
    renderScoreBar(worstScoreValue, worstScoreBarFill, combined);
    scoreExplanation.style.display = "none";

    // Colour the Download URL Reputation label to match combined score
    if (hostLabel) {
        hostLabel.className = "label label-" + vtScoreToStyle(combined);
    }

    // VT confidence label
    const vtScoreRow = document.getElementById("vtScoreRow");
    const vtScoreVal = document.getElementById("vtScoreValue");
    if (vtScoreRow && hasVt) {
        vtScoreRow.style.display  = "";
        vtScoreVal.textContent    = confidenceLabel(currentVtScore);
        vtScoreVal.style.color    = confidenceColor(currentVtScore);
    }

    // Heuristics box: show host-only confidence score
    const hostScoreRow      = document.getElementById("hostScoreRow");
    const hostConfidenceVal = document.getElementById("hostConfidenceValue");
    if (hostScoreRow && hasHost) {
        hostScoreRow.style.display    = "";
        hostConfidenceVal.textContent = confidenceLabel(currentHostScore);
        hostConfidenceVal.style.color = confidenceColor(currentHostScore);
    }
}


// ── Classification helpers ─────────────────────────────────────────────────────

function classifyToStyle(classification) {
    if (!classification) return "vt-unknown";
    if (classification.includes("Malicious"))    return "vt-malicious";
    if (classification.includes("Suspicious"))   return "vt-suspicious";
    if (classification.includes("Inconclusive") || classification.includes("Questionable")) return "vt-questionable";
    if (classification.includes("Safe"))         return "vt-safe";
    return "vt-unknown";
}

// ── VT rendering ──────────────────────────────────────────────────────────────

function renderVtDetails(data) {
    const vtUnknown = !data.vtScore && data.vtStatus === "done";
    const vtEngineCounts = document.getElementById("vtEngineCounts");

    // Section header is no longer needed — engine counts are bullets themselves
    vtSectionHeader.style.display = "none";
    if (vtEngineCounts) vtEngineCounts.style.display = "none";

    vtDetailsList.innerHTML = "";
    vtClassificationLine.style.display = "none";
    vtUnknownLine.style.display        = "none";

    if (vtUnknown) {
        vtUnknownLine.style.display      = "";
        vtUnknownLine.style.marginBottom = "12px";
        combinedDetailsBox.style.display = "";
        return;
    }

    if (!data.vtRawStats && !data.vtBreakdown) {
        combinedDetailsBox.style.display = "";
        return;
    }

    // ── Engine count rows as bullet items ────────────────────────────────
    const raw      = data.vtRawStats     || {};
    const filtered = data.vtFilteredStats || {};
    const fpLevel  = data.vtFpLevel || "NONE";

    if (raw.malicious !== undefined) {
        // Bullet 1: all engines (unfiltered)
        const li1 = document.createElement("li");
        li1.appendChild(buildEngineCountsRow(raw, "(all results)"));
        vtDetailsList.appendChild(li1);

        // Bullet 2: after FP filter (only when FP reduction is active)
        if (fpLevel !== "NONE" && data.vtFilteredStats) {
            const li2 = document.createElement("li");
            li2.appendChild(buildEngineCountsRow(filtered,
                '<a class="fp-reduction-link" href="#" id="fpFilterLink">(with FP reduction)</a>'));
            vtDetailsList.appendChild(li2);

            setTimeout(() => {
                const link = document.getElementById("fpFilterLink");
                if (link) {
                    link.addEventListener("click", e => {
                        e.preventDefault();
                        chrome.runtime.openOptionsPage();
                    });
                }
            }, 0);
        }
    }

    // Bullet 3: First submitted to VT
    if (data.vtBreakdown?.age?.ageDays !== null && data.vtBreakdown?.age?.ageDays !== undefined) {
        const days = Math.round(data.vtBreakdown.age.ageDays);
        const li   = document.createElement("li");
        li.textContent = `First submitted to VT: ${days} day${days === 1 ? "" : "s"} ago`;
        vtDetailsList.appendChild(li);
    }

    // Show the VT classification line in the details box only when it adds
    // information beyond what the top "DOWNLOAD URL REPUTATION" box already
    // shows. When heuristics are negative the top box shows the heuristics
    // verdict, not the VT verdict — so the VT conclusion here is genuinely
    // different and worth showing. When the top box already shows the VT
    // verdict (heuristics are clean), showing it again here is redundant.
    if (data.vtBreakdown?.detection) {
        const classText      = vtClassificationText(data.vtScore);
        const topBoxIsVtText = lastHostData && !(typeof lastHostData.score === "number" && lastHostData.score < 0);
        if (!topBoxIsVtText) {
            // Top box is showing heuristics verdict — show VT conclusion here too
            vtClassificationLine.textContent   = classText;
            vtClassificationLine.className     = "value details-classification " + vtScoreToStyle(data.vtScore);
            vtClassificationLine.style.display = "";
        } else {
            vtClassificationLine.style.display = "none";
        }
    }

    combinedDetailsBox.style.display = "";
}

// Sanitize strings from background messages — strip anything that isn't
// printable ASCII + common punctuation. Labels are internally generated
// but this guards against any future message spoofing.
function sanitizeLabel(str) {
    if (typeof str !== "string") return "";
    return str.replace(/[^ -~À-ɏ]/g, "").slice(0, 200);
}

function buildEngineCountsRow(stats, suffixHtml) {
    const harmless   = (stats.harmless   || 0) + (stats.undetected || 0);
    const unknown    =  stats.unknown    || 0;
    const suspicious =  stats.suspicious || 0;
    const malicious  =  stats.malicious  || 0;

    // Build using DOM nodes so numbers from VT API never touch innerHTML
    const frag = document.createDocumentFragment();
    function addCell(label, value, cls) {
        const lbl = document.createElement("span");
        lbl.className = "ec-label";
        lbl.textContent = label;
        const num = document.createElement("span");
        num.className = "ec-num " + cls;
        num.textContent = String(value);
        frag.appendChild(lbl);
        frag.appendChild(num);
    }
    addCell("Not harmful:", harmless,   "ec-harmless");
    addCell("Unknown:",     unknown,    "ec-unknown");
    addCell("Suspicious:",  suspicious, "ec-suspicious");
    addCell("Malicious:",   malicious,  "ec-malicious");

    // suffix is trusted static HTML (hardcoded strings or our own link)
    const suffixSpan = document.createElement("span");
    suffixSpan.className = "ec-suffix";
    suffixSpan.innerHTML = suffixHtml; // only ever hardcoded strings
    frag.appendChild(suffixSpan);
    return frag;
}

function vtScoreToStyle(score) {
    if (score === null || score === undefined) return "vt-unknown";
    if (score >= 30)   return "vt-safe";
    if (score >= -30)  return "vt-questionable";
    if (score >= -60)  return "vt-suspicious";
    return "vt-malicious";
}

function vtClassificationText(score) {
    if (score === null || score === undefined) return "";
    if (score >= 30)   return "VirusTotal rates it currently as probably safe";
    if (score >= -30)  return "VirusTotal rates it currently as probably inconclusive";
    if (score >= -60)  return "VirusTotal rates it currently as probably suspicious";
    return "VirusTotal rates it currently as probably malicious";
}

function renderVtScore(data) {
    if (typeof data.vtScore !== "number") {
        if (data.vtStatus === "done") {
            currentVtScore = null;
            applyVtUnknownDisclaimer();
            if (lastHostData) renderHostReputation(lastHostData);
        }
        return;
    }
    currentVtScore = data.vtScore;
    updateCombinedScore();
    // Re-render host box so the verdict label reflects the now-known VT result
    if (lastHostData) renderHostReputation(lastHostData);
}

function applyVtResult(data) {
    lastVtData = data;
    srcUrl.textContent     = (data.url || "Unknown URL").split("?")[0].split("#")[0];
    reasonText.textContent = data.ext ? "." + data.ext : "Unknown";
    renderVtScore(data);
    renderVtDetails(data);
    if (data.vtStatus === "done") vtDone = true;

    if (data.slippedThrough) applySlippedThroughUi();
}

let isSlippedThrough = false; // set true by applySlippedThroughUi — changes btnAllow behaviour

function applySlippedThroughUi() {
    // File already landed on disk before the pause could intercept it
    // (small/fast file race — see background.js onCreated comment).
    // "Go back" makes no sense here (nothing to cancel) and stays disabled.
    // "Proceed" is repurposed: it closes the warning and opens VirusTotal so
    // the user can verify the URL/file there, rather than resuming a download
    // that already finished.
    isSlippedThrough = true;

    btnBack.disabled      = true;
    btnBack.style.opacity = "0.5";
    btnBack.style.cursor  = "not-allowed";

    btnAllow.textContent = "Proceed";

    const titleEl    = document.getElementById("warningTitle");
    const subtitleEl = document.getElementById("warningSubtitle");
    if (titleEl)    titleEl.textContent = "File already downloaded — review before opening";
    if (subtitleEl) subtitleEl.textContent =
        "This file finished downloading, before a result of VT was received. This is what we " +
        "currently know from the download URL.";

    disclaimer.innerHTML =
        '<span style="color:#fbbf24;font-weight:600;">⚠ This file already finished downloading before it could be checked. </span>' +
        '<span style="color:#ffffff;font-weight:600;">Review the results above before opening it.</span>';
}

// ── Host reputation rendering ─────────────────────────────────────────────────

function renderHostReputation(hostData) {
    if (!hostData) return;
    lastHostData = hostData;

    const vtUnknown = vtDone && currentVtScore === null;

    if (hostData.score === null && !vtUnknown) {
        hostBox.style.display = "none";
        return;
    }

    // ── Overall verdict label ────────────────────────────────────────────────
    // Priority: VT verdict (when known) > heuristics (when negative) > VT unknown fallback
    hostBox.style.display = "";
    const hostIsNegative = typeof hostData.score === "number" && hostData.score < 0;
    const vtKnown        = currentVtScore !== null;

    // Combined score drives the verdict text in the top box
    const combined = Math.max(-100, Math.min(100,
        (vtKnown ? currentVtScore : 0) +
        (typeof hostData.score === "number" ? hostData.score : 0)
    ));

    if (vtKnown) {
        // VT result available — show combined verdict
        hostResult.textContent = vtClassificationText(combined);
        hostResult.className   = "value value-prominent " + vtScoreToStyle(combined);
    } else if (hostIsNegative) {
        // VT not yet available, heuristics already negative — show heuristics signal
        hostResult.textContent = sanitizeLabel(hostData.label || hostData.classification || "Checked");
        hostResult.className   = "value value-prominent " + classifyToStyle(hostData.classification);
    } else {
        // VT not yet available, heuristics clean — show heuristics label
        hostResult.textContent = sanitizeLabel(hostData.label || hostData.classification || "Checked");
        hostResult.className   = "value value-prominent " + classifyToStyle(hostData.classification);
    }

    if (typeof hostData.score === "number") {
        currentHostScore = hostData.score;
        updateCombinedScore();
    }

    // ── Heuristics section in combined details box ────────────────────────────
    combinedDetailsBox.style.display = "";
    hostDetailsList.innerHTML = "";

    // Quad9 — only show when negative (BLOCKED) or when VT unknown
    if (hostData.quad9?.status) {
        if (hostData.quad9.status === "BLOCKED") {
            const li = document.createElement("li");
            li.textContent = "Domain is on Quad9 blacklist (confirmed malicious)";
            hostDetailsList.appendChild(li);
        } else if (vtUnknown) {
            const li = document.createElement("li");
            li.textContent = "Domain not flagged by Quad9 as harmful";
            hostDetailsList.appendChild(li);
        }
    }

    // Scoring rows — only negative, no prefix labels
    const rows = hostData.breakdown || [];
    for (const row of rows) {
        if (row.source === "Quad9") continue;
        if (row.score >= 0) continue;
        const li = document.createElement("li");
        li.textContent = sanitizeLabel(row.label);
        hostDetailsList.appendChild(li);
    }

    // Slipped-through executables: nudge the user to check the actual file
    // (not just the URL) at VirusTotal, since the file is already on disk
    // and a URL-only check may have missed something a file scan would catch.
    // Scripts get their own dedicated negative-signal bullet above instead —
    // adding this too would be redundant noise for that case.
    if (isSlippedThrough && lastVtData?.fileType === "executable" && lastVtData?.ext &&
        !SCRIPT_EXTS_CLIENT.includes(lastVtData.ext)) {
        const li = document.createElement("li");
        li.innerHTML = "Please check the download at " +
            vtManualCheckLink("https://www.virustotal.com/gui/home/upload") + "VirusTotal</a>";
        hostDetailsList.appendChild(li);
    }

    // Always show divider; when no signals, add a reassuring note
    if (heuristicsBox) heuristicsBox.style.display = "";
    if (hostDetailsList.children.length === 0) {
        const li = document.createElement("li");
        li.textContent = "Heuristics found no alarming signals";
        li.style.color = "#6b7280"; // muted — not a warning, just informational
        hostDetailsList.appendChild(li);
    }
}

// ── Cancel / Allow ────────────────────────────────────────────────────────────

btnBack.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "CANCEL_DOWNLOAD", downloadId });
    window.close();
});

btnAllow.addEventListener("click", () => {
    if (isSlippedThrough) {
        // Nothing to resume — just clean up the record and open VT for the user
        chrome.runtime.sendMessage({ type: "CANCEL_DOWNLOAD", downloadId }, () => {
            chrome.tabs.create({ url: "https://www.virustotal.com/gui/home/url" });
            window.close();
        });
        return;
    }
    chrome.runtime.sendMessage({ type: "ALLOW_DOWNLOAD", downloadId });
    window.close();
});

// ── Initial data fetch + poll ─────────────────────────────────────────────────

chrome.runtime.sendMessage(
    { type: "GET_BLOCKED_DOWNLOAD", downloadId },
    data => {
        if (!data) {
            // Download was already removed (cancelled/completed) before page loaded
            document.body.style.opacity = "0.5";
            srcUrl.textContent = "Download no longer active — you can close this window.";
            btnAllow.disabled  = true;
            return;
        }
        applyVtResult(data);

        if (data.hostResult) {
            renderHostReputation(data.hostResult);
            hostDone = true;
        }

        if (!vtDone || !hostDone) {
            const pollStart    = Date.now();
            // 8 s: safety net — push message (VT_RESULT_UPDATE) usually arrives in
            // under 3 s, but slow VT responses need more headroom. Push always wins
            // even if timeout fires first.
            const POLL_TIMEOUT = 8000;

            const pollInterval = setInterval(() => {
                if (Date.now() - pollStart >= POLL_TIMEOUT) {
                    clearInterval(pollInterval);

                    if (!vtDone) {
                        vtDone = true;
                        currentVtScore = null;
                        applyVtUnknownDisclaimer();
                        vtSectionHeader.style.display = "";
                        vtUnknownLine.style.display   = "";
                        combinedDetailsBox.style.display = "";
                        if (lastHostData) renderHostReputation(lastHostData);
                    }

                    if (!hostDone) {
                        hostDone = true;
                        hostResult.textContent = "Host reputation check timed out";
                        hostResult.className   = "value vt-unknown";
                        hostBox.style.display  = "";
                    }
                    return;
                }

                chrome.runtime.sendMessage(
                    { type: "GET_BLOCKED_DOWNLOAD", downloadId },
                    polled => {
                        if (!polled) { clearInterval(pollInterval); return; }
                        if (!vtDone)   applyVtResult(polled);
                        if (!hostDone && polled.hostResult) {
                            renderHostReputation(polled.hostResult);
                            hostDone = true;
                        }
                        if (vtDone && hostDone) clearInterval(pollInterval);
                    }
                );
            }, 250);
        }
    }
);

// ── Push updates from background ─────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender) => {
    // Only accept messages from our own extension background service worker
    if (sender.id !== chrome.runtime.id) return;
    if (msg.downloadId !== downloadId) return;

    if (msg.type === "VT_RESULT_UPDATE") {
        vtDone = true;
        // Always apply push result even if timeout already fired — push data is authoritative
        vtUnknownLine.style.display = "none";
        const synth = {
            vtStatus:           "done",
            vtScore:            msg.vtScore,
            vtBreakdown:        msg.vtBreakdown,
            vtRawStats:         msg.vtRawStats,
            vtFilteredStats:    msg.vtFilteredStats,
            vtFpLevel:          msg.vtFpLevel,
            url:                lastVtData?.url,
            ext:                lastVtData?.ext,
        };
        renderVtScore(synth);
        renderVtDetails(synth);
        if (lastHostData) renderHostReputation(lastHostData);
    }

    if (msg.type === "HOST_RESULT_UPDATE") {
        hostDone = true;
        renderHostReputation(msg.hostResult);
    }
});
