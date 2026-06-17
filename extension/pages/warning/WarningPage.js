// ── Setup ──────────────────────────────────────────────────────────────────────

const params     = new URLSearchParams(location.search);
const downloadId = Number(params.get("downloadId"));

// If downloadId is missing or invalid, there's nothing to show
if (!downloadId) {
    document.body.innerHTML = "<p style='color:white;padding:2rem'>Invalid warning page — no download ID found.</p>";
    throw new Error("[DownloadSentinel] WarningPage opened without a valid downloadId");
}

const reasonText  = document.getElementById("reasonText");
const srcUrl      = document.getElementById("srcUrl");
const bpResult    = document.getElementById("bpResult");
const scoreBox    = document.getElementById("scoreBox");
const scoreBarFill = document.getElementById("scoreBarFill");
const scoreValue  = document.getElementById("scoreValue");
const breakdownBox  = document.getElementById("breakdownBox");
const breakdownList = document.getElementById("breakdownList");
const btnBack     = document.getElementById("btn-back");
const btnAllow    = document.getElementById("btn-allow");
const disclaimer  = document.getElementById("disclaimerText");

let vtDone = false;

// ── Apply settings (background color + disclaimer text) ───────────────────────

function applySettings(settings) {
    // Custom background color
    const r = settings.warningColorR ?? 179;
    const g = settings.warningColorG ?? 38;
    const b = settings.warningColorB ?? 30;
    document.body.style.backgroundColor = `rgb(${r}, ${g}, ${b})`;

    // Disclaimer text
    if (settings.isVtApiKeySet && settings.vtApiKey) {
        disclaimer.innerHTML =
            '<span style="color:#fff;">Disclaimer: this is what Virus Total currently knows, file can still be malicious!</span>';
    } else {
        disclaimer.innerHTML =
            '<span style="color:#fff;">Reputation check not activated, please </span>' +
            '<a href="https://www.virustotal.com/gui/join-us" target="_blank" ' +
            'style="color:rgb(243,186,34);font-weight:600;text-decoration:none;">' +
            'Get a free API key</a>';
    }
}

// Load settings as soon as the page is ready
Settings.get(applySettings);

// ── Download data ──────────────────────────────────────────────────────────────

function renderScore(data) {
    if (typeof data.vtScore !== "number") {
        scoreBox.style.display = "none";
        return;
    }

    scoreBox.style.display = "";

    const score      = data.vtScore;
    const isPositive = score >= 0;
    const magnitude  = Math.min(100, Math.abs(score)); // 0-100, fills the full track width

    scoreValue.textContent = `${isPositive ? "+" : ""}${score}`;
    scoreValue.className   = "score-bar-value " + (isPositive ? "positive" : "negative");

    scoreBarFill.className   = "score-bar-fill " + (isPositive ? "positive" : "negative");
    scoreBarFill.style.width = `${magnitude}%`;
}

function renderBreakdown(data) {
    if (!data.vtBreakdown) {
        breakdownBox.style.display = "none";
        return;
    }

    breakdownBox.style.display = "";
    breakdownList.innerHTML = "";

    const { detection, reputation, age, votes } = data.vtBreakdown;
    [
        ["Detections", detection],
        ["Reputation", reputation],
        ["Age", age],
        ["Community votes", votes]
    ].forEach(([name, part]) => {
        if (!part) return;
        const li = document.createElement("li");
        const sign = part.score > 0 ? "+" : "";
        li.textContent = `${name}: ${part.label} (${sign}${part.score})`;
        breakdownList.appendChild(li);
    });
}

function applyResult(data) {
    srcUrl.textContent     = data.url || "Unknown URL";
    reasonText.textContent = data.ext ? "." + data.ext : "Unknown";
    bpResult.textContent   = data.browserProtectionResult || "Checking...";
    applyVtStyling(data.browserProtectionResult);
    renderScore(data);
    renderBreakdown(data);

    if (data.vtStatus === "done") vtDone = true;
}

// Initial fetch from background
chrome.runtime.sendMessage(
    { type: "GET_BLOCKED_DOWNLOAD", downloadId },
    data => {
        if (!data) return;
        applyResult(data);

        if (!vtDone) {
            const pollStart    = Date.now();
            const POLL_TIMEOUT = 3000;

            const pollInterval = setInterval(() => {
                // Hard cap: if VT hasn't answered within 3000ms, show Failed and stop
                if (Date.now() - pollStart >= POLL_TIMEOUT) {
                    clearInterval(pollInterval);
                    if (vtDone) return;
                    vtDone = true;
                    const suffix = data.ext ? "." + data.ext + " download" : "download";
                    bpResult.textContent = "Reputation check failed — " + suffix;
                    applyVtStyling(bpResult.textContent);
                    scoreBox.style.display = "none";
                    breakdownBox.style.display = "none";
                    return;
                }

                chrome.runtime.sendMessage(
                    { type: "GET_BLOCKED_DOWNLOAD", downloadId },
                    polled => {
                        if (!polled) { clearInterval(pollInterval); return; }
                        applyResult(polled);
                        if (polled.vtStatus === "done") clearInterval(pollInterval);
                    }
                );
            }, 250);
        }
    }
);

// ── VT styling ─────────────────────────────────────────────────────────────────

function applyVtStyling(result) {
    bpResult.classList.remove("vt-malicious", "vt-suspicious", "vt-questionable", "vt-safe", "vt-unknown");

    if (!result || result.startsWith("Checking") || result.startsWith("Blocked")) {
        bpResult.classList.add("vt-unknown");
    } else if (result.startsWith("Probably Safe")) {
        bpResult.classList.add("vt-safe");
    } else if (result.startsWith("Probably Questionable")) {
        bpResult.classList.add("vt-questionable");
    } else if (result.startsWith("Probably Suspicious")) {
        bpResult.classList.add("vt-suspicious");
    } else if (result.startsWith("Probably Malicious")) {
        bpResult.classList.add("vt-malicious");
    } else {
        // Unknown reputation, reputation check failed/not enabled, etc.
        bpResult.classList.add("vt-unknown");
    }
}

// ── Buttons ────────────────────────────────────────────────────────────────────

btnBack.addEventListener("click", () => window.close());

btnAllow.addEventListener("click", () => {
    btnAllow.disabled     = true;
    btnAllow.textContent  = "Starting download...";

    chrome.runtime.sendMessage({ type: "ALLOW_DOWNLOAD", downloadId }, response => {
        if (response && response.success) {
            window.close();
        } else {
            btnAllow.disabled    = false;
            btnAllow.textContent = "Ignore & Proceed";
            console.error("[DownloadProtection] Failed to allow download:", response?.error);
        }
    });
});
