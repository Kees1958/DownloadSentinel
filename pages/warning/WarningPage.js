"use strict";

// ── WarningPage.js ────────────────────────────────────────────────────────────
// Warning page controller — renders the combined VT + heuristics risk report
// for a single download.
//
// Architecture: single-render pass (V2.0+). background.js waits for all checks
// before opening the page; we fetch the record once and render everything.
// A VT_RESULT_UPDATE push message is also handled for the SUBMIT_URL_TO_VT
// flow (user requests fresh VT scan from the warning page).
//
// Public interface: none (self-contained IIFE, runs on load)
//
// Dependencies:
//   util/AppConstants.js          — APP
//   util/MessageTypes.js          — MSG
//   util/Settings.js              — Settings.get
//   util/UrlUtils.js              — UrlUtils.toVtUrlId
//   protection/ScoringEngineV2.js — SCORING_CONFIG (thresholds for colour coding)
//   pages/warning/FocusRing.js    — FocusRing.init (v3.5.4: ring only on keyboard navigation)
//
// State owned by this module:
//   currentVtScore   {number|null}  — most recent VT score received
//   currentHostScore {number|null}  — host-reputation score
//   lastHostData     {object|null}  — last full host-reputation result
//   lastVtData       {object|null}  — last full VT data received
// ─────────────────────────────────────────────────────────────────────────────

import { APP } from "../../util/AppConstants.js";
import { MSG } from "../../util/MessageTypes.js";
import { MessageGate } from "../../util/MessageGate.js";   // v3.6.0 — sender check on the VT_RESULT_UPDATE listener
import { Settings } from "../../util/Settings.js";
import { UrlUtils } from "../../util/UrlUtils.js";
import { SCORING_CONFIG } from "../../protection/ScoringEngineV2.js";
import { FocusRing } from "./FocusRing.js";

// ── DNS threat-intel UNKNOWN display text ───────────────────────────────────
// Single source of truth mapping each DnsThreatProtection UNKNOWN_REASON code
// (protection/DnsThreatProtection.js) to the line shown in the Heuristics box
// — provider-agnostic text; the provider's own label (e.g. "Quad9",
// "Cloudflare Security (malware)") is prefixed at render time in
// renderHostReputation() below. Keep this table in sync with that module's
// UNKNOWN_REASON enum — add a new entry here whenever a new code is added
// there. Any code not present in this table (including a missing/undefined
// reasonCode) falls back to DNS_UNKNOWN_FALLBACK, so a future/unrecognised
// code never renders blank.
const DNS_UNKNOWN_TEXT = Object.freeze({
    NO_THREAT_DATA: "no threat-intel data for this host",
    REQUEST_FAILED: "lookup failed (service error)",
    NXDOMAIN:       "domain name does not exist (NXDOMAIN)",
    NO_ANSWER:      "returned no DNS records for this host",
    TIMEOUT:        "lookup timed out",
    PERMISSION_MISSING: "not checked — permission not granted (allow it in Options)",
    ERROR:          "lookup failed (network error)"
});
const DNS_UNKNOWN_FALLBACK = "could not be verified";

(function () {

    // ── Setup ──────────────────────────────────────────────────────────────────

    const params     = new URLSearchParams(location.search);
    const downloadId = Number(params.get("downloadId"));

    if (!downloadId) {
        document.body.innerHTML = "<p style='color:white;padding:2rem'>Invalid warning page — no download ID found.</p>";
        throw new Error("[DownloadSentinel] WarningPage opened without a valid downloadId");
    }

    // ── DOM refs ───────────────────────────────────────────────────────────────

    const reasonText            = document.getElementById("reasonText");
    const srcUrl                = document.getElementById("srcUrl");

    const hostBox               = document.getElementById("hostBox");
    const hostResult            = document.getElementById("hostResult");
    const hostLabel             = document.getElementById("hostLabel");

    const combinedDetailsBox    = document.getElementById("combinedDetailsBox");
    const vtSectionHeader       = document.getElementById("vtSectionHeader");
    const vtUnknownLine         = document.getElementById("vtUnknownLine");
    const vtDetailsList         = document.getElementById("vtDetailsList");
    const vtClassificationLine  = document.getElementById("vtClassificationLine");
    const heuristicsBox         = document.getElementById("heuristicsBox");
    const hostDetailsList       = document.getElementById("hostDetailsList");

    const worstScoreBox         = document.getElementById("worstScoreBox");
    const worstScoreValue       = document.getElementById("worstScoreValue");
    const worstScoreBarFill     = document.getElementById("worstScoreBarFill");
    const scoreExplanation      = document.getElementById("scoreExplanation");

    const btnOk                 = document.getElementById("btn-ok");
    const btnVt                 = document.getElementById("btn-vt");
    const disclaimer            = document.getElementById("disclaimerText");

    // v3.5.4 (3P Matrix 4.4.6): the careful choice is the keyboard default —
    // Enter checks the download instead of proceeding; no ring until Tab.
    FocusRing.init();
    btnVt?.focus();

    // ── Module-level state ─────────────────────────────────────────────────────
    // All declared with let so strict mode does not create implicit globals.

    let currentVtScore   = null;  // most recent VT axis score
    let currentHostScore = null;  // host-reputation axis score
    let lastHostData     = null;  // last full host-reputation result object
    let lastVtData       = null;  // last full VT data received

    // ── Settings ───────────────────────────────────────────────────────────────

    function applySettings(settings) {
        // v3.3.0 (item 15) — fallback colour was duplicated here as bare
        // 179/38/30; APP.WARNING_COLOR_DEFAULT_* already exists as the one
        // source of truth (see AppConstants.js) — use it instead of redeclaring it.
        const r = settings.warningColorR ?? APP.WARNING_COLOR_DEFAULT_R;
        const g = settings.warningColorG ?? APP.WARNING_COLOR_DEFAULT_G;
        const b = settings.warningColorB ?? APP.WARNING_COLOR_DEFAULT_B;
        document.body.style.backgroundColor = `rgb(${r}, ${g}, ${b})`;

        const titleEl = document.getElementById("warningTitle");
        if (titleEl) {
            // v3.3.0 (item 11) — textContent for both branches. The default
            // title is currently plain text with no markup, so innerHTML was
            // never exploitable today, but it's a trap for a future edit
            // that adds markup to APP.WARNING_TITLE_DEFAULT without noticing
            // this call site. textContent costs nothing here.
            const custom = (settings.warningTitle || "").trim();
            titleEl.textContent = custom || APP.WARNING_TITLE_DEFAULT;
        }
    }

    Settings.get(applySettings);

    // ── VT URL ID helper ───────────────────────────────────────────────────────
    // Now imported from UrlUtils.js (util/UrlUtils.js is in web_accessible_resources
    // alongside the other util/ modules this page already imports — see manifest.json).
    // Previously duplicated here because that wasn't the case yet (jscpd-flagged
    // duplicate, audit pass) — no behavior change, same encoding.

    // ── Disclaimer ─────────────────────────────────────────────────────────────
    // Set after the record arrives so we can tailor the text to what actually ran.
    //   vtApiKeySet + vtScore known  → VT ran and returned data
    //   vtApiKeySet + vtScore null   → VT ran but URL was unknown to VT
    //   !vtApiKeySet                 → VT was not configured; heuristics only
    //
    // PRIVACY NOTE: every VT check this extension performs — both the automatic
    // one at download time and the SUBMIT_URL_TO_VT recheck (see background.js's
    // submitAndPollVt()) — submits only the download URL, never the downloaded
    // file itself. Uploading the actual file to a third party is a meaningfully
    // bigger privacy/exposure decision than checking a URL, so that step is left
    // entirely to the user: "Check download at VT" (btnVt) just opens
    // virustotal.com/hybrid-analysis.com in a new tab for the user to upload the
    // file manually if they choose to — this extension never does it for them.
    // v3.3.0 (item 3) — single source of truth for the VT key sign-up link,
    // so the no-key disclaimer below and OptionsPage's own "Get a free API
    // key" link point at the same place.
    const VT_KEY_SIGNUP_URL = "https://www.virustotal.com/gui/join-us";

    function renderDisclaimer(data) {
        if (!disclaimer) return;
        const vtRan     = data.vtApiKeySet;
        const vtUnknown = vtRan && data.vtScore === null;

        // v3.3.0 (item 11) — every branch below builds the paragraph with
        // createElement/textContent, never innerHTML, even where the text
        // is currently hardcoded — the link target is the only part that
        // isn't literal text, and it still goes through href, not markup.
        disclaimer.replaceChildren();

        if (!vtRan) {
            // v3.3.0 (item 3) — was a single sentence ("No VirusTotal API
            // key is configured..."); the lookup is simply not run, so say
            // that plainly and offer the (free) fix as its own line/link,
            // rather than one run-on sentence.
            const line1 = document.createElement("span");
            line1.textContent = "Reputation lookup at VirusTotal skipped";
            const link = document.createElement("a");
            link.href        = VT_KEY_SIGNUP_URL;
            link.target      = "_blank";
            link.rel         = "noopener";
            link.textContent = "Request a free (no cost) key at VirusTotal";
            disclaimer.append(line1, document.createElement("br"), link);
            if (btnVt) btnVt.textContent = "Check download at VT";

        } else if (vtUnknown) {
            // VT has no record of this URL — direct user to Hybrid Analysis
            const span = document.createElement("span");
            span.textContent =
                "Accept conditions, ignore e-mail requirement and select QUICK SCAN " +
                "for free hybrid analysis at METADEFENDER and CROWDSTRIKE, " +
                "before opening the downloaded file!";
            disclaimer.appendChild(span);
            if (btnVt) btnVt.textContent = "Check download at Hybrid Analysis";

        } else {
            // v3.3.0 (item 23) — VT already answered and the boxes above say
            // so; the old closing line ("This is what VirusTotal knows...")
            // just repeated that. Keep only the actionable part.
            const span = document.createElement("span");
            span.textContent = "When in doubt, upload the download itself at VirusTotal using the button.";
            disclaimer.appendChild(span);
            if (btnVt) btnVt.textContent = "Check download at VT";
        }
    }

    // ── Score bar ──────────────────────────────────────────────────────────────

    function renderScoreBar(valueEl, fillEl, score) {
        const isPositive = score >= 0;
        const magnitude  = Math.min(100, Math.abs(score));
        valueEl.textContent = `${isPositive ? "+" : ""}${score}%`;
        valueEl.className   = "score-bar-value " + (isPositive ? "positive" : "negative");
        fillEl.className    = "score-bar-fill "  + (isPositive ? "positive" : "negative");
        fillEl.style.width  = `${magnitude}%`;
    }

    function confidenceLabel(score) {
        return `${score >= 0 ? "+" : ""}${score}%`;
    }

    function confidenceColor(score) {
        // Colour thresholds mirror SCORING_CONFIG so UI matches scoring logic
        if (score >= SCORING_CONFIG.THRESHOLD_SAFE)         return "#34d399"; // green
        if (score >= SCORING_CONFIG.THRESHOLD_QUESTIONABLE) return "#60a5fa"; // blue
        if (score >= SCORING_CONFIG.THRESHOLD_SUSPICIOUS)   return "#fbbf24"; // yellow
        return "#ef4444"; // red
    }

    function updateCombinedScore() {
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

        // Colour the warning title to match the combined score category
        const titleEl = document.getElementById("warningTitle");
        if (titleEl) titleEl.style.color = confidenceColor(combined);

        // Colour the "Download URL Reputation" label
        if (hostLabel) hostLabel.className = "label label-" + vtScoreToStyle(combined);

        // VT confidence score row
        const vtScoreRow = document.getElementById("vtScoreRow");
        const vtScoreVal = document.getElementById("vtScoreValue");
        if (vtScoreRow && hasVt) {
            vtScoreRow.style.display = "";
            vtScoreVal.textContent   = confidenceLabel(currentVtScore);
            vtScoreVal.style.color   = confidenceColor(currentVtScore);
        }

        // Heuristics confidence score row
        const hostScoreRow      = document.getElementById("hostScoreRow");
        const hostConfidenceVal = document.getElementById("hostConfidenceValue");
        if (hostScoreRow && hasHost) {
            hostScoreRow.style.display    = "";
            hostConfidenceVal.textContent = confidenceLabel(currentHostScore);
            hostConfidenceVal.style.color = confidenceColor(currentHostScore);
        }
    }

    // ── Classification helpers ─────────────────────────────────────────────────

    function classifyToStyle(classification) {
        if (!classification)                          return "vt-unknown";
        if (classification.includes("Malicious"))     return "vt-malicious";
        if (classification.includes("Suspicious"))    return "vt-suspicious";
        if (classification.includes("Inconclusive") ||
            classification.includes("Questionable"))  return "vt-questionable";
        if (classification.includes("Safe"))          return "vt-safe";
        return "vt-unknown";
    }

    function vtScoreToStyle(score) {
        if (score === null || score === undefined)          return "vt-unknown";
        if (score >= SCORING_CONFIG.THRESHOLD_SAFE)         return "vt-safe";
        if (score >= SCORING_CONFIG.THRESHOLD_QUESTIONABLE) return "vt-questionable";
        if (score >= SCORING_CONFIG.THRESHOLD_SUSPICIOUS)   return "vt-suspicious";
        return "vt-malicious";
    }

    function vtClassificationText(score) {
        if (score === null || score === undefined)          return "";
        if (score >= SCORING_CONFIG.THRESHOLD_SAFE)         return "VirusTotal rates it currently as probably safe";
        if (score >= SCORING_CONFIG.THRESHOLD_QUESTIONABLE) return "VirusTotal rates it currently as probably inconclusive";
        if (score >= SCORING_CONFIG.THRESHOLD_SUSPICIOUS)   return "VirusTotal rates it currently as probably suspicious";
        return "VirusTotal rates it currently as probably malicious";
    }

    // ── Input sanitisation ─────────────────────────────────────────────────────
    // Labels come from background messages. Strip non-printable chars as a
    // guard against any future message spoofing.

    // v3.3.0 (item 15) — single named constant instead of a bare 200.
    const LABEL_SANITIZE_MAX_LENGTH = 200;
    // v3.5.0 — also keeps typographic punctuation (U+2010–U+2015 dashes,
    // U+2018–U+201F quotes, U+2026 ellipsis, U+2192 arrow): the em dash in
    // labels like "was hidden — no extension…" used to be deleted, gluing the
    // words together. Bidi/override controls (U+202A–U+202E, U+2066–U+2069)
    // and everything else outside the allowed set are still stripped.
    const LABEL_ALLOWED_CHARS = /[^ -~À-ɏ‐-―‘-‟…→]/g;
    function sanitizeLabel(str) {
        if (typeof str !== "string") return "";
        return str.replace(LABEL_ALLOWED_CHARS, "").slice(0, LABEL_SANITIZE_MAX_LENGTH);
    }

    // ── Engine count row builder ───────────────────────────────────────────────

    // v3.3.0 (item 11) — suffix is now a DOM node (or a plain string, wrapped
    // in a text node) built by the caller, never an HTML string assigned via
    // innerHTML. Both current callers pass either a literal word ("(all
    // results)") or our own <a> element — never anything derived from a
    // remote/untrusted source — but textContent/appendChild cost nothing
    // extra and close off that path for good.
    function buildEngineCountsRow(stats, suffixNode) {
        const harmless   = (stats.harmless   || 0) + (stats.undetected || 0);
        const unknown    =  stats.unknown    || 0;
        const suspicious =  stats.suspicious || 0;
        const malicious  =  stats.malicious  || 0;

        const frag = document.createDocumentFragment();
        function addCell(label, value, cls) {
            const lbl = document.createElement("span");
            lbl.className   = "ec-label";
            lbl.textContent = label;
            const num = document.createElement("span");
            num.className   = "ec-num " + cls;
            num.textContent = String(value);
            frag.appendChild(lbl);
            frag.appendChild(num);
        }
        addCell("Not harmful:", harmless,   "ec-harmless");
        addCell("Unknown:",     unknown,    "ec-unknown");
        addCell("Suspicious:",  suspicious, "ec-suspicious");
        addCell("Malicious:",   malicious,  "ec-malicious");

        const suffixSpan = document.createElement("span");
        suffixSpan.className = "ec-suffix";
        if (typeof suffixNode === "string") suffixSpan.textContent = suffixNode;
        else suffixSpan.appendChild(suffixNode);
        frag.appendChild(suffixSpan);
        return frag;
    }

    // ── VT rendering ──────────────────────────────────────────────────────────

    function renderVtDetails(data) {
        // v3.3.0 (item 4) — was `!data.vtScore`, which is also true for a
        // real score of exactly 0 (clean, zero detections): a genuinely
        // clean file was being shown as "unknown to VirusTotal". Only an
        // actual non-number score means VT has no verdict at all (same test
        // already used correctly by renderVtScore() below).
        const vtUnknown      = typeof data.vtScore !== "number" && data.vtDone;
        const vtEngineCounts = document.getElementById("vtEngineCounts");

        vtSectionHeader.style.display = "none";
        if (vtEngineCounts) vtEngineCounts.style.display = "none";

        vtDetailsList.innerHTML        = "";
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

        // ── Engine count bullets ──────────────────────────────────────────────
        const raw      = data.vtRawStats     || {};
        const filtered = data.vtFilteredStats || {};
        const fpLevel  = data.vtFpLevel || "NONE";

        if (raw.malicious !== undefined) {
            const li1 = document.createElement("li");
            li1.appendChild(buildEngineCountsRow(raw, "(all results)"));
            vtDetailsList.appendChild(li1);

            if (fpLevel !== "NONE" && data.vtFilteredStats) {
                // v3.3.0 (item 11) — built as a real element and wired up
                // directly, instead of an innerHTML string plus a setTimeout
                // to find-and-attach the listener afterward.
                const fpLink = document.createElement("a");
                fpLink.className = "fp-reduction-link";
                fpLink.href       = "#";
                fpLink.textContent = "(with FP reduction)";
                fpLink.addEventListener("click", e => {
                    e.preventDefault();
                    chrome.runtime.openOptionsPage();
                });
                const li2 = document.createElement("li");
                li2.appendChild(buildEngineCountsRow(filtered, fpLink));
                vtDetailsList.appendChild(li2);
            }
        }

        // ── Age bullet ────────────────────────────────────────────────────────
        if (data.vtBreakdown?.age?.ageDays !== null &&
            data.vtBreakdown?.age?.ageDays !== undefined) {
            const days = Math.round(data.vtBreakdown.age.ageDays);
            const li   = document.createElement("li");
            li.textContent = `First submitted to VT: ${days} day${days === 1 ? "" : "s"} ago`;
            vtDetailsList.appendChild(li);
        }

        // ── VT classification line ────────────────────────────────────────────
        if (data.vtBreakdown?.detection) {
            const classText      = vtClassificationText(data.vtScore);
            const topBoxIsVtText = lastHostData &&
                !(typeof lastHostData.score === "number" && lastHostData.score < 0);
            if (!topBoxIsVtText) {
                vtClassificationLine.textContent   = classText;
                vtClassificationLine.className     = "value details-classification " +
                    vtScoreToStyle(data.vtScore);
                vtClassificationLine.style.display = "";
            } else {
                vtClassificationLine.style.display = "none";
            }
        }

        combinedDetailsBox.style.display = "";
    }

    function renderVtScore(data) {
        if (typeof data.vtScore !== "number") {
            if (data.vtDone) {
                currentVtScore = null;
                if (lastHostData) renderHostReputation(lastHostData);
            }
            return;
        }
        currentVtScore = data.vtScore;
        updateCombinedScore();
        if (lastHostData) renderHostReputation(lastHostData);
    }

    function applyVtResult(data) {
        lastVtData = data;
        if (srcUrl)     srcUrl.textContent     = (data.url || "Unknown URL").split("?")[0].split("#")[0];
        if (reasonText) reasonText.textContent = data.ext ? "." + data.ext : "Unknown";
        renderVtScore(data);
        renderVtDetails(data);
    }

    // ── Host reputation rendering ──────────────────────────────────────────────

    function renderHostReputation(hostData) {
        if (!hostData) return;
        lastHostData = hostData;

        const vtUnknown = currentVtScore === null;

        if (hostData.score === null && !vtUnknown) {
            hostBox.style.display = "none";
            return;
        }

        hostBox.style.display = "";
        const hostIsNegative = typeof hostData.score === "number" && hostData.score < 0;
        const vtKnown        = currentVtScore !== null;

        const combined = Math.max(-100, Math.min(100,
            (vtKnown ? currentVtScore : 0) +
            (typeof hostData.score === "number" ? hostData.score : 0)
        ));

        if (vtKnown) {
            hostResult.textContent = vtClassificationText(combined);
            hostResult.className   = "value value-prominent " + vtScoreToStyle(combined);
        } else if (hostIsNegative) {
            hostResult.textContent = sanitizeLabel(hostData.label || hostData.classification || "See heuristics below");
            hostResult.className   = "value value-prominent " + classifyToStyle(hostData.classification);
        } else {
            hostResult.textContent = sanitizeLabel(hostData.label || hostData.classification || "See heuristics below");
            hostResult.className   = "value value-prominent " + classifyToStyle(hostData.classification);
        }

        if (typeof hostData.score === "number") {
            currentHostScore = hostData.score;
            updateCombinedScore();
        }

        combinedDetailsBox.style.display = "";
        hostDetailsList.innerHTML = "";

        // DNS threat-intel checks (user's chosen first/second, v3.0.6) —
        // always shown here, regardless of VT's own status. UNKNOWN gets its
        // own reason-specific line (see DNS_UNKNOWN_TEXT above) rather than
        // one generic message or being silently skipped — a timeout and
        // "no threat-intel data for this host" are different situations and
        // neither is worded as a malware flag, since the check gave no real
        // verdict either way. A slot the user set to "None" (status
        // "SKIPPED") renders nothing.
        for (const dnsCheck of hostData.dnsChecks || []) {
            if (!dnsCheck?.status || dnsCheck.status === "SKIPPED") continue;
            const who = dnsCheck.providerLabel || "DNS check";
            const li  = document.createElement("li");
            if (dnsCheck.status === "BLOCKED") {
                li.textContent = `Domain is on the ${who} blacklist (confirmed malicious)`;
            } else if (dnsCheck.status === "ALLOWED") {
                li.textContent = `Not flagged as malware at ${who}`;
            } else {
                li.textContent = `${who}: ${DNS_UNKNOWN_TEXT[dnsCheck.reasonCode] || DNS_UNKNOWN_FALLBACK}`;
            }
            hostDetailsList.appendChild(li);
        }

        // Negative scoring rows, then (v3.5.0) explained route quirks — shown so
        // the user sees what was noticed and why it did not count — and the
        // established-site credit. Other zero/positive rows stay hidden as before.
        const rows = hostData.breakdown || [];
        for (const row of rows) {
            if (row.source === "DnsThreat") continue;
            let rowClass = null;
            if (row.explained)          rowClass = "host-signal-explained";
            else if (row.score > 0)     rowClass = "host-signal-credit";
            else if (row.score >= 0)    continue;
            const li = document.createElement("li");
            li.textContent = sanitizeLabel(row.label);
            if (rowClass) li.className = rowClass;
            hostDetailsList.appendChild(li);
        }

        // RDAP domain-registration age — always shown here in the Heuristics
        // box (never in the VT box, regardless of whether VT has its own
        // first-seen data). Skipped only when RDAP's own hit was negative
        // enough to already appear above via the normal breakdown loop
        // ("New domain registration: ..."), so the age is never shown twice.
        if (hostData.rdap?.label && !rows.some(r => r.source === "RDAP")) {
            const li = document.createElement("li");
            li.textContent = `Domain registration age: ${sanitizeLabel(hostData.rdap.label)}`;
            hostDetailsList.appendChild(li);
        }

        if (heuristicsBox) heuristicsBox.style.display = "";

        if (hostDetailsList.children.length === 0) {
            const li = document.createElement("li");
            li.textContent = "Heuristics found no alarming signals";
            // Use CSS class instead of inline style (audit item A6)
            li.className = "host-signals-empty";
            hostDetailsList.appendChild(li);
        }
    }

    // ── Button handlers ───────────────────────────────────────────────────────

    btnOk?.addEventListener("click", () => {
        chrome.runtime.sendMessage(
            { type: MSG.DISMISS_CHECK, downloadId },
            () => window.close()
        );
    });

    btnVt?.addEventListener("click", () => {
        // VT unknown → send user to Hybrid Analysis for free sandbox analysis.
        // VT has results → open the direct VT detection page for this URL.
        // Fallback → VT homepage if the record has not arrived yet.
        const vtUnknown = lastVtData?.vtApiKeySet && lastVtData?.vtScore === null;
        let targetUrl;
        if (vtUnknown) {
            targetUrl = "https://hybrid-analysis.com/";
        } else if (lastVtData?.url) {
            targetUrl = `https://www.virustotal.com/gui/url/${UrlUtils.toVtUrlId(lastVtData.url)}/detection`;
        } else {
            targetUrl = "https://www.virustotal.com/gui/home/url";
        }
        chrome.runtime.sendMessage(
            { type: MSG.DISMISS_CHECK, downloadId },
            () => {
                chrome.tabs.create({ url: targetUrl });
                window.close();
            }
        );
    });

    // ── VT_RESULT_UPDATE push listener ────────────────────────────────────────
    // Handles fresh VT results pushed by background.js after SUBMIT_URL_TO_VT.
    // The submit+poll round trip in submitAndPollVt() (background.js) is short
    // — typically ~2-3 seconds — so nothing here needs its own progress/timer
    // UI; the update just arrives and this listener re-renders in place.

    chrome.runtime.onMessage.addListener((msg, sender) => {
        // v3.6.0 (3P Matrix 5.0.6 C46) — only this extension's own service worker pushes results here.
        if (!sender || sender.id !== chrome.runtime.id ||
            MessageGate.senderKind(sender, chrome.runtime.getURL("")) !== MessageGate.SENDER_KIND.EXTENSION_PAGE) return;
        if (!msg || msg.type !== MSG.VT_RESULT_UPDATE) return;
        if (msg.downloadId !== downloadId)     return;

        // Merge the pushed fields into a synthetic data object and re-render
        const merged = Object.assign({}, lastVtData || {}, {
            vtScore:         msg.vtScore         ?? null,
            vtConfidence:    msg.vtConfidence     ?? null,
            vtBreakdown:     msg.vtBreakdown      ?? null,
            vtHardRule:      msg.vtHardRule        ?? null,
            vtRawStats:      msg.vtRawStats        ?? null,
            vtFilteredStats: msg.vtFilteredStats   ?? null,
            vtFpLevel:       msg.vtFpLevel         ?? null,
            vtDone:          true,
        });
        applyVtResult(merged);
        renderDisclaimer(merged);
        if (msg.hostVerdict) renderHostReputation(msg.hostVerdict);   // v3.5.6 — VirusTotal's answer can switch it
        else if (lastHostData) renderHostReputation(lastHostData);
    });

    // ── Initial render ────────────────────────────────────────────────────────
    // In V2.0+ architecture background.js waits for all checks before opening
    // the warning page — fetch the record once and render in a single pass.

    chrome.runtime.sendMessage(
        { type: MSG.GET_PENDING_CHECK, downloadId },
        data => {
            if (!data) {
                if (document.body) document.body.style.opacity = "0.5";
                if (srcUrl) srcUrl.textContent = "Download no longer active — you can close this window.";
                return;
            }
            applyVtResult(data);
            renderDisclaimer(data);
            const host = data.hostVerdict ?? data.hostResult;   // v3.5.6 — the host verdict that applies
            if (host) renderHostReputation(host);
        }
    );

})(); // end IIFE
