"use strict";

// ── PopupPage.js ──────────────────────────────────────────────────────────────
// Popup controller — displays extension and VT on/off state; routes to options.
//
// Public interface:
//   window.SentinelPopup.initialize()  — called on DOMContentLoaded
//
// State owned: none (all state is in chrome.storage via Settings)
// ─────────────────────────────────────────────────────────────────────────────

import { MSG } from "../../util/MessageTypes.js";
import { Settings } from "../../util/Settings.js";
import { APP } from "../../util/AppConstants.js";
import { QuietLog } from "../../util/QuietLog.js"; // v3.5.2 — downloads checked without a warning window

window.SentinelPopup = window.SentinelPopup || (function () {

    // ── State helpers ──────────────────────────────────────────────────────────

    function getState(settings) {
        if (!settings.extensionEnabled) return "off";
        const hasKey = settings.isVtApiKeySet &&
                       settings.vtApiKey &&
                       settings.vtApiKey.trim() !== "";
        if (!hasKey || !settings.virusTotalEnabled) return "no-key";
        return "ready";
    }

    function hasApiKey(settings) {
        return !!(settings.isVtApiKeySet &&
                  settings.vtApiKey &&
                  settings.vtApiKey.trim() !== "");
    }

    // ── UI update ──────────────────────────────────────────────────────────────

    function applyUI(settings) {
        const state      = getState(settings);
        const banner     = document.getElementById("banner");
        const logo       = document.getElementById("logo");
        const sw         = document.getElementById("extSwitch");
        const statusLbl  = document.getElementById("extStatus");
        const optionsBtn = document.getElementById("optionsBtn");

        banner.className = "banner state-" + state;

        logo.src = settings.extensionEnabled
            ? "../../assets/icons/icon128.png"
            : "../../assets/icons/icon128_OFF.png";

        sw.className = "switch " + (settings.extensionEnabled ? "on" : "off");

        if (state === "off") {
            statusLbl.textContent = "download warning disabled";
            statusLbl.className   = "status-label inactive";
        } else {
            statusLbl.textContent = "download warning enabled";
            statusLbl.className   = "status-label";
        }

        optionsBtn.className = "options-btn";
        applyVtSwitch(settings);
    }

    // ── VT switch ──────────────────────────────────────────────────────────────

    function applyVtSwitch(settings) {
        const keyPresent = hasApiKey(settings);
        const enabled    = keyPresent && settings.virusTotalEnabled;

        const sw       = document.getElementById("vtSwitch");
        const lbl      = document.getElementById("vtStatus");
        const infoIcon = document.getElementById("vtInfoIcon");

        sw.className = "switch " +
            (enabled ? "on" : "off") +
            (keyPresent ? "" : " vt-locked");

        lbl.textContent = enabled
            ? "reputation check enabled"
            : "reputation check disabled";

        lbl.className = "status-label vt-label" + (enabled ? "" : " vt-disabled");

        // The info icon only makes sense while there's no key yet — it's the
        // "here's why, and here's how to get one" nudge. Once a key is set,
        // the row speaks for itself and the icon is just clutter.
        infoIcon.style.display = keyPresent ? "none" : "inline-flex";
    }

    function bindVtSwitch() {
        document.getElementById("vtSwitch").addEventListener("click", () => {
            Settings.get(settings => {
                if (!hasApiKey(settings)) return;

                const newVal = !settings.virusTotalEnabled;
                Settings.set({ virusTotalEnabled: newVal }, () => {
                    chrome.runtime.sendMessage({ type: MSG.SETTINGS_UPDATED }).catch(() => {});
                    applyUI({ ...settings, virusTotalEnabled: newVal });
                });
            });
        });
    }

    // ── Main extension switch ──────────────────────────────────────────────────

    function bindSwitch() {
        document.getElementById("extSwitch").addEventListener("click", () => {
            Settings.get(settings => {
                const newEnabled = !settings.extensionEnabled;
                Settings.set({ extensionEnabled: newEnabled }, () => {
                    chrome.runtime.sendMessage({
                        type:    MSG.EXTENSION_TOGGLE,
                        enabled: newEnabled
                    }).catch(() => {});
                    applyUI({ ...settings, extensionEnabled: newEnabled });
                });
            });
        });
    }

    // ── Options button ────────────────────────────────────────────────────────

    function bindOptionsButton() {
        document.getElementById("optionsBtn").addEventListener("click", () => {
            chrome.runtime.openOptionsPage();
            window.close();
        });
    }

    // ── VT info-icon tooltip link ─────────────────────────────────────────────
    // The icon itself opens/closes the tooltip via CSS :hover/:focus-within —
    // only the "Get a free API key" link inside it needs a click handler.

    function bindVtInfoLink() {
        const link = document.getElementById("vtInfoLink");
        if (!link) return;

        link.addEventListener("click", event => {
            event.preventDefault();
            event.stopPropagation(); // don't let the click bubble into the switch row
            chrome.tabs.create({ url: APP.VT_JOIN_URL }).catch(() => {});
            window.close();
        });
    }

    // ── Quiet downloads (v3.5.2) ──────────────────────────────────────────────
    // Lists the downloads that were checked but got no warning window, newest
    // first, then clears the list and the toolbar badge (opened = seen).
    function renderQuietList(list) {
        const box = document.getElementById("quietBox");
        const ul  = document.getElementById("quietList");
        ul.replaceChildren();
        for (const e of list) {
            const li   = document.createElement("li");
            const file = document.createElement("div");
            file.className   = "quiet-file";
            file.textContent = e.filename || "(no name)";
            const meta = document.createElement("div");
            meta.className   = "quiet-meta";
            meta.textContent = `${e.host || "unknown host"} · ${e.verdict} (${e.score})`;
            li.append(file, meta);
            ul.appendChild(li);
        }
        box.hidden = list.length === 0;
    }

    function showQuietDownloads() {
        QuietLog.read(list => {
            renderQuietList(list);
            if (list.length > 0) QuietLog.clear();
        });
    }

    // ── Init ──────────────────────────────────────────────────────────────────

    function initialize() {
        showQuietDownloads();
        bindSwitch();
        bindVtSwitch();
        bindOptionsButton();
        bindVtInfoLink();
        Settings.get(settings => applyUI(settings));
    }

    return { initialize };
})();

document.addEventListener("DOMContentLoaded", () => {
    window.SentinelPopup.initialize();
});
