"use strict";

// ── VtKeyPrompt.js ────────────────────────────────────────────────────────────
// Controller for the startup "Get a free VirusTotal API Key" nudge popup
// (v3.0.7). background.js opens this page in a small popup window on
// browser startup when no VT key is set and the user hasn't dismissed it
// (see background.js's shouldShowVtKeyPrompt()).
//
// Public interface: none (self-contained, runs on load)
//
// Behavior:
//   Request → opens VT's "join us" page in a new tab; if the "don't show
//             again" checkbox is ticked, also persists the dismissal.
//   Ignore  → closes with no lasting effect, UNLESS the checkbox is ticked,
//             in which case the dismissal is persisted exactly as above.
//   Either way the window closes itself afterward — this page never lingers.
// ─────────────────────────────────────────────────────────────────────────────

import { APP } from "../../util/AppConstants.js";
import { Settings } from "../../util/Settings.js";

(function () {

    const checkbox   = document.getElementById("dontShowAgain");
    const ignoreBtn  = document.getElementById("ignoreBtn");
    const requestBtn = document.getElementById("requestBtn");

    // Guard: every button handler below disables both buttons on first
    // click — a double-click can't fire this twice (e.g. two tabs opened,
    // or a write racing a second write) and the window is about to close
    // anyway, so there is nothing left to re-enable them for.
    function disableButtons() {
        ignoreBtn.disabled  = true;
        requestBtn.disabled = true;
    }

    // Persists the opt-out when asked, then always closes the window —
    // the single exit path both buttons funnel through.
    function finish(persistDismissal) {
        if (!persistDismissal) { window.close(); return; }
        Settings.set({ vtKeyPromptDismissed: true }, () => window.close());
    }

    if (ignoreBtn) {
        ignoreBtn.addEventListener("click", () => {
            disableButtons();
            finish(checkbox?.checked ?? false);
        });
    }

    if (requestBtn) {
        requestBtn.addEventListener("click", () => {
            disableButtons();
            chrome.tabs.create({ url: APP.VT_JOIN_URL }).catch(() => { /* best-effort — window still closes below */ });
            finish(checkbox?.checked ?? false);
        });
    }

})();
