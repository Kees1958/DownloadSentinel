"use strict";

// ── VtKeyPromptPolicy.js ──────────────────────────────────────────────────────
// Pure decision logic for the startup "Get a free VirusTotal API Key" nudge
// popup (v3.0.7). Extracted out of background.js so the three independent
// reasons the popup must NOT show are gathered in one place and unit-tested
// directly, rather than living inline in the service worker where they'd
// only ever be exercised indirectly.
//
// Public interface:
//   shouldShowVtKeyPrompt(settings) -> boolean
// ─────────────────────────────────────────────────────────────────────────────

export const VtKeyPromptPolicy = (function () {

    function shouldShowVtKeyPrompt(settings) {
        if (!settings) return false;
        if (settings.extensionEnabled === false) return false;         // master switch is off
        if (settings.isVtApiKeySet && settings.vtApiKey) return false; // key already set
        if (settings.vtKeyPromptDismissed) return false;               // user ticked "don't show again"
        return true;
    }

    return { shouldShowVtKeyPrompt };
})();
