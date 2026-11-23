"use strict";

// ── VtKeyPromptPolicy.test.js ───────────────────────────────────────────────
// Covers util/VtKeyPromptPolicy.js — the pure show/don't-show decision for
// the startup "Get a free VirusTotal API Key" nudge popup (v3.0.7).

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { VtKeyPromptPolicy } from "../../util/VtKeyPromptPolicy.js";

function baseSettings(overrides = {}) {
    return {
        extensionEnabled: true,
        isVtApiKeySet: false,
        vtApiKey: "",
        vtKeyPromptDismissed: false,
        ...overrides
    };
}

describe("VtKeyPromptPolicy.shouldShowVtKeyPrompt", () => {
    test("no key, not dismissed, extension on — shows the prompt", () => {
        assert.equal(VtKeyPromptPolicy.shouldShowVtKeyPrompt(baseSettings()), true);
    });

    test("a VT key is already set (both isVtApiKeySet and vtApiKey) — never shows", () => {
        const s = baseSettings({ isVtApiKeySet: true, vtApiKey: "a".repeat(64) });
        assert.equal(VtKeyPromptPolicy.shouldShowVtKeyPrompt(s), false);
    });

    test("isVtApiKeySet true but vtApiKey empty (inconsistent/cleared state) — still shows, matching the rest of the app's isVtApiKeySet && vtApiKey convention", () => {
        const s = baseSettings({ isVtApiKeySet: true, vtApiKey: "" });
        assert.equal(VtKeyPromptPolicy.shouldShowVtKeyPrompt(s), true);
    });

    test("user ticked \"don't show again\" — never shows, even with no key", () => {
        const s = baseSettings({ vtKeyPromptDismissed: true });
        assert.equal(VtKeyPromptPolicy.shouldShowVtKeyPrompt(s), false);
    });

    test("extension master switch is off — never shows, regardless of key/dismissal state", () => {
        const s = baseSettings({ extensionEnabled: false });
        assert.equal(VtKeyPromptPolicy.shouldShowVtKeyPrompt(s), false);
    });

    test("missing/null settings object — defensively returns false, never throws", () => {
        assert.equal(VtKeyPromptPolicy.shouldShowVtKeyPrompt(null), false);
        assert.equal(VtKeyPromptPolicy.shouldShowVtKeyPrompt(undefined), false);
    });
});
