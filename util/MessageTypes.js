"use strict";

// ── MessageTypes.js ───────────────────────────────────────────────────────────
// Single source of truth for all chrome.runtime message type strings.
//
// Public interface:
//   MSG  {Object}  — frozen map of message-type string constants
//
// Dependencies: none
//
// Usage:
//   Service worker:   importScripts("util/MessageTypes.js")
//   Page contexts:    <script src="../../util/MessageTypes.js">
//
// Rule: never write a bare string like "GET_PENDING_CHECK" in any send or
// receive site — always use MSG.GET_PENDING_CHECK. A typo then causes a
// reference error (caught at dev time) instead of a silent no-op.
// ─────────────────────────────────────────────────────────────────────────────

export const MSG = Object.freeze({
    // Warning page requests the pending-check record for its downloadId
    GET_PENDING_CHECK: "GET_PENDING_CHECK",

    // Warning page or options page requests background to clean up a check
    DISMISS_CHECK: "DISMISS_CHECK",

    // Popup notifies background that the master on/off toggle changed
    EXTENSION_TOGGLE: "EXTENSION_TOGGLE",

    // Any options page notifies background that settings were saved
    SETTINGS_UPDATED: "SETTINGS_UPDATED",

    // Warning page requests a fresh VT submission + polling cycle.
    // As of this audit, nothing currently sends this — see CHANGELOG and
    // background.js's submitAndPollVt() header comment for status.
    SUBMIT_URL_TO_VT: "SUBMIT_URL_TO_VT",

    // Background pushes a fresh VT result to the warning page after polling
    VT_RESULT_UPDATE: "VT_RESULT_UPDATE",
});
