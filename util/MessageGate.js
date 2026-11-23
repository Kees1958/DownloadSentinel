"use strict";

// ── MessageGate.js ────────────────────────────────────────────────────────────
// v3.6.0 (from 3P Matrix 5.0.6 C46 + 5.0.7 C52) — who may send a message to the router, and how a refused
// sender is named in a log. Pure: no chrome.* call, no state.
//
// Public interface:
//   SENDER_KIND                            — frozen enum of sender kinds
//   senderKind(sender, extensionOrigin)    → SENDER_KIND.EXTENSION_PAGE (this extension's own pages and its
//                                            service worker), or null (unknown/foreign sender)
//   isMessageAllowed(type, kind)           → true when `kind` may send message `type` (a known MSG.* only)
//   senderLabel(sender)                    → the sender's origin only, for logs (never a full address)
//
// Why: the router (background.js) used to accept any sender that carried this extension's id. DownloadSentinel
// has no content scripts today, so that was the same as "our own pages" — but only by accident: a content script
// (code that runs next to hostile pages) carries the same id. Now a sender must ALSO be one of this extension's
// own pages (its URL starts with the extension origin). Should a content script ever be added, its messages must
// be listed here explicitly (3P Matrix's CONTENT_SCRIPT_MESSAGES) — until then it is refused everything.
// Same rule as 3P Matrix core/message-gate.js and uBlock-Stripped-Dynamic's route table (SENDER_KINDS).
//
// Consumers: background.js (router), pages/warning/WarningPage.js (VT_RESULT_UPDATE listener).
// Dependencies: util/MessageTypes.js (MSG — the set of known message types).
// State owned: none.
// ─────────────────────────────────────────────────────────────────────────────

import { MSG } from "./MessageTypes.js";

const SENDER_KIND = Object.freeze({ EXTENSION_PAGE: "extensionPage" });
const KNOWN_TYPES = Object.freeze(new Set(Object.values(MSG)));
const UNKNOWN_SENDER_LABEL = "an unknown sender";
const UNPARSEABLE_SENDER_LABEL = "an unparseable sender";

// `extensionOrigin` = chrome.runtime.getURL("") (ends with "/"), passed in so this module stays pure and testable.
function senderKind(sender, extensionOrigin) {
    if (!sender || typeof sender.url !== "string" || typeof extensionOrigin !== "string" || extensionOrigin === "") return null;
    return sender.url.startsWith(extensionOrigin) ? SENDER_KIND.EXTENSION_PAGE : null;
}

function isMessageAllowed(type, kind) {
    return kind === SENDER_KIND.EXTENSION_PAGE && KNOWN_TYPES.has(type);
}

// Logs name the sender by origin only — a full address can carry a path, query or token (3P Matrix C52).
function senderLabel(sender) {
    if (!sender || typeof sender.url !== "string") return UNKNOWN_SENDER_LABEL;
    try {
        const u = new URL(sender.url);
        // Non-web schemes (chrome-extension:) can report origin "null" — rebuild it from scheme + host.
        return u.origin !== "null" ? u.origin : `${u.protocol}//${u.host}`;
    } catch { return UNPARSEABLE_SENDER_LABEL; }
}

export const MessageGate = Object.freeze({ SENDER_KIND, senderKind, isMessageAllowed, senderLabel });
