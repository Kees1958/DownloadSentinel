"use strict";

// ── QuietLog.js ───────────────────────────────────────────────────────────────
// v3.5.2 — downloads that were checked but got NO warning window
// (protection/WarnPolicy.js decided "quiet"). Each one is listed in the popup
// and counted on the toolbar badge, so a quiet decision is never invisible.
//
// Lifecycle (guards):
//   init()   — INIT: restore the badge from storage.session (service-worker
//              restart); idempotent.
//   add(e)   — append one entry, keep the newest APP.QUIET_LOG_MAX, update badge.
//   read(cb) — the list, newest first (popup).
//   clear()  — RELEASE: empty the list and the badge (popup opened = seen).
//
// Entry: { filename, host, verdict, score, at } — display data only, no record.
// Storage: storage.session through util/Storage.js (single storage layer, C4).
// Toolbar: chrome.action badge text/colour/title (no permission needed).
// Dependencies: AppConstants.js, Storage.js.
// ─────────────────────────────────────────────────────────────────────────────
import { APP } from "./AppConstants.js";
import { Storage } from "./Storage.js";

export const QuietLog = (function () {

    let initialized = false;

    function showBadge(count) {
        const text = count > 0 ? String(count) : "";
        chrome.action.setBadgeText({ text }).catch(err => console.warn("[DS] setBadgeText failed:", err?.message));
        if (count > 0) {
            chrome.action.setBadgeBackgroundColor({ color: APP.QUIET_BADGE_COLOR })
                .catch(err => console.warn("[DS] setBadgeBackgroundColor failed:", err?.message));
        }
        // title "" restores the manifest's default_title
        const title = count > 0 ? APP.QUIET_BADGE_TITLE.replace(APP.QUIET_COUNT_TOKEN, String(count)) : "";
        chrome.action.setTitle({ title }).catch(err => console.warn("[DS] setTitle failed:", err?.message));
    }

    function read(callback) {
        Storage.getFromSessionStore(APP.QUIET_LOG_KEY, list => callback(Array.isArray(list) ? list : []));
    }

    function init() {
        if (initialized) return;
        initialized = true;
        read(list => showBadge(list.length));
    }

    function add(entry) {
        read(list => {
            const next = [entry, ...list].slice(0, APP.QUIET_LOG_MAX);
            Storage.setToSessionStore(APP.QUIET_LOG_KEY, next, () => showBadge(next.length));
        });
    }

    function clear() {
        Storage.setToSessionStore(APP.QUIET_LOG_KEY, [], () => showBadge(0));
    }

    return { init, add, read, clear };
})();
