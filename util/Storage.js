"use strict";

// ── Storage.js ────────────────────────────────────────────────────────────────
// Single storage-access layer for chrome.storage.local and (v3.5.2)
// chrome.storage.session.
//
// Public interface:
//   Storage.getFromLocalStore(key, callback)       — read one key
//   Storage.setToLocalStore(key, value, callback)  — write one key
//   Storage.getFromSessionStore(key, callback)     — v3.5.2: read one key from storage.session
//   Storage.setToSessionStore(key, value, callback)— v3.5.2: write one key to storage.session
//       (session = kept while the browser runs, across service-worker restarts,
//        cleared on browser restart; readable by the extension's own pages)
//
// Dependencies: none
//
// State owned: none (stateless pass-through to chrome.storage.local)
//
// NOTE: All chrome.storage.local access in the extension must go through this
// module (audit item C4). Feature modules must not call chrome.storage directly.
// ─────────────────────────────────────────────────────────────────────────────

export const Storage = {

    getFromLocalStore: function getFromLocalStore(key, callback) {
        chrome.storage.local.get(key, function (result) {
            if (chrome.runtime.lastError) {
                console.error("[Sentinel] storage.get error:", chrome.runtime.lastError.message);
            }
            callback(result && result[key]);
        });
    },

    getFromSessionStore: function getFromSessionStore(key, callback) {
        chrome.storage.session.get(key, function (result) {
            if (chrome.runtime.lastError) {
                console.error("[Sentinel] storage.session.get error:", chrome.runtime.lastError.message);
            }
            callback(result && result[key]);
        });
    },
    setToSessionStore: function setToSessionStore(key, value, callback) {
        const data = {};
        data[key] = value;
        chrome.storage.session.set(data, function () {
            if (chrome.runtime.lastError) {
                console.error("[Sentinel] storage.session.set error:", chrome.runtime.lastError.message);
            }
            if (callback) callback();
        });
    },
    setToLocalStore: function setToLocalStore(key, value, callback) {
        const data = {};
        data[key] = value;
        chrome.storage.local.set(data, function () {
            if (chrome.runtime.lastError) {
                console.error("[Sentinel] storage.set error:", chrome.runtime.lastError.message);
            }
            if (callback) callback();
        });
    }
};
