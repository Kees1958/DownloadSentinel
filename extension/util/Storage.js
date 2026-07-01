"use strict";

// Storage utility for interacting with the browser's local storage.
const Storage = {

    getFromLocalStore: function (key, callback) {
        const browserAPI = typeof browser === 'undefined' ? chrome : browser;
        browserAPI.storage.local.get(key, function (result) {
            if (chrome.runtime.lastError) {
                console.error('[Sentinel] storage.get error:', chrome.runtime.lastError.message);
            }
            callback(result && result[key]);
        });
    },

    setToLocalStore: function (key, value, callback) {
        const browserAPI = typeof browser === 'undefined' ? chrome : browser;
        const data = {};
        data[key] = value;
        browserAPI.storage.local.set(data, function () {
            if (chrome.runtime.lastError) {
                console.error('[Sentinel] storage.set error:', chrome.runtime.lastError.message);
            }
            if (callback) callback();
        });
    }
};
