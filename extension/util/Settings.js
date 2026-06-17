"use strict";

// Manages user preferences and configurations.
const Settings = (function () {
    const settingsKey = "Settings"; // Key for storing settings in local storage

    let defaultSettings = {
        extensionEnabled: true,      // Master on/off switch for the extension
        virusTotalEnabled: true,     // Whether VT URL check is active (requires API key)

        isInstanceIDInitialized: false,
        instanceID: 0,

        vtApiKey: "",                // VirusTotal API key entered by the user
        isVtApiKeySet: false,        // Whether the user has provided a VT API key

        // Custom warning background color (default: Google Red)
        warningColorR: 179,
        warningColorG: 38,
        warningColorB: 30,

        // Custom whitelist domains (up to 12, in addition to built-in defaults)
        customDomains: []
    };

    const updateIfChanged = function (target, source) {
        let hasChanges = false;
        if (source) {
            for (let key in source) {
                if (source[key] !== target[key]) {
                    target[key] = source[key];
                    hasChanges = true;
                }
            }
        }
        return hasChanges;
    };

    return {
        get: function (callback) {
            Storage.getFromLocalStore(settingsKey, (function (storedSettings) {
                let mergedSettings = JSON.parse(JSON.stringify(defaultSettings));
                updateIfChanged(mergedSettings, storedSettings);
                callback && callback(mergedSettings);
            }));
        },

        set: function (newSettings, callback) {
            Storage.getFromLocalStore(settingsKey, (function (storedSettings) {
                let mergedSettings = JSON.parse(JSON.stringify(defaultSettings));
                storedSettings && updateIfChanged(mergedSettings, storedSettings);
                updateIfChanged(mergedSettings, newSettings);
                Storage.setToLocalStore(settingsKey, mergedSettings, callback);
            }));
        }
    };
})();
