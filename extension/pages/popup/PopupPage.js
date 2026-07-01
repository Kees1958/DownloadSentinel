"use strict";

window.SentinelPopup = window.SentinelPopup || (function () {

    const browserAPI = typeof browser === 'undefined' ? chrome : browser;

    // ── Helpers ────────────────────────────────────────────────────────────────

    function getState(settings) {

        if (!settings.extensionEnabled) {
            return 'off';
        }

        const hasKey =
            settings.isVtApiKeySet &&
            settings.vtApiKey &&
            settings.vtApiKey.trim() !== '';

        if (!hasKey || !settings.virusTotalEnabled) {
            return 'no-key';
        }

        return 'ready';
    }

    // ── UI update ──────────────────────────────────────────────────────────────

    function applyUI(settings) {

        const state      = getState(settings);
        const banner     = document.getElementById('banner');
        const logo       = document.getElementById('logo');
        const sw         = document.getElementById('extSwitch');
        const statusLbl  = document.getElementById('extStatus');
        const optionsBtn = document.getElementById('optionsBtn');

        banner.className = 'banner state-' + state;

        logo.src = settings.extensionEnabled
            ? '../../assets/icons/icon128.png'
            : '../../assets/icons/icon128_OFF.png';

        sw.className = 'switch ' +
            (settings.extensionEnabled ? 'on' : 'off');

        if (state === 'off') {
            statusLbl.textContent = 'download warning disabled';
            statusLbl.className = 'status-label inactive';
        } else {
            statusLbl.textContent = 'download warning enabled';
            statusLbl.className = 'status-label';
        }

        optionsBtn.className = 'options-btn';

        applyVtSwitch(settings);
    }

    // ── VT switch ──────────────────────────────────────────────────────────────

    function applyVtSwitch(settings) {

        const hasKey =
            settings.isVtApiKeySet &&
            settings.vtApiKey &&
            settings.vtApiKey.trim() !== '';

        const enabled =
            hasKey &&
            settings.virusTotalEnabled;

        const sw  = document.getElementById('vtSwitch');
        const lbl = document.getElementById('vtStatus');

        sw.className =
            'switch ' +
            (enabled ? 'on' : 'off') +
            (hasKey ? '' : ' vt-locked');

        lbl.textContent = enabled
            ? 'reputation check enabled'
            : 'reputation check disabled';

        lbl.className =
            'status-label vt-label' +
            (enabled ? '' : ' vt-disabled');
    }

    function bindVtSwitch() {

        document.getElementById('vtSwitch').addEventListener('click', () => {

            Settings.get(settings => {

                const hasKey =
                    settings.isVtApiKeySet &&
                    settings.vtApiKey &&
                    settings.vtApiKey.trim() !== '';

                if (!hasKey) {
                    return;
                }

                const newVal = !settings.virusTotalEnabled;

                Settings.set(
                    { virusTotalEnabled: newVal },
                    () => {

                        const updatedSettings = {
                            ...settings,
                            virusTotalEnabled: newVal
                        };

                        browserAPI.runtime.sendMessage({
                            type: 'SETTINGS_UPDATED'
                        }).catch(() => {});

                        applyUI(updatedSettings);
                    }
                );
            });
        });
    }

    // ── Main switch ────────────────────────────────────────────────────────────

    function bindSwitch() {

        const sw = document.getElementById('extSwitch');

        sw.addEventListener('click', () => {

            Settings.get(settings => {

                const newEnabled =
                    !settings.extensionEnabled;

                Settings.set(
                    { extensionEnabled: newEnabled },
                    () => {

                        browserAPI.runtime.sendMessage({
                            type: 'EXTENSION_TOGGLE',
                            enabled: newEnabled
                        }).catch(() => {});

                        applyUI({
                            ...settings,
                            extensionEnabled: newEnabled
                        });
                    }
                );
            });
        });
    }

    // ── Options button ────────────────────────────────────────────────────────

    function bindOptionsButton() {

        document.getElementById('optionsBtn')
            .addEventListener('click', () => {

                browserAPI.runtime.openOptionsPage();
                window.close();
            });
    }

    // ── Init ──────────────────────────────────────────────────────────────────

    function initialize() {

        bindSwitch();
        bindVtSwitch();
        bindOptionsButton();

        Settings.get(settings => {
            applyUI(settings);
        });
    }

    return { initialize };

})();

document.addEventListener('DOMContentLoaded', () => {
    window.SentinelPopup.initialize();
});
