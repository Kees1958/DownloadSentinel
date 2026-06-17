"use strict";

window.SentinelOptions = window.SentinelOptions || (function () {

    const browserAPI = typeof browser === 'undefined' ? chrome : browser;

    // ── Helpers ────────────────────────────────────────────────────────────────

    function getState(settings) {
        if (!settings.isVtApiKeySet || !settings.vtApiKey) return 'no-key';
        return 'ready';
    }

    // Valid domain: at least one label, dot, TLD (letters only, 2-24 chars)
    const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}$/;

    function isValidDomain(val) {
        return val === '' || DOMAIN_RE.test(val);
    }

    function clamp(n) {
        const v = parseInt(n, 10);
        if (isNaN(v)) return 0;
        return Math.min(255, Math.max(0, v));
    }

    function setMsg(id, text, type) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = text;
        el.className = 'api-msg ' + (type || '');
    }

    // ── Banner / UI state ──────────────────────────────────────────────────────

    function applyBannerState(settings) {
        const state  = getState(settings);
        const banner = document.getElementById('banner');
        banner.className = 'banner state-' + state;
    }

    function unlockSections(unlock) {
        ['colorSection', 'domainSection'].forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            el.classList.toggle('locked',    !unlock);
            el.classList.toggle('unlocked',   unlock);
        });
    }

    // ── API key ────────────────────────────────────────────────────────────────

    function loadApiKeyField(settings) {
        const input = document.getElementById('vtApiKeyInput');
        if (settings.isVtApiKeySet && settings.vtApiKey) {
            // Show masked placeholder so user knows a key is stored
            input.placeholder = '••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••';
        }
    }

    function bindApiKey() {
        // Save key
        document.getElementById('saveKeyBtn').addEventListener('click', () => {
            const raw = document.getElementById('vtApiKeyInput').value.trim();
            if (!raw) {
                setMsg('apiKeyMsg', 'Please enter your API key.', 'error');
                return;
            }
            if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
                setMsg('apiKeyMsg', 'Invalid key — expected 64 hex characters.', 'error');
                return;
            }
            Settings.set({ vtApiKey: raw, isVtApiKeySet: true, virusTotalEnabled: true }, () => {
                setMsg('apiKeyMsg', 'API key saved!', 'success');
                document.getElementById('vtApiKeyInput').value = '';
                document.getElementById('vtApiKeyInput').placeholder =
                    '••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••';
                Settings.get(s => {
                    applyBannerState(s);
                    unlockSections(true);
                });
                notifyBackground();
            });
        });

        // Allow Enter key
        document.getElementById('vtApiKeyInput').addEventListener('keydown', e => {
            if (e.key === 'Enter') document.getElementById('saveKeyBtn').click();
        });

        // Clear key
        document.getElementById('clearKeyBtn').addEventListener('click', () => {
            Settings.set({ vtApiKey: '', isVtApiKeySet: false, virusTotalEnabled: false }, () => {
                setMsg('apiKeyMsg', 'API key cleared.', 'info');
                document.getElementById('vtApiKeyInput').value = '';
                document.getElementById('vtApiKeyInput').placeholder =
                    'Paste your VT API key (64 hex characters)…';
                Settings.get(s => {
                    applyBannerState(s);
                    unlockSections(false);
                });
                notifyBackground();
            });
        });
    }

    // ── Color section ──────────────────────────────────────────────────────────

    function updateColorPreview() {
        const r = clamp(document.getElementById('colorR').value || 179);
        const g = clamp(document.getElementById('colorG').value || 38);
        const b = clamp(document.getElementById('colorB').value || 30);
        document.getElementById('colorPreview').style.backgroundColor =
            `rgb(${r}, ${g}, ${b})`;
    }

    function loadColorFields(settings) {
        document.getElementById('colorR').value = settings.warningColorR ?? 179;
        document.getElementById('colorG').value = settings.warningColorG ?? 38;
        document.getElementById('colorB').value = settings.warningColorB ?? 30;
        updateColorPreview();
    }

    function bindColorSection() {
        ['colorR', 'colorG', 'colorB'].forEach(id => {
            document.getElementById(id).addEventListener('input', updateColorPreview);
        });

        document.getElementById('saveColorBtn').addEventListener('click', () => {
            const r = clamp(document.getElementById('colorR').value);
            const g = clamp(document.getElementById('colorG').value);
            const b = clamp(document.getElementById('colorB').value);
            Settings.set({ warningColorR: r, warningColorG: g, warningColorB: b }, () => {
                setMsg('colorMsg', 'Color saved!', 'success');
                setTimeout(() => setMsg('colorMsg', '', ''), 2000);
            });
        });
    }

    // ── Domain whitelist ───────────────────────────────────────────────────────

    function buildDomainInputs() {
        const container = document.getElementById('domainInputs');
        for (let i = 0; i < 12; i++) {
            const inp = document.createElement('input');
            inp.type        = 'text';
            inp.className   = 'domain-input';
            inp.id          = 'domain_' + i;
            inp.placeholder = 'e.g. example.com';
            inp.spellcheck  = false;
            inp.autocomplete = 'off';
            inp.addEventListener('input', () => validateDomainInput(inp));
            container.appendChild(inp);
        }
    }

    function validateDomainInput(inp) {
        const val = inp.value.trim();
        if (val === '') {
            inp.className = 'domain-input';
        } else if (isValidDomain(val)) {
            inp.className = 'domain-input valid';
        } else {
            inp.className = 'domain-input invalid';
        }
    }

    function loadDomainFields(settings) {
        const domains = Array.isArray(settings.customDomains) ? settings.customDomains : [];
        for (let i = 0; i < 12; i++) {
            const inp = document.getElementById('domain_' + i);
            if (inp) inp.value = domains[i] || '';
        }
    }

    function bindDomainSection() {
        document.getElementById('saveDomainsBtn').addEventListener('click', () => {
            const domains = [];
            let hasError = false;

            for (let i = 0; i < 12; i++) {
                const inp = document.getElementById('domain_' + i);
                const val = inp ? inp.value.trim() : '';
                if (val !== '') {
                    if (!isValidDomain(val)) {
                        hasError = true;
                        inp.className = 'domain-input invalid';
                    } else {
                        domains.push(val);
                    }
                }
            }

            if (hasError) {
                setMsg('domainMsg', 'Fix invalid domains before saving (format: domain.tld).', 'error');
                return;
            }

            Settings.set({ customDomains: domains }, () => {
                setMsg('domainMsg', 'Domains saved!', 'success');
                setTimeout(() => setMsg('domainMsg', '', ''), 2000);
                notifyBackground();
            });
        });
    }

    // ── Notify background ──────────────────────────────────────────────────────

    function notifyBackground() {
        browserAPI.runtime.sendMessage({ type: 'SETTINGS_UPDATED' }).catch(() => {});
    }

    // ── Init ───────────────────────────────────────────────────────────────────

    function initialize() {
        buildDomainInputs();
        bindApiKey();
        bindColorSection();
        bindDomainSection();

        Settings.get(settings => {
            applyBannerState(settings);
            loadApiKeyField(settings);
            loadColorFields(settings);
            loadDomainFields(settings);
            unlockSections(settings.isVtApiKeySet && !!settings.vtApiKey);
        });
    }

    return { initialize };
})();

document.addEventListener('DOMContentLoaded', () => {
    window.SentinelOptions.initialize();
});
