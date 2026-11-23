"use strict";

// ── OptionsPage.js ────────────────────────────────────────────────────────────
// Options page controller — loads, displays, and saves all user settings.
//
// Public interface:
//   window.SentinelOptions.initialize()  — called on DOMContentLoaded
//
// State owned: none (all state is in chrome.storage via Settings)
// ─────────────────────────────────────────────────────────────────────────────

import { APP } from "../../util/AppConstants.js";
import { MSG } from "../../util/MessageTypes.js";
import { Settings } from "../../util/Settings.js";
import { DnsDefaults } from "../../util/DnsDefaults.js";
import { DnsPermissions } from "../../util/DnsPermissions.js";
import { WarnPolicy } from "../../protection/WarnPolicy.js"; // v3.5.2 — window threshold sentence per FP level

// ── DNS threat-intel dropdown options ────────────────────────────────────────
// Built once from APP.DNS_PROVIDERS (single source of truth, shared with
// DnsThreatProtection.js) plus a trailing "None" entry for disabling a slot.
const DNS_SELECT_OPTIONS = [
    ...Object.values(APP.DNS_PROVIDERS).map(p => ({ id: p.id, text: `${p.label} — ${p.host}` })),
    { id: APP.DNS_NONE, text: "None" },
];

window.SentinelOptions = window.SentinelOptions || (function () {

    // ── Helpers ────────────────────────────────────────────────────────────────

    function getState(settings) {
        if (!settings.isVtApiKeySet || !settings.vtApiKey) return "no-key";
        return "ready";
    }

    // Valid domain: at least one label, dot, TLD (letters only, 2-24 chars)
    const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}$/;

    function isValidDomain(val) {
        return val === "" || DOMAIN_RE.test(val);
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
        el.className = "api-msg " + (type || "");
    }

    // ── Banner / UI state ──────────────────────────────────────────────────────

    function applyBannerState(settings) {
        const state  = getState(settings);
        const banner = document.getElementById("banner");
        if (banner) banner.className = "banner state-" + state;
    }

    // v3.3.0 (3P Matrix alignment item 5) — none of these five sections
    // actually depend on a VT API key being set: the domain whitelist, the
    // DNS threat-intel checks, auto-allow, the FP-reduction level, and
    // warning-window personalization all work (and take effect in
    // background.js's scoring) whether or not VT is configured at all — VT
    // is only ONE of several independent signals the combined score adds
    // up. Locking them behind a VT key was unnecessarily conservative, so
    // this function (and its one caller below) always unlocks them now;
    // kept as a named function rather than inlined so a future genuinely
    // VT-dependent section has an obvious place to gate instead.
    function unlockSections() {
        ["silentWhenInconclusiveSection", "autoAllowSection", "domainSection", "dnsSection", "fpSection", "personalizeSection"].forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            el.classList.remove("locked");
            el.classList.add("unlocked");
        });
    }

    // ── Notify background ──────────────────────────────────────────────────────

    function notifyBackground() {
        // Use chrome directly — MV3 extensions in Chrome have no browser global
        chrome.runtime.sendMessage({ type: MSG.SETTINGS_UPDATED }).catch(() => {});
    }

    // ── API key ────────────────────────────────────────────────────────────────

    function updateSaveBtnState(keyIsSet) {
        const input = document.getElementById("vtApiKeyInput");
        const btn   = document.getElementById("saveKeyBtn");
        if (!btn || !input) return;
        const hasValue = input.value.trim().length > 0 || keyIsSet;
        btn.classList.toggle("key-active", hasValue);
    }

    function loadApiKeyField(settings) {
        const input = document.getElementById("vtApiKeyInput");
        if (!input) return;
        if (settings.isVtApiKeySet && settings.vtApiKey) {
            input.placeholder = "••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••";
        }
        updateSaveBtnState(settings.isVtApiKeySet && !!settings.vtApiKey);
    }

    function bindApiKey() {
        const input = document.getElementById("vtApiKeyInput");
        if (!input) return;
        input.addEventListener("input", () => updateSaveBtnState(false));

        // Save key
        document.getElementById("saveKeyBtn").addEventListener("click", () => {
            const raw = document.getElementById("vtApiKeyInput").value.trim();
            if (!raw) {
                setMsg("apiKeyMsg", "Please enter your API key.", "error");
                return;
            }
            if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
                setMsg("apiKeyMsg", "Invalid key — expected 64 hex characters.", "error");
                return;
            }
            Settings.set({ vtApiKey: raw, isVtApiKeySet: true, virusTotalEnabled: true }, () => {
                if (chrome.runtime.lastError) {
                    setMsg("apiKeyMsg", "Save failed — storage error.", "error");
                    return;
                }
                setMsg("apiKeyMsg", "API key saved!", "success");
                updateSaveBtnState(true);
                const vtInput = document.getElementById("vtApiKeyInput");
                vtInput.value       = "";
                vtInput.placeholder = "••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••";
                Settings.get(s => {
                    applyBannerState(s);
                });
                notifyBackground();
            });
        });

        // Allow Enter key to trigger save
        input.addEventListener("keydown", e => {
            if (e.key === "Enter") document.getElementById("saveKeyBtn").click();
        });

        // Clear key
        document.getElementById("clearKeyBtn").addEventListener("click", () => {
            Settings.set({ vtApiKey: "", isVtApiKeySet: false, virusTotalEnabled: false }, () => {
                if (chrome.runtime.lastError) {
                    setMsg("apiKeyMsg", "Clear failed — storage error.", "error");
                    return;
                }
                setMsg("apiKeyMsg", "API key cleared.", "info");
                const vtInput = document.getElementById("vtApiKeyInput");
                vtInput.value       = "";
                vtInput.placeholder = "Paste your VT API key (64 hex characters)…";
                Settings.get(s => {
                    applyBannerState(s);
                });
                notifyBackground();
            });
        });
    }

    // ── Color section ──────────────────────────────────────────────────────────

    function updateColorPreview() {
        const r = clamp(document.getElementById("colorR").value || APP.WARNING_COLOR_DEFAULT_R);
        const g = clamp(document.getElementById("colorG").value || APP.WARNING_COLOR_DEFAULT_G);
        const b = clamp(document.getElementById("colorB").value || APP.WARNING_COLOR_DEFAULT_B);
        document.getElementById("colorPreview").style.backgroundColor = `rgb(${r}, ${g}, ${b})`;
    }

    function loadColorFields(settings) {
        document.getElementById("colorR").value = settings.warningColorR ?? APP.WARNING_COLOR_DEFAULT_R;
        document.getElementById("colorG").value = settings.warningColorG ?? APP.WARNING_COLOR_DEFAULT_G;
        document.getElementById("colorB").value = settings.warningColorB ?? APP.WARNING_COLOR_DEFAULT_B;
        updateColorPreview();
    }

    // Reset the color + title fields in the DOM back to defaults. Used when
    // the user unchecks "Personalize" so the visible inputs never hold stale
    // customized values that could be re-saved by accident.
    function resetPersonalizeFieldsToDefault() {
        const r     = document.getElementById("colorR");
        const g     = document.getElementById("colorG");
        const b     = document.getElementById("colorB");
        const title = document.getElementById("warningTitleInput");
        if (r)     r.value     = APP.WARNING_COLOR_DEFAULT_R;
        if (g)     g.value     = APP.WARNING_COLOR_DEFAULT_G;
        if (b)     b.value     = APP.WARNING_COLOR_DEFAULT_B;
        if (title) title.value = "";
        updateColorPreview();
    }

    function bindColorSection() {
        ["colorR", "colorG", "colorB"].forEach(id => {
            document.getElementById(id).addEventListener("input", updateColorPreview);
        });
    }

    // ── Warning window title ───────────────────────────────────────────────────

    function loadTitleField(settings) {
        const input = document.getElementById("warningTitleInput");
        if (input) input.value = settings.warningTitle || "";
    }

    // ── Domain whitelist ───────────────────────────────────────────────────────

    // Render the built-in domain list dynamically from APP.BUILTIN_DO_NOT_CHECK_DOMAINS
    // so the options page always reflects the actual enforcement list in background.js.
    function renderBuiltinDomains() {
        const span = document.getElementById("builtinDomains");
        if (!span) return;
        const domains = APP.BUILTIN_DO_NOT_CHECK_DOMAINS || [];
        span.innerHTML = domains.map((d, i) => {
            const comma = i < domains.length - 1 ? ", " : ".";
            return `<span class="mono">${d}</span>${comma}`;
        }).join("");
    }

    // v3.3.0 (3P Matrix alignment item 25) — render the "Trust AI downloads"
    // category's domain list the same way renderBuiltinDomains() does, from
    // the single source of truth (APP.AI_DOWNLOAD_DOMAINS) rather than
    // duplicating the list in HTML.
    function renderAiDownloadDomains() {
        const span = document.getElementById("aiDownloadDomains");
        if (!span) return;
        const domains = APP.AI_DOWNLOAD_DOMAINS || [];
        span.textContent = domains.join(", ");
    }

    function loadTrustAiDownloads(settings) {
        const checkbox = document.getElementById("trustAiDownloadsCheckbox");
        if (checkbox) checkbox.checked = !!settings.trustAiDownloads;
    }

    function buildDomainInputs() {
        renderBuiltinDomains();
        renderAiDownloadDomains();
        const container = document.getElementById("domainInputs");
        if (!container) return;
        // APP.DOMAIN_WHITELIST_MAX is the single source of truth for the limit
        for (let i = 0; i < APP.DOMAIN_WHITELIST_MAX; i++) {
            const inp = document.createElement("input");
            inp.type         = "text";
            inp.className    = "domain-input";
            inp.id           = "domain_" + i;
            inp.placeholder  = "e.g. example.com";
            inp.spellcheck   = false;
            inp.autocomplete = "off";
            inp.addEventListener("input", () => validateDomainInput(inp));
            container.appendChild(inp);
        }
    }

    function validateDomainInput(inp) {
        const val = inp.value.trim();
        if      (val === "")          inp.className = "domain-input";
        else if (isValidDomain(val))  inp.className = "domain-input valid";
        else                          inp.className = "domain-input invalid";
    }

    function loadDomainFields(settings) {
        const domains = Array.isArray(settings.customDomains) ? settings.customDomains : [];
        for (let i = 0; i < APP.DOMAIN_WHITELIST_MAX; i++) {
            const inp = document.getElementById("domain_" + i);
            if (inp) inp.value = domains[i] || "";
        }
    }

    // ── DNS threat-intel checks (choose 2 of 5, v3.0.6; DNS4EU + CleanBrowsing v3.3.1) ───────────────────────

    function buildDnsSelects() {
        for (const id of ["dnsFirst", "dnsSecond"]) {
            const sel = document.getElementById(id);
            if (!sel) continue;
            sel.replaceChildren(...DNS_SELECT_OPTIONS.map(opt => {
                const o = document.createElement("option");
                o.value       = opt.id;
                o.textContent = opt.text;
                return o;
            }));
        }
    }

    function loadDnsFields(settings) {
        const first  = document.getElementById("dnsFirst");
        const second = document.getElementById("dnsSecond");
        if (first)  first.value  = settings.dnsFirst  ?? DnsDefaults.get().first;
        if (second) second.value = settings.dnsSecond ?? DnsDefaults.get().second;
        warnIfPermissionMissing();
    }

    // v3.3.1 — a selected optional-permission provider (DNS4EU) whose grant
    // was revoked (e.g. via chrome://extensions) can't be checked; say so
    // here rather than only on the warning page.
    function warnIfPermissionMissing() {
        const ids = ["dnsFirst", "dnsSecond"].map(id => document.getElementById(id)?.value);
        Promise.all(ids.map(id => DnsPermissions.has(id))).then(granted => {
            const missing = ids.filter((id, i) => !granted[i]).map(id => APP.DNS_PROVIDERS[id].label);
            if (missing.length) {
                setMsg("dnsStatus", `${missing.join(", ")}: permission not granted — select it again to allow.`, "error");
            }
        });
    }

    // Never ask the same resolver twice — if the user picks the same
    // provider for both slots, the second one is cleared to "None" so it's
    // obvious nothing extra is actually being checked.
    //
    // v3.3.0 (3P Matrix alignment item 28) — these two dropdowns now save
    // immediately on change, not just via the big "Save All" button below:
    // a quick, standalone choice like "which DNS check" shouldn't be lost
    // if the user navigates away before remembering to hit Save All.
    function bindDnsSelects() {
        const first  = document.getElementById("dnsFirst");
        const second = document.getElementById("dnsSecond");
        if (!first || !second) return;

        // Last saved value per slot, so a declined permission prompt can
        // put the dropdown back instead of saving a provider we can't query.
        const previous = { dnsFirst: first.value, dnsSecond: second.value };

        // v3.3.1 — selecting an optional-permission provider (DNS4EU) asks
        // for its host permission first. DnsPermissions.request() is called
        // synchronously in the change handler so the user gesture is still
        // active; non-optional providers resolve to true immediately.
        function onDnsChange(event) {
            const sel       = event.target;
            const requested = sel.value; // captured before a possible revert below
            DnsPermissions.request(requested).then(granted => {
                if (!granted) {
                    sel.value = previous[sel.id];
                    setMsg("dnsStatus", `${APP.DNS_PROVIDERS[requested]?.label ?? "This DNS check"} not selected — permission was not granted.`, "error");
                    return;
                }
                saveAndConfirm();
            });
        }

        function saveAndConfirm() {
            let deduped = false;
            if (second.value !== APP.DNS_NONE && second.value === first.value) {
                second.value = APP.DNS_NONE;
                deduped = true;
            }
            Settings.set({ dnsFirst: first.value, dnsSecond: second.value }, () => {
                if (chrome.runtime.lastError) {
                    setMsg("dnsStatus", "Save failed — storage error.", "error");
                    return;
                }
                setMsg("dnsStatus",
                    deduped ? "Second check cleared — it was the same as the first. Saved." : "Saved.",
                    "success");
                setTimeout(() => setMsg("dnsStatus", "", ""), 2000);
                previous.dnsFirst  = first.value;
                previous.dnsSecond = second.value;
                // Release: drop optional permissions no slot uses any more.
                DnsPermissions.releaseUnused([first.value, second.value]);
                notifyBackground();
            });
        }
        first.addEventListener("change", onDnsChange);
        second.addEventListener("change", onDnsChange);
    }

    // ── False positive reduction ──────────────────────────────────────────────

    const FP_LEVELS = ["HIGH", "MEDIUM", "LOW", "NONE"];

    const FP_HINTS = [
        "Use only antivirus engines known for very low false positive rates.",
        "Use antivirus engines known for low false positive rates and early detection.",
        "Use well-known antivirus engines from the B2B and consumer market.",
        "Use all engines listed at VirusTotal — unfiltered."
    ];

    function setActiveFpLabel(idx) {
        const labels = document.querySelectorAll("#fpGridLabels span");
        labels.forEach(s => s.classList.remove("active"));
        if (labels[idx]) labels[idx].classList.add("active");
        const hint = document.getElementById("fpModeHint");
        // v3.5.2: + from which score a download gets a warning window at this level (shared WarnPolicy text)
        if (hint) hint.textContent = `${FP_HINTS[idx] ?? ""} ${WarnPolicy.windowHint(FP_LEVELS[idx])}`.trim();
    }

    function loadFpSlider(settings) {
        const level  = settings.fpReductionLevel || "MEDIUM";
        const idx    = FP_LEVELS.indexOf(level);
        const slider = document.getElementById("fpSlider");
        if (slider) slider.value = idx >= 0 ? idx : 1;
        setActiveFpLabel(idx >= 0 ? idx : 1);
    }

    function bindFpSlider() {
        const slider = document.getElementById("fpSlider");
        if (!slider) return;
        slider.addEventListener("input", () => {
            setActiveFpLabel(parseInt(slider.value, 10));
        });
    }


    // ── Silent when inconclusive (v3.5.3, off by default) ───────────────────

    function loadSilentWhenInconclusive(settings) {
        const toggle = document.getElementById("silentWhenInconclusiveToggle");
        if (!toggle) return;
        toggle.checked = !!settings.silentWhenInconclusive;
    }

    // ── Auto-allow ────────────────────────────────────────────────────────────

    function loadAutoAllow(settings) {
        const toggle    = document.getElementById("autoAllowToggle");
        const threshold = document.getElementById("autoAllowThreshold");
        const row       = document.getElementById("autoAllowThresholdRow");
        if (!toggle) return;
        toggle.checked    = !!settings.autoAllow;
        threshold.value   = settings.autoAllowThreshold ?? APP.AUTO_ALLOW_THRESHOLD_DEFAULT;
        row.style.display = settings.autoAllow ? "" : "none";
    }

    function bindAutoAllow() {
        const toggle = document.getElementById("autoAllowToggle");
        const row    = document.getElementById("autoAllowThresholdRow");
        if (!toggle) return;
        toggle.addEventListener("change", () => {
            row.style.display = toggle.checked ? "" : "none";
        });
    }

    // ── Personalize section expand/collapse ──────────────────────────────────

    function bindPersonalize() {
        const checkbox = document.getElementById("personalizeCheckbox");
        const content  = document.getElementById("personalizeContent");
        if (!checkbox || !content) return;
        checkbox.addEventListener("change", () => {
            content.style.display = checkbox.checked ? "" : "none";
            // Unchecking Personalize must visibly reset the fields too —
            // otherwise the hidden inputs still hold the old customized
            // values and bindSaveAll() would have nothing to distinguish
            // "never customized" from "customized, then turned off".
            if (!checkbox.checked) resetPersonalizeFieldsToDefault();
        });
    }

    function loadPersonalize(settings) {
        const checkbox = document.getElementById("personalizeCheckbox");
        const content  = document.getElementById("personalizeContent");
        if (!checkbox || !content) return;

        // Use APP constants so the comparison is always against the live default
        const hasCustom = (
            settings.warningColorR !== APP.WARNING_COLOR_DEFAULT_R ||
            settings.warningColorG !== APP.WARNING_COLOR_DEFAULT_G ||
            settings.warningColorB !== APP.WARNING_COLOR_DEFAULT_B ||
            ((settings.warningTitle || "").trim() !== "" &&
              settings.warningTitle !== APP.WARNING_TITLE_DEFAULT)
        );
        checkbox.checked      = hasCustom;
        content.style.display = hasCustom ? "" : "none";
    }

    // ── Single Save All button ────────────────────────────────────────────────

    function bindSaveAll() {
        const btn = document.getElementById("saveAllBtn");
        if (!btn) return;
        btn.addEventListener("click", () => {

            // Collect FP level
            const slider  = document.getElementById("fpSlider");
            const fpLevel = FP_LEVELS[parseInt(slider?.value ?? 1, 10)] || "MEDIUM";

            // Guard: Personalize section — if the user has unchecked it, the
            // warning color and title MUST be cleared back to defaults on
            // save, regardless of whatever is still sitting in the (hidden)
            // input fields. This is what makes unchecking Personalize
            // actually take effect instead of silently re-saving stale
            // customized values.
            const personalizeOn = document.getElementById("personalizeCheckbox")?.checked ?? false;

            // Collect colors
            const r = personalizeOn
                ? clamp(document.getElementById("colorR")?.value ?? APP.WARNING_COLOR_DEFAULT_R)
                : APP.WARNING_COLOR_DEFAULT_R;
            const g = personalizeOn
                ? clamp(document.getElementById("colorG")?.value ?? APP.WARNING_COLOR_DEFAULT_G)
                : APP.WARNING_COLOR_DEFAULT_G;
            const b = personalizeOn
                ? clamp(document.getElementById("colorB")?.value ?? APP.WARNING_COLOR_DEFAULT_B)
                : APP.WARNING_COLOR_DEFAULT_B;

            // Collect title
            const title = personalizeOn
                ? (document.getElementById("warningTitleInput")?.value || "").trim()
                : "";

            // Collect domains — validate first
            const domains  = [];
            let   hasError = false;
            for (let i = 0; i < APP.DOMAIN_WHITELIST_MAX; i++) {
                const inp = document.getElementById("domain_" + i);
                const val = inp ? inp.value.trim() : "";
                if (val !== "") {
                    if (!isValidDomain(val)) {
                        hasError = true;
                        if (inp) inp.className = "domain-input invalid";
                    } else {
                        domains.push(val);
                    }
                }
            }

            if (hasError) {
                setMsg("saveAllMsg", "Fix invalid domains before saving (format: domain.tld).", "error");
                return;
            }

            // Collect DNS threat-intel choices — guard against a stray/
            // invalid select value (should never happen, options are built
            // from DNS_SELECT_OPTIONS, but settings are data, not trusted
            // input) and re-apply the "never ask the same resolver twice"
            // dedupe here too, not just on change.
            const dnsIds   = new Set(DNS_SELECT_OPTIONS.map(o => o.id));
            let   dnsFirst  = document.getElementById("dnsFirst")?.value;
            let   dnsSecond = document.getElementById("dnsSecond")?.value;
            if (!dnsIds.has(dnsFirst))  dnsFirst  = DnsDefaults.get().first;
            if (!dnsIds.has(dnsSecond)) dnsSecond = DnsDefaults.get().second;
            if (dnsSecond !== APP.DNS_NONE && dnsSecond === dnsFirst) dnsSecond = APP.DNS_NONE;

            // v3.5.3 (user request) — "Silent when inconclusive", off by default
            const silentWhenInconclusive = document.getElementById("silentWhenInconclusiveToggle")?.checked ?? false;

            // Collect auto-allow — clamp to APP-defined bounds
            const autoAllow = document.getElementById("autoAllowToggle")?.checked ?? false;
            const autoAllowThreshold = Math.max(
                APP.AUTO_ALLOW_THRESHOLD_MIN,
                Math.min(
                    APP.AUTO_ALLOW_THRESHOLD_MAX,
                    parseInt(document.getElementById("autoAllowThreshold")?.value ?? APP.AUTO_ALLOW_THRESHOLD_DEFAULT, 10)
                    || APP.AUTO_ALLOW_THRESHOLD_DEFAULT
                )
            );

            // v3.3.0 (item 25) — "Trust AI downloads" opt-in checkbox
            const trustAiDownloads = document.getElementById("trustAiDownloadsCheckbox")?.checked ?? false;

            Settings.set({
                fpReductionLevel: fpLevel,
                warningColorR: r, warningColorG: g, warningColorB: b,
                warningTitle: title,
                customDomains: domains,
                trustAiDownloads,
                silentWhenInconclusive,
                autoAllow,
                autoAllowThreshold,
                dnsFirst,
                dnsSecond
            }, () => {
                if (chrome.runtime.lastError) {
                    setMsg("saveAllMsg", "Save failed — storage error.", "error");
                    return;
                }
                setMsg("saveAllMsg", "All settings saved!", "success");
                setTimeout(() => setMsg("saveAllMsg", "", ""), 2000);
                notifyBackground();
            });
        });
    }

    // ── Init ───────────────────────────────────────────────────────────────────

    function initialize() {
        buildDomainInputs();
        buildDnsSelects();
        bindApiKey();
        bindFpSlider();
        bindColorSection();
        bindAutoAllow();
        bindPersonalize();
        bindDnsSelects();
        bindSaveAll();

        Settings.get(settings => {
            applyBannerState(settings);
            loadApiKeyField(settings);
            loadFpSlider(settings);
            loadColorFields(settings);
            loadTitleField(settings);
            loadSilentWhenInconclusive(settings);
            loadAutoAllow(settings);
            loadPersonalize(settings);
            loadDomainFields(settings);
            loadTrustAiDownloads(settings);
            loadDnsFields(settings);
            unlockSections();
        });
    }

    return { initialize };
})();

document.addEventListener("DOMContentLoaded", () => {
    window.SentinelOptions.initialize();
});
