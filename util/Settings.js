"use strict";

// ── Settings.js ───────────────────────────────────────────────────────────────
// Manages user preferences: merge-with-defaults, read, and write.
//
// Public interface:
//   Settings.get(callback)              — read merged settings (defaults + stored)
//   Settings.set(newSettings, callback) — write partial update (merged with stored)
//
// State owned:
//   defaultSettings  {Object}  — stateless template; never mutated at runtime.
//
// NOTE: Do not add settings keys without also adding them to the options UI
// and verifying backward-compatible defaults (audit item B9).
// ─────────────────────────────────────────────────────────────────────────────

import { Storage } from "./Storage.js";
import { APP } from "./AppConstants.js";
import { DnsDefaults } from "./DnsDefaults.js";

export const Settings = (function () {

    // ── Storage key ───────────────────────────────────────────────────────────
    // Must not be renamed — it is a stored-data contract with existing users.
    const SETTINGS_KEY = "Settings";

    // ── Default settings ──────────────────────────────────────────────────────
    // Every key must have a sensible default that works correctly on first
    // install and after extension updates (backward-compatible defaults).
    const defaultSettings = {
        // Master on/off switch for the extension
        extensionEnabled: true,

        // Whether VT URL check is active (requires API key)
        virusTotalEnabled: true,

        // VirusTotal API key entered by the user
        vtApiKey: "",

        // Whether the user has provided a VT API key
        isVtApiKeySet: false,

        // v3.5.3 (user request): splits the FP-reduction staged threshold (WarnPolicy, v3.5.2) out
        // from "Silent when probably safe" below — OFF by default (user decision): every monitored
        // download that is not auto-allowed below and has no exception gets a warning window,
        // whatever its score (pre-v3.5.2 behaviour), until the user explicitly ticks this on. A
        // brand new key with a sensible default — no migration needed.
        silentWhenInconclusive: false,

        // Auto-allow when combined score exceeds threshold
        autoAllow: false,
        autoAllowThreshold: APP.AUTO_ALLOW_THRESHOLD_DEFAULT,

        // Custom warning background color — single source of truth via APP
        // constants (default: Google Red)
        warningColorR: APP.WARNING_COLOR_DEFAULT_R,
        warningColorG: APP.WARNING_COLOR_DEFAULT_G,
        warningColorB: APP.WARNING_COLOR_DEFAULT_B,

        // Custom warning window title — single source of truth via APP constant
        warningTitle: APP.WARNING_TITLE_DEFAULT,

        // Custom whitelist domains (up to APP.DOMAIN_WHITELIST_MAX).
        // sharepoint.com is provided as a first example — org-controlled
        // content hosting that was previously in the built-in whitelist.
        // Users can remove it if they do not use SharePoint.
        customDomains: ["sharepoint.com"],

        // v3.3.0 (3P Matrix alignment item 25) — opt-in "Trust AI downloads"
        // category (OptionsPage.js checkbox): skips checks for
        // APP.AI_DOWNLOAD_DOMAINS (claude.ai, chatgpt.com, …). Off by
        // default — unlike APP.BUILTIN_DO_NOT_CHECK_DOMAINS, these sites
        // are not curated/reviewed app stores, so trusting them is the
        // user's own choice, not a built-in default.
        trustAiDownloads: false,

        // False positive reduction level: "NONE" | "LOW" | "MEDIUM" | "HIGH"
        fpReductionLevel: "MEDIUM",

        // DNS threat-intel checks (v3.0.6) — which 2 of the providers in
        // APP.DNS_PROVIDERS to query (or APP.DNS_NONE to disable a slot).
        // Raw values are still re-validated defensively wherever they're
        // read (background.js's validDnsProviderId()) — never trust stored
        // data blindly, even though this merge-with-defaults already covers
        // the common case of nothing stored yet.
        // v3.3.1 — defaults are region-aware (DnsDefaults: Control D +
        // Cloudflare in France, Quad9 + Control D elsewhere). Applies only
        // while nothing is stored for these keys.
        dnsFirst:  DnsDefaults.get().first,
        dnsSecond: DnsDefaults.get().second,

        // v3.0.7 — the startup "Get a free VirusTotal API Key" nudge popup
        // (pages/vtkeyprompt/). Set true only when the user explicitly ticks
        // "I understand, don't show this warning again" — pressing Ignore
        // alone leaves this false, so the nudge returns on the next browser
        // start. Already-having a VT key is a SEPARATE, independent reason
        // the nudge won't show (see background.js's shouldShowVtKeyPrompt())
        // — this flag only covers the explicit opt-out.
        vtKeyPromptDismissed: false,

        // v3.3.0 (item 13) — schema version of this settings object, so a
        // future stored-shape change can tell "old data, needs migrating"
        // from "nothing stored yet". Always equals SETTINGS_SCHEMA_VERSION
        // in the defaults template; the only place a DIFFERENT (older, or
        // missing/undefined) value can appear is stored data from a past
        // install, which runMigrations() below brings up to date first.
        schemaVersion: 1,
    };

    // ── Schema migration ──────────────────────────────────────────────────────
    // Single source of truth for both the current version number and the
    // ordered list of migrations needed to reach it. Bump
    // SETTINGS_SCHEMA_VERSION and append one MIGRATIONS entry whenever a
    // future release changes the *shape* of stored settings (renaming,
    // restructuring, or repurposing a key) in a way `updateIfChanged`'s
    // flat merge-with-defaults can't handle safely on its own — a brand
    // new key with a sensible default does NOT need a migration entry.
    //
    // Each entry's `toVersion` is the version it migrates INTO; migrations
    // run in array order, each applied only when the settings object is
    // still below that version, so upgrading from any older version always
    // replays the full remaining chain.
    const SETTINGS_SCHEMA_VERSION = 1;
    const MIGRATIONS = [
        // No migrations yet — v1 is the first version this field was
        // introduced at, so there is nothing to migrate FROM. Add entries
        // here as: { toVersion: 2, migrate(settings) { ...mutate in place... } }
    ];

    // ── Private helpers ───────────────────────────────────────────────────────

    // Apply fields from source into target; returns true if anything changed.
    function updateIfChanged(target, source) {
        let hasChanges = false;
        if (source) {
            for (const key in source) {
                if (source[key] !== target[key]) {
                    target[key] = source[key];
                    hasChanges = true;
                }
            }
        }
        return hasChanges;
    }

    // Bring a stored settings object up to SETTINGS_SCHEMA_VERSION in place,
    // replaying only the migrations it hasn't already passed through.
    // No-op (and safe to call) on settings that are already current, or on
    // null/undefined (nothing stored yet — defaultSettings already starts
    // at the current version).
    function runMigrations(storedSettings) {
        if (!storedSettings) return storedSettings;
        let version = storedSettings.schemaVersion || 0; // missing = pre-schema-versioning data
        for (const migration of MIGRATIONS) {
            if (version < migration.toVersion) {
                migration.migrate(storedSettings);
                version = migration.toVersion;
            }
        }
        storedSettings.schemaVersion = SETTINGS_SCHEMA_VERSION;
        return storedSettings;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    return {

        get: function get(callback) {
            Storage.getFromLocalStore(SETTINGS_KEY, function (storedSettings) {
                const merged = JSON.parse(JSON.stringify(defaultSettings));
                updateIfChanged(merged, runMigrations(storedSettings));
                if (callback) callback(merged);
            });
        },

        set: function set(newSettings, callback) {
            Storage.getFromLocalStore(SETTINGS_KEY, function (storedSettings) {
                const merged = JSON.parse(JSON.stringify(defaultSettings));
                if (storedSettings) updateIfChanged(merged, runMigrations(storedSettings));
                updateIfChanged(merged, newSettings);
                Storage.setToLocalStore(SETTINGS_KEY, merged, callback);
            });
        }
    };
})();
