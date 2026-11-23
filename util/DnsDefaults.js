"use strict";

// ── DnsDefaults.js ────────────────────────────────────────────────────────────
// v3.3.1 — resolves THIS user's first-install DNS threat-intel defaults
// (first/second check) from APP.DNS_REGION_DEFAULTS, falling back to the
// global APP.DEFAULT_DNS_FIRST / APP.DEFAULT_DNS_SECOND.
//
// Public interface:
//   DnsDefaults.get()                     — { first, second, region } for this
//                                           browser (cached after first call)
//   DnsDefaults.resolveForTimeZone(tz)    — same, for an explicit IANA zone
//                                           (pure; used by tests)
//   DnsDefaults.reset()                   — clear the cache (tests / re-detect)
//
// State owned:
//   cachedDefaults {Object|null} — frozen result of get(); null until first
//                                  use and after reset().
//
// Region detection is offline (Intl time zone): no network request and no
// extra permission. Every failure path (Intl missing/throwing, unknown zone,
// a rule naming a provider id that no longer exists) lands on the global
// defaults — this module never throws and never returns an unknown id.
// ─────────────────────────────────────────────────────────────────────────────

import { APP } from "./AppConstants.js";

export const DnsDefaults = (function () {

    // Region label reported when no APP.DNS_REGION_DEFAULTS rule matched.
    const GLOBAL_REGION = "GLOBAL";

    let cachedDefaults = null;

    // ── Private helpers ───────────────────────────────────────────────────────

    function isKnownProvider(id) {
        return typeof id === "string" && Object.hasOwn(APP.DNS_PROVIDERS, id);
    }

    function globalDefaults() {
        return Object.freeze({ first: APP.DEFAULT_DNS_FIRST, second: APP.DEFAULT_DNS_SECOND, region: GLOBAL_REGION });
    }

    // Guard: Intl may be absent or throw in exotic contexts — treat as "unknown".
    function detectTimeZone() {
        try {
            return Intl.DateTimeFormat().resolvedOptions().timeZone || "";
        } catch {
            return "";
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    function resolveForTimeZone(timeZone) {
        if (typeof timeZone !== "string" || timeZone === "") return globalDefaults();
        for (const rule of APP.DNS_REGION_DEFAULTS) {
            if (!rule.timeZones.includes(timeZone)) continue;
            // Guard: a rule pointing at a removed/renamed provider is ignored
            // rather than handing callers an id DnsThreatProtection can't use.
            if (!isKnownProvider(rule.first) || !isKnownProvider(rule.second)) continue;
            // Guard: a default must work without a permission prompt.
            if (APP.DNS_PROVIDERS[rule.first].optionalPermission || APP.DNS_PROVIDERS[rule.second].optionalPermission) continue;
            return Object.freeze({ first: rule.first, second: rule.second, region: rule.region });
        }
        return globalDefaults();
    }

    function get() {
        if (!cachedDefaults) cachedDefaults = resolveForTimeZone(detectTimeZone());
        return cachedDefaults;
    }

    function reset() {
        cachedDefaults = null;
    }

    return { get, resolveForTimeZone, reset, GLOBAL_REGION };
})();
