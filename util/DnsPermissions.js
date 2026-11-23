"use strict";

// ── DnsPermissions.js ─────────────────────────────────────────────────────────
// v3.3.1 — runtime host permission for DNS threat-intel providers that are
// declared in manifest.json's `optional_host_permissions` instead of
// `host_permissions` (APP.DNS_PROVIDERS[id].optionalPermission === true —
// currently only DNS4EU). Keeping a new provider optional means an update
// never pauses the extension for a permission prompt; only a user who picks
// that provider is asked, once.
//
// Public interface:
//   DnsPermissions.needsPermission(id)     — true if `id` is an optional-permission provider
//   DnsPermissions.originFor(id)           — "https://<host>/*" match pattern, or null
//   DnsPermissions.has(id)        → Promise<boolean> — granted (always true for non-optional ids)
//   DnsPermissions.request(id)    → Promise<boolean> — ask the user; MUST be called
//                                   synchronously inside a user gesture (no `await` before it)
//   DnsPermissions.releaseUnused(selectedIds) → Promise<void> — remove optional grants
//                                   for providers no longer selected in any slot
//
// Lifecycle (guard pattern): a permission is ACQUIRED by request() when the
// user selects the provider and RELEASED by releaseUnused() as soon as no
// slot uses it any more — the extension never keeps access it doesn't use.
//
// Every function guards against chrome.permissions being unavailable
// (tests, unusual contexts) and never throws: failure = "not granted".
// ─────────────────────────────────────────────────────────────────────────────

import { APP } from "./AppConstants.js";

export const DnsPermissions = (function () {

    function provider(id) {
        return (typeof id === "string" && Object.hasOwn(APP.DNS_PROVIDERS, id)) ? APP.DNS_PROVIDERS[id] : null;
    }

    function needsPermission(id) {
        return provider(id)?.optionalPermission === true;
    }

    function originFor(id) {
        const p = provider(id);
        return p ? `https://${p.host}/*` : null;
    }

    function permissionsApi() {
        return globalThis.chrome?.permissions ?? null;
    }

    async function has(id) {
        if (!needsPermission(id)) return true;
        const api = permissionsApi();
        if (!api) return false;
        try {
            return await api.contains({ origins: [originFor(id)] });
        } catch {
            return false;
        }
    }

    // No `await` before api.request(): Chrome only shows the prompt while the
    // caller's user gesture is still active.
    function request(id) {
        if (!needsPermission(id)) return Promise.resolve(true);
        const api = permissionsApi();
        if (!api) return Promise.resolve(false);
        try {
            return api.request({ origins: [originFor(id)] }).catch(() => false);
        } catch {
            return Promise.resolve(false);
        }
    }

    async function releaseUnused(selectedIds) {
        const api = permissionsApi();
        if (!api) return;
        const inUse = new Set(Array.isArray(selectedIds) ? selectedIds : []);
        const unused = Object.keys(APP.DNS_PROVIDERS)
            .filter(id => needsPermission(id) && !inUse.has(id))
            .map(originFor);
        if (unused.length === 0) return;
        try {
            await api.remove({ origins: unused });
        } catch {
            // Best effort — an origin that was never granted is not an error worth surfacing.
        }
    }

    return { needsPermission, originFor, has, request, releaseUnused };
})();
