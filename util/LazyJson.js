"use strict";

/**
 * LazyJson.js — shared first-use loader for the precompiled list modules (v3.5.5, ported from 3P Matrix
 * 4.5.4, perf P4 — byte-identical logic in both projects).
 *
 * Every util/<Name>.default.js list ships its data as ONE JSON string (written by
 * tools/gen-data-defaults.mjs). A string literal costs almost nothing when the service worker evaluates its
 * static imports at every start; the data is parsed only when a lookup first needs it.
 *
 *   lazyJson(text) → get()   get() parses `text` once and returns the same parsed value afterwards
 *
 * Init/clear/release: the parsed value is created on first get(), kept for the life of the service
 * worker (the source string is part of the module anyway), and released with it. A wrapper's
 * resetToDefault() drops ITS OWN derived structures and goes back to get() — the default itself is
 * never mutated by any wrapper, so sharing one parsed copy is safe.
 */
export function lazyJson(text) {
    let value;
    let parsed = false;
    return function get() {
        if (!parsed) {
            value = JSON.parse(text);
            parsed = true;
        }
        return value;
    };
}
