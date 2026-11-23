"use strict";

/**
 * ListSetModule.js — Shared factory for the two extracted data modules whose
 * shape is "a flat list of strings, exposed as both .list and .set"
 * (BrandDomains.js, UrlShorteners.js). Both used to hand-roll an identical
 * IIFE around their own default (jscpd flagged the duplication once the
 * data/ split landed — see CHANGELOG.md's v2.10.0 entry) —
 * this is the single implementation both now call into.
 *
 * Not itself an extracted data module — it has no data and no default of
 * its own. It only exists to remove duplication between modules that share
 * this exact shape (now also PlatformSuffixes.js, RdapCctlds.js,
 * GovSuffixes.js — v3.3.0, 3P Matrix alignment items 1 and 17).
 */
import { lazyJson } from "./LazyJson.js";

// 3P Matrix 4.5.4 (perf P4): takes the module's precompiled JSON string; the list and its Set are built
// on first access (never at service-worker start). resetToDefault() releases them; the next access
// rebuilds from the default.
export function createListSetModule(defaultJson) {
    const defaultList = lazyJson(defaultJson);
    let list = null;    // null = not built yet (or released by resetToDefault)
    let set = null;

    function ensureLoaded() {
        if (list === null) setData(defaultList());
    }

    function setData(newList) {
        list = newList;
        set = new Set(list);
    }

    function resetToDefault() {
        list = null;
        set = null;
    }

    return {
        get list() { ensureLoaded(); return list; },
        get set() { ensureLoaded(); return set; },
        setData,
        resetToDefault,
    };
}
