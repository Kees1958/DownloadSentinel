"use strict";

/**
 * ActiveThreatHosts.js — v3.5.4. Hosts seen RIGHT NOW (live threat-intel, not
 * a generic "open platform" rule) serving malware — but ONLY when the URL also
 * looks like the actual delivery pattern of that campaign, not ordinary use of
 * the same host. Ported from 3P Matrix 4.5.1 (data/active-threat-hosts.js +
 * core/download-guard.js applyActiveThreatFloor(); C21: same list, same gates,
 * same floor — not reinvented).
 *
 * Why (3P Matrix 4.4.9 → 4.5.1): since 2026-10-28 GitHub's and GitLab's
 * raw-content/release hosts — and the github.com/gitlab.com redirect origins
 * that resolve to them — are used to distribute malware inside archive /
 * executable files in throwaway repos. URLhaus live feed, 2026-10-29
 * (125,522 entries): raw.githubusercontent.com 45 %, github.com
 * /releases/download/ 32 %, github.com /raw/ 6 %, gitlab.com /-/raw/ 0.6 %,
 * github.com /archive/refs/heads/ 0.07 %, other GitHub CDNs 0.03 % — ~84 % of
 * the feed together. The same hosts serve countless harmless raw .js/.css/.md
 * files and real release binaries, so every entry requires a delivery
 * extension (RISKY_DELIVERY_EXT_RE), and the two redirect-origin hosts (which
 * also serve their whole browsing UI) additionally require a path shape.
 *
 * github.com /archive/refs/heads/<branch>.zip is the link behind GitHub's own
 * "Download ZIP" button — a shape a normal user produces on their own — so it
 * carries a `note` shown on the warning page, but only when it is the SOLE
 * negative signal of the download.
 *
 * Floor, not a CombinationScoring family entry: applied AFTER
 * BrowserProtection.checkHostReputation() returns. An unregistered family
 * degrades to NEUTRAL and is dropped as soon as another signal of a grouped
 * family (RiskyHosting — present for nearly every one of these hosts) is
 * there; the floor cannot be swallowed that way.
 *
 * DownloadSentinel-only module (like Settings.js / QuietLog.js): NOT part of
 * the util/ + protection/ files 3P Matrix vendors as lib/downloadsentinel/,
 * which therefore stay byte-identical. Short-lived by design — review and
 * prune when a campaign dies down; not a permanent blocklist.
 *
 * Public interface:
 *   ActiveThreatHosts.match(host, pathname) → null | { note }
 *   ActiveThreatHosts.applyFloor(hostResult, urls) → hostResult (unchanged
 *       object when no hit; otherwise a NEW object — input never mutated).
 *       `urls` = one URL or a list (final URL first, then the original link —
 *       DS addition over 3P Matrix, which checks the final URL only); the
 *       first URL that matches decides.
 *
 * Pure: no chrome.*, no state — unit-tested in tools/tests/ActiveThreatHosts.test.js.
 */
import { ScoringEngineV2 } from "../protection/ScoringEngineV2.js";

// ── Settings (one place) ─────────────────────────────────────────────────────
const CONFIG = Object.freeze({
    // Floor for a matched delivery. Same value as 3P Matrix SCORE.ACTIVE_THREAT_HOST
    // — keep both in sync. v3.5.5 (3P Matrix 4.5.8, user decision 2026-11-06): −40 → −30,
    // because this list is a dated snapshot, not a live feed. Alone: "Probably Inconclusive"
    // (THRESHOLD_QUESTIONABLE). A floor, not an addend — other signals change the verdict
    // only when they already score below it on their own.
    FLOOR_SCORE: -30,
    SOURCE:      "ActiveThreatHost",       // breakdown entry of the hit itself
    // v3.5.5 (3P Matrix 4.5.8): the engine's "file-sharing platform" row (ScoringEngineV2
    // Check 10) is left out when this floor applies — both describe the same host, and this
    // line is the stronger, more specific one (one fact, one signal). It also removes the
    // contradiction "no other corroborating signal, so halved" right above this line.
    PLATFORM_SOURCE: "RiskyHosting",
    NOTE_SOURCE: "ActiveThreatHostNote",   // breakdown entry of a shape's disclaimer
    NOTE_SCORE:  0,                         // disclaimer: shown, never counted
    HTTP_PROTOCOLS: Object.freeze(["http:", "https:"]),
});

// Archive/executable extensions — the delivery vehicle of a payload, as
// opposed to the source/content files (.js, .css, .json, .md, .png, …) these
// hosts serve constantly and harmlessly. Case-insensitive, end of path.
const RISKY_DELIVERY_EXT_RE = /\.(zip|rar|7z|tar|tgz|gz|exe|msi|bat|cmd|scr|jar|apk|dmg|pkg|iso|ps1|vbs|dll|sys)$/i;

const DOWNLOAD_ZIP_NOTE = "When you pressed the “Download ZIP” button on GitHub, it might be a false alarm.";

// Exact host match, lowercase. `shapes` = ADDITIONAL requirement on top of the
// extension gate, only for hosts that also serve a normal browsing UI.
const ACTIVE_THREAT_HOSTS = Object.freeze([
    Object.freeze({ host: "raw.githubusercontent.com" }),
    Object.freeze({ host: "release-assets.githubusercontent.com" }),
    Object.freeze({ host: "codeload.github.com" }),
    Object.freeze({ host: "objects.githubusercontent.com" }),
    Object.freeze({ host: "media.githubusercontent.com" }),
    Object.freeze({
        host: "github.com",
        shapes: Object.freeze([
            Object.freeze({ pattern: /\/releases\/download\// }),
            Object.freeze({ pattern: /\/raw\// }),
            Object.freeze({ pattern: /\/archive\/refs\/heads\//, note: DOWNLOAD_ZIP_NOTE }),
        ]),
    }),
    Object.freeze({ host: "gitlab.com", shapes: Object.freeze([Object.freeze({ pattern: /\/-\/raw\// })]) }),
]);

const HOST_MAP = new Map(ACTIVE_THREAT_HOSTS.map(e => [e.host, e]));

// Label of the hit — one template (the user sees the actual extension and host).
const hitLabel = (ext, host) => `Currently used to deliver malware as a .${ext} file (${host})`;

// The count + verdict label is rebuilt with ScoringEngineV2.heuristicLabel() — the
// engine's own builder (exported since v3.5.5 / 3P Matrix 4.5.8), so the wording
// cannot drift from the engine's (was a retyped copy here).

// ── Pure helpers ─────────────────────────────────────────────────────────────

// Guard: only a parseable http(s) URL can match; blob:/data:/garbage → null.
function parseHttpUrl(url) {
    try {
        const u = new URL(String(url || ""));
        return CONFIG.HTTP_PROTOCOLS.includes(u.protocol) ? u : null;
    } catch {
        return null;
    }
}

/**
 * @param {string} host      - lowercase hostname
 * @param {string} pathname  - URL path
 * @returns {null | { note: string|null }}
 */
function match(host, pathname) {
    const entry = HOST_MAP.get(String(host || "").toLowerCase());
    if (!entry) return null;
    const path = pathname || "";
    if (!RISKY_DELIVERY_EXT_RE.test(path)) return null;
    if (!entry.shapes) return { note: null };                 // CDN-only host: extension is the gate
    const shape = entry.shapes.find(s => s.pattern.test(path));
    return shape ? { note: shape.note || null } : null;
}

const isCountedNegative = e => e && e.score < 0 && !e.explained;

// First matching URL of the candidates → { u, hit }, or null.
function firstHit(urls) {
    const list = Array.isArray(urls) ? urls : [urls];
    for (const candidate of list) {
        const u = parseHttpUrl(candidate);
        const hit = u && match(u.hostname, u.pathname);
        if (hit) return { u, hit };
    }
    return null;
}

/**
 * Apply the active-threat floor to a BrowserProtection.checkHostReputation()
 * result. Never raises an already-worse score; never touches a hard-rule
 * (e.g. DNS-blocked) verdict text.
 *
 * @param {object|null} hostResult - { score, classification, label, hardRuleApplied, breakdown, … }
 * @param {string|string[]} urls  - final URL, or [final URL, original link]
 * @returns {object} hostResult itself when no hit, else a new object
 */
function applyFloor(hostResult, urls) {
    const found = firstHit(urls);
    if (!found) return hostResult;
    // v3.5.6 — both verdicts (ScoringEngineV2.hostVerdict) get the same floor.
    if (hostResult?.heuristicsOnly) {
        const { heuristicsOnly, ...vtKnown } = hostResult;
        return { ...applyFloor(vtKnown, urls), heuristicsOnly: applyFloor(heuristicsOnly, urls) };
    }
    const { u, hit } = found;

    const prior = (Array.isArray(hostResult?.breakdown) ? hostResult.breakdown : [])
        .filter(e => e?.source !== CONFIG.PLATFORM_SOURCE);          // v3.5.5 — one fact, one signal
    const ext = u.pathname.split(".").pop().toLowerCase();
    const entries = [...prior, { score: CONFIG.FLOOR_SCORE, label: hitLabel(ext, u.hostname), source: CONFIG.SOURCE }];

    // Disclaimer only when nothing else about this download is alarming.
    // `explained: true` = shown on the warning page, never counted (DeliveryContext meaning).
    if (hit.note && !prior.some(isCountedNegative)) {
        entries.push({ score: CONFIG.NOTE_SCORE, label: hit.note, source: CONFIG.NOTE_SOURCE, explained: true });
    }

    const score = Math.min(hostResult?.score ?? 0, CONFIG.FLOOR_SCORE);
    const hardRule = hostResult?.hardRuleApplied ?? null;
    const classification = hardRule
        ? hostResult.classification
        : ScoringEngineV2.classifyByScore(score);
    const label = hardRule
        ? hostResult.label
        : ScoringEngineV2.heuristicLabel(entries.filter(isCountedNegative).length, classification);

    return {
        ...(hostResult || {}),
        score,
        classification,
        label,
        hardRuleApplied: hardRule,
        breakdown: entries.sort((a, b) => a.score - b.score),   // same order as the engine: worst first
    };
}

export const ActiveThreatHosts = Object.freeze({ match, applyFloor, CONFIG, RISKY_DELIVERY_EXT_RE });
