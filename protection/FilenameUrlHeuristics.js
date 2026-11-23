"use strict";

// ── FilenameUrlHeuristics.js ──────────────────────────────────────────────────
// Heuristics plan "Later steps" (v2.11.0 — Step 5, "Smaller filename and URL
// heuristics"). Three small, independent, pure signals that didn't warrant
// their own module each:
//
//   checkRlo(filename, url)
//       — right-to-left/bidi override characters (U+202A-U+202E,
//         U+2066-U+2069) in the filename or URL — the classic "gpj.exe"
//         (reversed to display as "exe.jpg") disguise trick. Almost never
//         legitimate.
//
//   checkPaddedDoubleExtension(filename)
//       — a decoy extension-like segment followed by an abnormally long run
//         of padding characters (space/dot/underscore/hyphen/zero-width),
//         then a dangerous final extension, e.g.
//         "Invoice_PDF____________________.exe". Distinct from
//         FilenameAnalysis.getDoubleExtension() (DS-H003), which only
//         handles dot-separated decoy segments with no padding between
//         them — this catches the padding variant specifically.
//
//   checkUrlShortener(hostname)
//       — a known URL-shortener domain (util/UrlShorteners.js). A much
//         weaker/more ambiguous signal than the other four — shorteners are
//         extremely common for entirely legitimate use — so this is scored
//         mildly and is purely informational/contextual.
//
//   checkReferrerMismatch(referrer, finalUrl)
//       — the download's HTTP referrer resolves to a different, unrelated
//         origin than the download host itself. Conservative and
//         low-confidence by design (see SCORING_CONFIG.REFERRER_MISMATCH_
//         SCORE's comment in ScoringEngineV2.js for why, and this file's
//         header for the sub-feature that was DROPPED rather than forced
//         in unreliable — comparing against the initiating TAB's origin,
//         which would need the chrome.tabs permission this extension does
//         not request).
//
// DROPPED SUB-FEATURE — tab-origin comparison:
//   The spec for this step asked for the download's referrer to be compared
//   against "the initiating tab's origin" when chrome.tabs access is
//   available. It is not: manifest.json requests only
//   ["downloads", "storage", "alarms"] — no "tabs" permission — and nothing
//   elsewhere in this codebase ever calls chrome.tabs.*. Requesting that
//   permission purely to strengthen one already-low-confidence,
//   easily-dropped signal was judged not worth widening the extension's
//   permission footprint (a user-visible, review-relevant change for a
//   Chrome extension). checkReferrerMismatch() below uses only
//   chrome.downloads.DownloadItem.referrer (already available with the
//   existing "downloads" permission) against the download's own resulting
//   host — still a real, if weaker, signal — and degrades to a no-op (null)
//   whenever referrer or the final host is missing, exactly as specified.
//
// v3.2.0 (3P Matrix alignment §1): checkBrandHomoglyph() and
// checkLookalikeTopSite() — the two character-substitution typosquat checks
// that used to live here — are REMOVED. They're replaced by one unified
// check, protection/LookalikeDomainCheck.js, which folds in SketchyUrlCheck's
// former generic digit-substitution check too (three overlapping checks that
// grew separately -> one). See that module's header for the full design.
// toRegisteredDomain() below is kept — still used by checkReferrerMismatch().
//
// Dependencies: UrlUtils (getRegisteredDomain — pure string logic, no
// chrome.* access) and the shortener data module.
//
// State owned: none — CONFIG, BIDI_CONTROL_RE and PADDING_RE are built once
// and frozen at module load (B3a/B8 — stateless constants), same convention
// as StagingCheck.js/CombinationScoring.js.
// ─────────────────────────────────────────────────────────────────────────────

import { UrlUtils } from "../util/UrlUtils.js";
import { UrlShorteners } from "../util/UrlShorteners.js";
import { DangerousExts } from "../util/DangerousExts.js";
import { DeliveryPatterns } from "../util/DeliveryPatterns.js"; // v3.5.0 — same-company domains (referrer check)

export const FilenameUrlHeuristics = (function () {

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIG — every magic number for this module, gathered here (B1).
    // Host-axis *scores* live in ScoringEngineV2.js's SCORING_CONFIG, same
    // project convention as StagingCheck.js — this block only holds this
    // module's own internal tuning (thresholds, caps).
    // ─────────────────────────────────────────────────────────────────────────
    const CONFIG = Object.freeze({
        MAX_INPUT_LENGTH:     2048, // cap every input field before any regex/scan runs (ReDoS/perf guard)
        PADDING_MIN_LENGTH:      8, // a run of padding chars shorter than this is just an ordinary long filename
        DECOY_TOKEN_MAX_LEN:    10, // the "second extension-like segment" token checked against DECOY_EXTS
    });

    // ── RLO / bidi-override detection ─────────────────────────────────────────
    // U+202A LRE, U+202B RLE, U+202C PDF, U+202D LRO, U+202E RLO (the classic
    // one), U+2066-U+2069 LRI/RLI/FSI/PDI (the newer "isolate" family — same
    // visual-reordering capability). A single bounded character class test —
    // no quantifiers at all, so this is trivially ReDoS-safe regardless of
    // input length.
    const BIDI_CONTROL_RE = /[‪-‮⁦-⁩]/;

    function checkRlo(filename, url) {
        const fname = (filename || "").slice(0, CONFIG.MAX_INPUT_LENGTH);
        if (BIDI_CONTROL_RE.test(fname)) {
            return {
                location: "filename",
                label: "Filename contains a right-to-left/bidi override character — a classic technique for disguising a dangerous extension",
            };
        }

        const rawUrl = (url || "").slice(0, CONFIG.MAX_INPUT_LENGTH);
        if (!rawUrl) return null;

        if (BIDI_CONTROL_RE.test(rawUrl)) {
            return {
                location: "url",
                label: "URL contains a right-to-left/bidi override character — a classic technique for disguising a dangerous extension",
            };
        }

        // One bounded percent-decode pass catches a URL-encoded override
        // character (e.g. %E2%80%AE for U+202E) that would not match the raw
        // text above. try/catch guards a malformed percent sequence.
        let decoded = null;
        try { decoded = decodeURIComponent(rawUrl); } catch { /* malformed — ignore, no signal from this pass */ }
        if (decoded && decoded !== rawUrl && BIDI_CONTROL_RE.test(decoded)) {
            return {
                location: "url",
                label: "URL contains a percent-encoded right-to-left/bidi override character",
            };
        }

        return null;
    }

    // ── Padded double-extension detection ─────────────────────────────────────
    // Distinct from FilenameAnalysis.getDoubleExtension() (DS-H003): that
    // check handles dot-separated decoy segments ("invoice.pdf.exe") with no
    // padding between them; this one handles a decoy segment that is
    // deliberately padded away from the dangerous extension with a long run
    // of whitespace/separator/invisible characters so the real extension is
    // pushed off-screen in a UI that truncates long filenames, e.g.
    // "Invoice_PDF____________________.exe".
    //
    // Padding characters: ordinary ASCII space, dot, underscore, hyphen, plus
    // the same zero-width/invisible set StagingCheck.js already strips
    // (U+200B-U+200D ZERO WIDTH SPACE/NON-JOINER/JOINER, U+2060 WORD JOINER,
    // U+FEFF ZERO WIDTH NO-BREAK SPACE/BOM) and ordinary NBSP (U+00A0).
    //
    // The trailing-padding regex is anchored at the end of string with a
    // single bounded quantifier ({8,}) over a fixed character class — no
    // nesting, no overlapping alternation, so it cannot backtrack
    // catastrophically regardless of input length (and MAX_INPUT_LENGTH caps
    // that length to 2048 regardless).
    const PADDING_CHAR_CLASS = "[ ._\\-\\u00A0\\u200B-\\u200D\\u2060\\uFEFF]";
    const TRAILING_PADDING_RE = new RegExp(`${PADDING_CHAR_CLASS}{${CONFIG.PADDING_MIN_LENGTH},}$`);
    const TOKEN_SPLIT_RE = /[^a-z0-9]+/;

    const DANGEROUS_EXTS = DangerousExts.DANGEROUS.set;
    const DECOY_EXTS      = DangerousExts.DECOY.set;

    function checkPaddedDoubleExtension(filename) {
        if (!filename) return null;
        // Cap from the END, not the start: the decoy token, the padding run
        // and the final extension all live at the tail of the filename, so
        // truncating from the front (like StagingCheck's field cap) would
        // let an attacker evade detection simply by padding past the cap —
        // the opposite of what this check exists to catch.
        const capped = filename.length > CONFIG.MAX_INPUT_LENGTH
            ? filename.slice(-CONFIG.MAX_INPUT_LENGTH) : filename;
        const base   = capped.toLowerCase().split("/").pop().split("\\").pop();

        const lastDot = base.lastIndexOf(".");
        if (lastDot <= 0 || lastDot === base.length - 1) return null; // no final extension, or starts/ends with a dot

        const dangerous = base.slice(lastDot + 1);
        if (!DANGEROUS_EXTS.has(dangerous)) return null;

        const prefix = base.slice(0, lastDot);
        const paddingMatch = prefix.match(TRAILING_PADDING_RE);
        if (!paddingMatch) return null; // no abnormal padding run — not this pattern (plain double-extension check covers the rest)

        const remainder = prefix.slice(0, prefix.length - paddingMatch[0].length);
        if (!remainder) return null;

        const tokens   = remainder.split(TOKEN_SPLIT_RE).filter(Boolean);
        const lastToken = tokens[tokens.length - 1];
        if (!lastToken || lastToken.length > CONFIG.DECOY_TOKEN_MAX_LEN) return null;
        if (!DECOY_EXTS.has(lastToken)) return null; // no recognisable decoy token before the padding

        return {
            decoy:         lastToken,
            dangerous,
            paddingLength: paddingMatch[0].length,
        };
    }

    // Shared by checkReferrerMismatch() below — "lowercase + DNS-length-cap
    // the hostname, then resolve its registrable domain". Was also shared by
    // the now-removed checkBrandHomoglyph()/checkLookalikeTopSite() (see
    // this file's header) — kept here since it's still useful, generic
    // hostname-normalisation logic.
    function toRegisteredDomain(hostname) {
        if (!hostname) return null;
        const host = hostname.toLowerCase().slice(0, 253); // cap at max valid DNS hostname length
        return UrlUtils.getRegisteredDomain(host);
    }

    // ── URL shortener detection ────────────────────────────────────────────────
    // Weak/contextual only — see this file's header and
    // SCORING_CONFIG.URL_SHORTENER_SCORE for why.
    function checkUrlShortener(hostname) {
        if (!hostname) return null;
        const host = hostname.toLowerCase();
        if (UrlShorteners.set.has(host)) return { matchedShortener: host };

        const registered = UrlUtils.getRegisteredDomain(host);
        if (registered && UrlShorteners.set.has(registered)) return { matchedShortener: registered };

        return null;
    }

    // ── Referrer / download-host mismatch detection ───────────────────────────
    // See this file's header for the tab-origin sub-feature that was
    // dropped and why. Defensive by construction: any missing/unparsable/
    // non-http(s) input degrades to null (neutral — no penalty), never
    // throws.
    function checkReferrerMismatch(referrer, finalUrl) {
        if (!referrer || !finalUrl) return null;

        let referrerParsed, finalParsed;
        try { referrerParsed = new URL(referrer); } catch { return null; }
        try { finalParsed    = new URL(finalUrl); } catch { return null; }

        if (referrerParsed.protocol !== "http:" && referrerParsed.protocol !== "https:") return null;
        if (!referrerParsed.hostname || !finalParsed.hostname) return null;

        const referrerHost = referrerParsed.hostname.toLowerCase();
        const finalHost     = finalParsed.hostname.toLowerCase();
        if (referrerHost === finalHost) return null; // same host — no signal

        // Same registered domain (referrer on a subdomain of the download
        // host, or vice versa) is normal and extremely common — not a
        // mismatch worth reporting.
        const referrerRegistered = UrlUtils.getRegisteredDomain(referrerHost);
        const finalRegistered    = UrlUtils.getRegisteredDomain(finalHost);
        if (referrerRegistered && finalRegistered && referrerRegistered === finalRegistered) return null;

        // v3.5.0 — different registered domains of ONE company (discord.com →
        // cdn.discordapp.com, github.com → objects.githubusercontent.com) are
        // related too; util/DeliveryPatterns.js SAME_COMPANY says which. This
        // only states a relation — what is hosted there is scored separately.
        if (DeliveryPatterns.sameCompany(referrerHost, finalHost)) return null;

        return { referrerHost, finalHost };
    }

    return {
        checkRlo,
        checkPaddedDoubleExtension,
        checkUrlShortener,
        checkReferrerMismatch,
        toRegisteredDomain,
        CONFIG,
    };

})();
