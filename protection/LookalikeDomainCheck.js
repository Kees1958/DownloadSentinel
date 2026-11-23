"use strict";

// ── LookalikeDomainCheck.js ───────────────────────────────────────────────────
// 3P Matrix alignment §1 (v3.2.0) — ONE look-alike/phishing-imitation check,
// replacing three that grew separately and disagreed:
//   - SketchyUrlCheck.js's generic digit-for-letter check (removed)
//   - FilenameUrlHeuristics.checkBrandHomoglyph (removed)
//   - FilenameUrlHeuristics.checkLookalikeTopSite (removed)
// Design and false-positive measurements from the 3P Matrix design session
// (claude/DESIGN_lookalike_check.md) — ported here for DownloadSentinel's
// download-URL host rather than 3P Matrix's opened-site host.
//
// Three tests, each ending the check early when it doesn't apply:
//
//   Test 1 — the host itself is popular -> stop. A registered domain already
//   in the top-sites list (util/TopSitesFilter.js, now the top 100,000 CrUX
//   sites + every Brands.json website + GovSuffixes.json suffix — see
//   tools/build-top-sites-filter.mjs §3) is an original, not an imitation.
//   Critical for downloads specifically: this is what keeps CDN/storage
//   hosts (githubusercontent.com, cloudfront.net, googleapis.com, ...) from
//   ever being flagged as "look-alikes" of themselves.
//
//   Test 2 — no imitation characters -> stop (this check only). Two tiers:
//     "clear": 1->l, 0->o, 5->s, 8->b, only when the digit touches a letter
//       (a digit RUN like "365", "500px", "1688" is not an imitation — see
//       hasClearSubstitution() below for the exact boundary rule, carried
//       over from the removed generic check's V2.4.1 fix) — plus non-Latin
//       look-alike letters inside a punycode (xn--) label, decoded and
//       mapped to their Latin look-alike (decodePunycodeLabel() /
//       CONFUSABLES below).
//     "questionable": rn->m, vv->w, cl->d.
//   No imitation character of either tier anywhere in the name -> stop.
//
//   Test 3 — convert and compare, first hit wins. Up to four variants, in
//   order (duplicates from having 0 or 1 questionable occurrences are
//   skipped automatically since they'd just re-test an identical string):
//     1. all clear substitutions converted
//     2. all clear + the 1st questionable occurrence (left to right)
//     3. all clear + the 2nd questionable occurrence
//     4. all clear + every questionable occurrence
//   Each variant is compared two ways: the WHOLE converted name against the
//   top-sites list (only when it has >= 5 letters — below that, accidental
//   hits dominate, e.g. "rnz"->"mz"), and the variant host's SEPARATE WORDS
//   (split on "." and "-") against the brand list (util/Brands.js) — this
//   is what catches "microsoft-login"/"paypa1-l0gin" style compounds.
//
// Dependencies: util/UrlUtils.js, util/TopSitesFilter.js, util/Brands.js —
// no chrome.* access, pure functions throughout.
// ─────────────────────────────────────────────────────────────────────────────

import { UrlUtils } from "../util/UrlUtils.js";
import { TopSitesFilter } from "../util/TopSitesFilter.js";
import { Brands } from "../util/Brands.js";
import { GovSuffixes } from "../util/GovSuffixes.js";

export const LookalikeDomainCheck = (function () {

    // ── CONFIG — every magic number/table for this module, gathered here ──────
    const CONFIG = Object.freeze({
        // A converted whole-name variant shorter than this is never compared
        // against the top-sites list — measured on CrUX 202609: below 5
        // letters accidental hits dominate (rnz->mz, tcl->td, e1->el); from
        // 5 letters the coincidence rate is 0.0-0.4%, equal for clear and
        // questionable substitution kinds.
        MIN_WHOLE_NAME_LENGTH: 5,
    });

    // "Clear" single-character substitutions — only counted when the digit
    // is directly adjacent to a letter (see hasLetterNeighbor() below), so a
    // pure digit run (365, 500px, 1688 — real popular sites anyway, caught
    // by test 1) is never miscounted as an imitation.
    const CLEAR_SUBSTITUTIONS = Object.freeze({ "1": "l", "0": "o", "5": "s", "8": "b" });

    // "Questionable" bigram substitutions — a visual pair standing in for a
    // single letter. Same three pairs this project has used since the
    // original bigram homoglyph check; see the removed
    // FilenameUrlHeuristics.checkBrandHomoglyph for prior art.
    const QUESTIONABLE_SUBSTITUTIONS = Object.freeze([
        ["rn", "m"],
        ["vv", "w"],
        ["cl", "d"],
    ]);

    // Non-Latin letters visually confusable with a Latin letter, inside a
    // decoded punycode (xn--) label — the small, deliberately conservative
    // set covering the characters actually used in real IDN-homograph
    // phishing kits (Cyrillic primarily, since Cyrillic/Latin share many
    // shapes at the single-letter level). Each of these counts as a "clear"
    // substitution, same tier as the digit map above (a single Latin-shaped
    // swap-in is just as strong a signal as 1->l).
    const CONFUSABLES = Object.freeze({
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", // Cyrillic а е о р с
        "х": "x", "у": "y", "і": "i", "ѕ": "s", "ԁ": "d", // Cyrillic х у і ѕ ԁ
        "α": "a", "ο": "o", "ρ": "p", "υ": "y",           // Greek   α ο ρ υ
    });

    // ── Punycode (RFC 3492) decoder — minimal, decode-only ────────────────────
    // No browser/JS API decodes punycode back to Unicode (the platform only
    // ever goes the other way, Unicode -> punycode, inside the URL parser
    // itself), so a label is decoded by hand here. Bounded by construction
    // (a DNS label is at most 63 octets) — not a general-purpose decoder,
    // just enough of RFC 3492 to recover the Unicode code points for the
    // confusable-letter check above.
    const PUNY_BASE = 36, PUNY_TMIN = 1, PUNY_TMAX = 26, PUNY_SKEW = 38,
          PUNY_DAMP = 700, PUNY_INITIAL_BIAS = 72, PUNY_INITIAL_N = 128;

    function punycodeDigitToValue(code) {
        if (code >= 48 && code <= 57)  return code - 22; // '0'-'9' -> 26-35
        if (code >= 65 && code <= 90)  return code - 65;  // 'A'-'Z' -> 0-25
        if (code >= 97 && code <= 122) return code - 97;  // 'a'-'z' -> 0-25
        return -1;
    }

    function adaptBias(delta, numPoints, firstTime) {
        let d = firstTime ? Math.floor(delta / PUNY_DAMP) : Math.floor(delta / 2);
        d += Math.floor(d / numPoints);
        let k = 0;
        while (d > Math.floor(((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) / 2)) {
            d = Math.floor(d / (PUNY_BASE - PUNY_TMIN));
            k += PUNY_BASE;
        }
        return k + Math.floor(((PUNY_BASE - PUNY_TMIN + 1) * d) / (d + PUNY_SKEW));
    }

    /**
     * Decodes one punycode label's payload (the part after "xn--") into its
     * Unicode code points. Returns null on any malformed input rather than
     * throwing — a decode failure just means this label contributes no
     * confusable-letter signal, never a crash.
     */
    function decodePunycodeLabel(input) {
        const output = [];
        let n = PUNY_INITIAL_N, i = 0, bias = PUNY_INITIAL_BIAS;

        const lastDelim = input.lastIndexOf("-");
        if (lastDelim >= 0) {
            for (let j = 0; j < lastDelim; j++) output.push(input.codePointAt(j));
            input = input.slice(lastDelim + 1);
        }

        let pos = 0;
        while (pos < input.length) {
            const oldi = i;
            let w = 1, k = PUNY_BASE;
            for (;;) {
                if (pos >= input.length) return null; // truncated — malformed
                const digit = punycodeDigitToValue(input.codePointAt(pos));
                pos++;
                if (digit < 0) return null;
                i += digit * w;
                const t = k <= bias ? PUNY_TMIN : (k >= bias + PUNY_TMAX ? PUNY_TMAX : k - bias);
                if (digit < t) break;
                w *= (PUNY_BASE - t);
                k += PUNY_BASE;
                if (w === 0 || i > 0x10FFFF) return null; // overflow guard
            }
            const numPoints = output.length + 1;
            bias = adaptBias(i - oldi, numPoints, oldi === 0);
            n += Math.floor(i / numPoints);
            i %= numPoints;
            output.splice(i, 0, n);
            i++;
            if (n > 0x10FFFF) return null;
        }
        return output.map((cp) => String.fromCodePoint(cp)).join("");
    }

    /**
     * Returns the label with every xn-- punycode segment decoded back to
     * Unicode where possible (left as-is on decode failure — a malformed
     * xn-- label just contributes no confusable signal).
     */
    function decodeHostLabels(name) {
        return name.split(".").map((label) => {
            if (!label.startsWith("xn--")) return label;
            const decoded = decodePunycodeLabel(label.slice(4));
            return decoded === null ? label : decoded;
        }).join(".");
    }

    // ── Test 2 — imitation-character detection ────────────────────────────────

    function hasLetterNeighbor(chars, idx) {
        const prev = idx > 0 ? chars[idx - 1] : null;
        const next = idx < chars.length - 1 ? chars[idx + 1] : null;
        return (prev !== null && /\p{L}/u.test(prev)) || (next !== null && /\p{L}/u.test(next));
    }

    /**
     * Every "clear" imitation-character occurrence in `name` (digit-for-
     * letter touching a letter, or a confusable non-Latin letter), as
     * { index, from, to } — positions index the ORIGINAL string, so test 3
     * can build each variant in one left-to-right pass without positions
     * shifting under it.
     */
    function findClearOccurrences(name) {
        const decoded = decodeHostLabels(name);
        const chars = [...decoded]; // code-point aware (confusables are single code points here)
        const occurrences = [];
        for (let i = 0; i < chars.length; i++) {
            const ch = chars[i];
            if (CLEAR_SUBSTITUTIONS[ch] && /\d/.test(ch)) {
                if (hasLetterNeighbor(chars, i)) {
                    occurrences.push({ index: i, from: ch, to: CLEAR_SUBSTITUTIONS[ch] });
                }
            } else if (CONFUSABLES[ch]) {
                occurrences.push({ index: i, from: ch, to: CONFUSABLES[ch] });
            }
        }
        return { decoded, chars, occurrences };
    }

    /** Every "questionable" bigram occurrence, left to right, non-overlapping. */
    function findQuestionableOccurrences(decoded) {
        const occurrences = [];
        for (const [from, to] of QUESTIONABLE_SUBSTITUTIONS) {
            let searchFrom = 0;
            for (;;) {
                const idx = decoded.indexOf(from, searchFrom);
                if (idx < 0) break;
                occurrences.push({ index: idx, from, to });
                searchFrom = idx + from.length;
            }
        }
        occurrences.sort((a, b) => a.index - b.index);
        return occurrences;
    }

    /**
     * Builds one test-3 variant: every clear occurrence converted, plus the
     * questionable occurrences in `questionableToApply` (a subset of the
     * full occurrence list, by reference). Single left-to-right pass over
     * the decoded string using each occurrence's ORIGINAL index, so
     * overlapping clear/questionable positions never double-consume a
     * character (a questionable bigram's second character is never also a
     * standalone clear-digit position in practice, since CLEAR_SUBSTITUTIONS
     * keys are digits and QUESTIONABLE_SUBSTITUTIONS keys are letter pairs).
     */
    function buildVariant(decoded, clearOccurrences, questionableToApply) {
        const applyAt = new Map(); // index -> {length, to}
        for (const occ of clearOccurrences) applyAt.set(occ.index, { length: [...occ.from].length, to: occ.to });
        for (const occ of questionableToApply) applyAt.set(occ.index, { length: occ.from.length, to: occ.to });

        let out = "";
        let i = 0;
        const chars = [...decoded];
        while (i < chars.length) {
            const sub = applyAt.get(i);
            if (sub) {
                out += sub.to;
                i += sub.length;
            } else {
                out += chars[i];
                i += 1;
            }
        }
        return out;
    }

    // ── Test 3 — compare one variant both ways ────────────────────────────────

    function compareVariant(variantName, suffix) {
        const variantHost = suffix ? `${variantName}.${suffix}` : variantName;

        // Brand match checked FIRST, even though it's structurally the
        // cheaper/narrower check: a curated brand-keyword hit is higher
        // confidence than a Bloom-filter top-sites hit (see
        // SCORING_CONFIG.LOOKALIKE_BRAND_SCORE vs LOOKALIKE_SITE_SCORE), and
        // every brand website is already unioned into the top-sites filter
        // too (tools/build-top-sites-filter.mjs's addBrandAndGovDomains) —
        // so checking top-sites first would silently downgrade every
        // brand-list hit to the weaker "site" result.
        const brandHit = Brands.matchWordAgainstBrands(Brands.wordsOf(variantHost));
        if (brandHit) {
            return { type: "brand", keyword: brandHit.keyword, resembles: brandHit.brand.domains[0] };
        }

        if (variantName.length >= CONFIG.MIN_WHOLE_NAME_LENGTH && TopSitesFilter.mightBeTopSite(variantHost)) {
            return { type: "site", resembles: variantHost };
        }
        return null;
    }

    // ── Public: check(hostname) ────────────────────────────────────────────────

    /**
     * @param {string} hostname — a download URL's hostname (as from
     *   util/UrlUtils.getHostname()).
     * @returns {{type: "brand"|"site", resembles: string, keyword?: string} | null}
     */
    function check(hostname) {
        if (!hostname) return null;
        const registeredDomain = UrlUtils.getRegisteredDomain(hostname);
        if (!registeredDomain) return null;

        // Test 1 — the host itself is popular -> stop.
        if (TopSitesFilter.mightBeTopSite(registeredDomain)) return null;

        const firstDot = registeredDomain.indexOf(".");
        if (firstDot <= 0) return null; // no separate name+suffix to work with
        const name   = registeredDomain.slice(0, firstDot);
        const suffix = registeredDomain.slice(firstDot + 1);

        // Test 1.5 (v3.3.0, item 17) — the SUFFIX itself is a government-
        // restricted registry (e.g. "gov.uk") -> stop. Only a verified
        // government body can register under one of these, so this domain
        // IS a real gov site by construction; a fake domain merely
        // mentioning "gov" in its own name has some OTHER suffix (e.g.
        // "evil.com") and is unaffected — this checks the suffix only,
        // never the full name.
        if (GovSuffixes.set.has(suffix)) return null;

        // Test 2 — no imitation characters -> stop (this check only).
        const { decoded, occurrences: clearOccurrences } = findClearOccurrences(name);
        const questionableOccurrences = findQuestionableOccurrences(decoded);
        if (clearOccurrences.length === 0 && questionableOccurrences.length === 0) return null;

        // Test 3 — convert and compare, first hit wins. Steps 2-4 only apply
        // (and only differ from each other / step 1) when there actually are
        // that many questionable occurrences — "duplicates skipped" per the
        // design doc is naturally satisfied by these length guards.
        const steps = [[]];
        if (questionableOccurrences.length >= 1) steps.push(questionableOccurrences.slice(0, 1));
        if (questionableOccurrences.length >= 2) steps.push(questionableOccurrences.slice(0, 2));
        if (questionableOccurrences.length >= 3) steps.push(questionableOccurrences.slice());

        for (const questionableToApply of steps) {
            if (clearOccurrences.length === 0 && questionableToApply.length === 0) continue; // that's the original name — test 1 already covers it
            const variantName = buildVariant(decoded, clearOccurrences, questionableToApply);
            if (variantName === name) continue; // no actual change — nothing to compare
            const hit = compareVariant(variantName, suffix);
            if (hit) return hit;
        }
        return null;
    }

    return { check, CONFIG };

})();
