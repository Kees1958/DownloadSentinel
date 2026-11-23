"use strict";

import { FpReductionEngines } from "../util/FpReductionEngines.js"; // getRawStats, filterResults — used by evaluateFromAnalysisResults below
import { UrlUtils } from "../util/UrlUtils.js"; // getHostname() — handles blob: URLs correctly (see that file)
import { CombinationScoring } from "./CombinationScoring.js"; // combineHostResults() — heuristics plan Step 3, v2.9.0
import { FilenameUrlHeuristics } from "./FilenameUrlHeuristics.js"; // RLO/padded-ext/shortener/referrer — heuristics plan Step 5, v2.11.0
import { LookalikeDomainCheck } from "./LookalikeDomainCheck.js";
import { DeliveryContext } from "./DeliveryContext.js"; // v3.5.0 — explain / cluster / credit step
import { DeliveryPatterns } from "../util/DeliveryPatterns.js"; // v3.5.0 — Check 27 message origin
import { TopSitesFilter } from "../util/TopSitesFilter.js"; // v3.5.0 — established-site credit // 3P Matrix alignment §1, v3.2.0 — see check 23 below

/**
 * ScoringEngineV2.js
 *
 * Scores a download URL across two independent axes:
 *
 *   A. VirusTotal URL reputation
 *      Weights: detection 70 %, age (VT first-seen) 30 %
 *      Community score removed.
 *
 *   B. Host reputation  (many parallel checks, combined per Step 3 below)
 *      1. DNS threat-intel block check (user's chosen 2 of Quad9/Cloudflare
 *         Security/Control D — v3.0.6; see DnsThreatProtection.js)
 *      2. RDAP registration age  (only when a configured DNS check resolves
 *         the domain) — its
 *         own independent signal (HOST_AGE family). When it is the ONLY
 *         signal present, CombinationScoring doubles it (e.g. < 30 days →
 *         −40); combined with any other signal it contributes its raw score
 *         and stacks like everything else (v2.9.0 — see check 20 below;
 *         before v2.9.0 this was instead folded additively, capped at −20,
 *         into whichever domain/TLD/list hit was present — see CHANGELOG).
 *      3. Suspicious-domain list match  (domain score × VT-suspicious-≥9 multiplier, base −70)
 *      4. Suspicious-TLD list match     (TLD score   × VT-suspicious-5–9 multiplier, base −50)
 *      5. Sketchy URL pattern heuristics (SketchyUrlCheck score × base −35)
 *      6. MIME type vs file extension consistency (mismatch → −60, consistent → 0)
 *      7. File size vs VirusTotal maximum 650 MB  (exceeds → −20; not for a huge Check-26 file, 4.5.8)
 *      8. HTTP protocol (when a configured DNS check resolves domain)  → −40
 *      9. IP address as download host (IPv4 or IPv6)  → −30
 *     10. Risky hosting platform                    → −15 to −80
 *     11. Script format (LOLBin-style)               → −25
 *     12. Extension obfuscation (onCreated vs onChanged) → −20 to −40
 *     13. HTTPS-to-HTTP redirect downgrade            → −35
 *     14. Double/deceptive extension chain            → −50
 *     15. URL contains embedded credentials           → −45
 *     16. Linux .desktop launcher file                → −35
 *     17. Merged host-risk list (HostList.js, v2.7.0)  (list score × base −70,
 *         same scaling/combination pattern as check 3 — a risk value, not a
 *         block; see SCORING_CONFIG.HOST_LIST_BASE_SCORE)
 *     18. Staging keywords (StagingCheck.checkKeywords, v2.8.0) — lure words,
 *         command-injection patterns and hidden Base64 payloads found in the
 *         URL path/query/fragment or filename (score × base −70, same
 *         scaling pattern as check 3; see SCORING_CONFIG.HOST_STAGING_BASE)
 *     19. Staging file format (StagingCheck.checkFormat, v2.8.0) — first-stage
 *         staging formats (Excel add-ins, shortcut formats) and undersized/
 *         unsized disk-image containers (see SCORING_CONFIG.STAGING_FORMAT_*
 *         and STAGING_CONTAINER_*)
 *     20. Combination scoring (CombinationScoring.combineHostResults, v2.9.0)
 *         — checks 1-19 above no longer simply report "worst single signal
 *         wins". Each check's source is grouped into one of nine families
 *         (see CombinationScoring.FAMILY_MAP); within a family only the
 *         worst member counts, so two signals measuring the same underlying
 *         thing (e.g. a HostList hit and an IP-address host) can't inflate
 *         each other. When two or more distinct families fire, their scores
 *         stack with geometric decay (2nd family ×0.5, 3rd ×0.25, 4th
 *         ×0.125; a 5th+ family adds nothing), plus a small bonus from any
 *         matching combination rule (e.g. "script from free/dynamic
 *         hosting"), the whole addition capped at −35 beyond the single
 *         worst signal. When only ONE family fires, the result is byte-for-
 *         byte identical to v2.8.0 — this is a hard invariant, tested
 *         explicitly (see tests/CombinationScoring.test.js).
 *     21. RLO/bidi-override character in filename or URL (v2.11.0)
 *     22. Padded double extension, e.g. "invoice_pdf____.exe" (v2.11.0)
 *     23. Look-alike/imitation-character domain check (v3.2.0, 3P Matrix
 *         alignment §1 — protection/LookalikeDomainCheck.js). Replaces the
 *         old "bigram homoglyph brand typosquat" (v2.11.0) with one unified
 *         check against both the brand list and the top-sites list; applied
 *         to the final URL's host and, when the registered domain differs,
 *         the original (pre-redirect) URL's host too — worse of the two, the
 *         same pattern BrowserProtection.checkHostReputation already uses
 *         for its own DNS checks.
 *     24. URL-shortener host (v2.11.0, weak/contextual only)
 *     25. Referrer/download-host mismatch (v2.11.0, weak/contextual only,
 *         defensively neutral whenever referrer or host is unavailable)
 *         — checks 21, 22, 24, 25 are protection/FilenameUrlHeuristics.js,
 *         heuristics plan "Later steps" Step 5; check 23 is its own module
 *         (see above). See each file's header for detail.
 *
 *   The caller (BrowserProtection / background.js) runs both axes in parallel
 *   and reports whichever produces the worst (lowest) final score.
 */
// Byte-size unit for every size threshold below (3P Matrix 4.5.8 — was a typed 1024 * 1024 per use).
const BYTES_PER_MB = 1024 * 1024;
// VirusTotal's maximum upload size: larger files are never scanned by it. ONE value for MimeCheck's
// Check 7 (SIZE_EXCEEDS_VT_SCORE, fires ABOVE it) and the huge tier of Check 26 (fires AT or above it).
const VT_MAX_MB = 650;

// ─────────────────────────────────────────────────────────────────────────────
// SCORING CONFIGURATION — tune all thresholds and bonuses here.
// Changing a value here affects the entire scoring system automatically.
// ─────────────────────────────────────────────────────────────────────────────
export const SCORING_CONFIG = {
    // ── Score range + hard DNS rule (v3.5.2 — were −100/100 literals) ──────────
    SCORE_FLOOR:            -100,  // every score is clamped to [SCORE_FLOOR, SCORE_CEILING]
    SCORE_CEILING:           100,
    DNS_BLOCKED_SCORE:      -100,  // a DNS threat-intel block: "Confirmed malicious" (hard rule)


    // ── VT detection base scores ──────────────────────────────────────────────
    VT_CLEAN_BASE:          30,    // base score when all engines clean
    VT_LONGEVITY_7D:        10,    // bonus: URL first seen > 7 days ago
    VT_LONGEVITY_30D:       30,    // bonus: URL first seen > 30 days ago

    // ── ABC consensus bonus (percentage of responding engines that are clean) ──
    ABC_A_PCT:              90,    // ≥ 90% clean → bonus A
    ABC_B_PCT:              70,    // ≥ 70% clean → bonus B
    ABC_C_PCT:              50,    // ≥ 50% clean → bonus C
    ABC_A_BONUS:            30,
    ABC_B_BONUS:            20,
    ABC_C_BONUS:            10,
    ABC_MIN_DAYS:            7,    // hard block: URL must be > 7 days old for bonus to apply

    // ── VT age penalties ──────────────────────────────────────────────────────
    VT_AGE_UNDER2D:        -20,    // URL first seen < 2 days ago
    VT_AGE_UNDER7D:        -10,    // URL first seen 2–7 days ago

    // ── VT detection penalties ────────────────────────────────────────────────
    VT_MALICIOUS_5PLUS:   -100,
    VT_MALICIOUS_3_4:      -80,    // base, scaled by age multiplier
    VT_MALICIOUS_1_2:      -60,    // base, scaled
    VT_SUSPICIOUS_10PLUS:  -70,
    VT_SUSPICIOUS_5_9:     -50,    // base, scaled  ← was -40 in config but -50 in code; -50 is correct
    VT_SUSPICIOUS_3_4:     -30,    // base, scaled
    VT_SUSPICIOUS_2:       -20,    // base
    VT_SUSPICIOUS_1:       -15,    // base

    // ── Host reputation base scores ───────────────────────────────────────────
    // Align with the VT detection tiers they correspond to:
    //   DOMAIN_BASE: mirrors VT suspicious ≥ 9 class (−70)
    //   TLD_BASE:    mirrors VT suspicious 5–8 class (−50)
    //   SKETCHY_URL: heuristic only — lower confidence than list hits
    HOST_DOMAIN_BASE_SCORE: -70,
    HOST_TLD_BASE_SCORE:    -50,
    HOST_SKETCHY_URL_BASE:  -35,

    // ── Merged host-risk list (heuristics plan Step 1, v2.7.0) ────────────────
    // HostList.js merges HaGeZi's DynDNS + Badware Hoster lists with Kees1958's
    // Suspicious-websites list (~2,641 net-new entries after dedup against
    // SuspiciousDomains.js / RiskyHostingSites.js — see tools/update-lists.mjs).
    // Same base-score mechanism as HOST_DOMAIN_BASE_SCORE: each entry carries
    // its own 0-100 risk value (see HostList.js), scaled through this base so
    // a hit alone stays in the "moderate" range — it is a risk value, not a
    // block, and only becomes decisive when combined with other signals
    // (heuristics plan Step 3 / v2.9.0 — not yet implemented).
    HOST_LIST_BASE_SCORE:   -70,

    // ── Staging keywords + staging formats (heuristics plan Step 2, v2.8.0) ──
    // HOST_STAGING_BASE: StagingCheck.checkKeywords() returns a 0-100 score
    // (lure words + command-injection patterns + hidden Base64 payloads found
    // in the URL/filename) scaled through this base, same mechanism as
    // HOST_DOMAIN_BASE_SCORE/HOST_LIST_BASE_SCORE above — a keyword hit alone
    // stays moderate; it only becomes decisive combined with other signals
    // (Step 3 / v2.9.0 combination scoring — not yet implemented).
    HOST_STAGING_BASE:        -70,

    // STAGING_FORMAT_*: StagingCheck.checkFormat() returns one of four tiers
    // directly (not a 0-100 score to scale) — each tier maps to its own fixed
    // score here. HIGH/MED are first-stage staging formats (Excel add-in,
    // Windows shortcut formats, ClickOnce, etc. — see StagingCheck.FORMATS);
    // CONTAINER_SMALL/CONTAINER_UNKNOWN are disk-image containers (iso/img/
    // vhd/vhdx) that are either suspiciously small or not yet sized.
    STAGING_FORMAT_HIGH:      -40,
    STAGING_FORMAT_MED:       -30,
    STAGING_CONTAINER_SMALL:  -35,
    STAGING_CONTAINER_UNKNOWN: -15,

    // ── Classification thresholds (combined VT + host score) ─────────────────
    THRESHOLD_SAFE:         30,    // score ≥ 30  → probably safe
    THRESHOLD_QUESTIONABLE: -30,   // score ≥ -30 → probably inconclusive
    THRESHOLD_SUSPICIOUS:   -60,   // score ≥ -60 → probably suspicious
                                   // score <  -60 → probably malicious

    // ── VT confidence thresholds ──────────────────────────────────────────────
    CONFIDENCE_HIGH_DAYS:  180,    // > 180 days → High confidence
    CONFIDENCE_MED_DAYS:    30,    // > 30 days  → Medium confidence

    // ── Host reputation: script format ────────────────────────────────────────
    SCRIPT_FORMAT_SCORE:   -25,    // penalty for script downloads (.ps1, .vbs, etc.)

    // ── Host reputation: HTTP / IP penalties ──────────────────────────────────
    // v3.4.0 weight review: −40 → −25. Alone it put 53 of 54 known-good
    // corpus downloads into "Probably Suspicious" when fetched from a plain-HTTP
    // mirror. Still ≤ CombinationScoring STACK_MIN_SIGNAL, so it stacks — a bare
    // IP over HTTP still scores Suspicious (plus combination rule C6).
    HTTP_PENALTY:          -25,
    // IP_HOST_PENALTY now covers IPv4, IPv6, and any noncanonical IPv4 form
    // (integer/hex/octal) that the browser's URL parser already canonicalizes
    // to a literal IP before we ever see it — see isIpHost() below (DS-H005).
    IP_HOST_PENALTY:       -30,

    // ── DS-H006 — HTTPS-to-HTTP redirect downgrade ─────────────────────────────
    // Download started on HTTPS but the final URL is unencrypted HTTP.
    // Independent signal from HTTP_PENALTY above (which fires when the whole
    // download was HTTP from the start) — a downgrade is a stronger signal
    // because it implies an active redirect stripped encryption mid-flight.
    HTTPS_DOWNGRADE_SCORE: -35,

    // ── DS-H004 — URL contains embedded credentials (user:pass@host) ───────────
    // Classic disguise: the visible text before "@" can look like a trusted
    // hostname while the actual destination (url.hostname) is something else.
    URL_CREDENTIALS_SCORE: -45,

    // ── DS-H001 — Linux .desktop launcher file ──────────────────────────────────
    // A .desktop file can define an Exec= line that runs an arbitrary shell
    // command when opened from a file manager — comparable risk tier to a
    // raw script (see SCRIPT_FORMAT_SCORE) but slightly higher because the
    // "double-click to run a document" affordance makes it easier to trigger
    // by accident than a visibly-scripty file.
    LINUX_LAUNCHER_SCORE:  -35,

    // ── Double extension in filename ──────────────────────────────────────────
    // e.g. invoice.pdf.exe — the true dangerous extension is hidden behind a
    // decoy extension. Virtually never legitimate. High-confidence signal.
    DOUBLE_EXTENSION_SCORE:            -50,

    // ── Extension obfuscation (Check 12) ────────────────────────────────────
    // Same FILE_DECEPTION family as DOUBLE_EXTENSION_SCORE above.
    // UNKNOWN_REVEALED: no extension was detectable at all when the download
    // started; the confirmed file turned out to be dangerous.
    // v3.4.0 weight review: −50 → −20. The old rationale ("same tier as a
    // double extension, no ordinary reason a server hides this") predates
    // combination scoring and is wrong: vendor CDNs routinely serve installers
    // from extensionless links and name the file via Content-Disposition
    // (go.microsoft.com/fwlink, download.mozilla.org, dl.google.com,
    // bits.avcdn.net for CCleaner/Avast). Replaying the knownGood corpus with
    // this signal turned 54/54 legit installers Suspicious (11 Malicious);
    // now 42 Inconclusive, the remaining 12 are install scripts (+ScriptFormat).
    // One step above EXTENSIONLESS_BINARY_SCORE (−15): "still hidden" −15,
    // "was hidden and is a program" −20. Still stacks (≤ STACK_MIN_SIGNAL).
    OBFUSCATION_UNKNOWN_SCORE:         -20,
    // CATEGORY_CHANGED: an extension WAS visible up front, it just switched
    // risk category after a redirect/rename (e.g. archive -> executable).
    // Weaker than full concealment above — occasionally legitimate (server-
    // side repackaging, content negotiation) — so one tier down, roughly
    // between LOOKALIKE_SITE_SCORE and DOUBLE_EXTENSION_SCORE.
    OBFUSCATION_CATEGORY_CHANGE_SCORE: -35,

    // ── Link opened from webmail / chat (v3.5.0 — Check 27) ─────────────────
    // The referrer (or the start of the redirect chain) is a webmail or chat
    // page (util/DeliveryPatterns.js MESSAGE_ORIGINS) — the classic route of a
    // phishing lure. Weak on its own (people share real links in chats too);
    // it matters together with other small oddities
    // (protection/DeliveryContext.js weak-signal cluster). Family ORIGIN.
    MESSAGE_ORIGIN_SCORE:              -10,

    // ── MimeCheck scores (v3.4.0 — moved here from literals in MimeCheck.js) ─
    // MIME_MISMATCH_SCORE: the visible extension and the declared content type
    // disagree (e.g. .exe as image/jpeg, invoice.pdf as an executable type).
    // v3.4.0 weight review: −60 → −45. A mismatch also has dull causes
    // (servers using a type our table lacks — 9 official types were missing
    // until v3.4.0, see DangerousMimes.js — or an HTML error page saved under
    // the requested name); −60 alone sat on the Malicious line.
    MIME_MISMATCH_SCORE:               -45,
    // SIZE_EXCEEDS_VT_SCORE: file larger than VirusTotal's scan limit
    // (MimeCheck.VT_MAX_BYTES) — VT would skip it. Value unchanged.
    SIZE_EXCEEDS_VT_SCORE:             -20,
    BYTES_PER_MB,
    VT_MAX_BYTES:                      VT_MAX_MB * BYTES_PER_MB,   // read by MimeCheck.checkSize and Check 26

    // ── Extensionless generic binary (v3.4.0, heuristic R1 — Check 26) ──────
    // No extension anywhere (URL, original URL, filename) AND a generic
    // binary content type (DangerousMimes.GENERIC_BINARY_MIMES): the server
    // does not say what the file is. Same FILE_DECEPTION family as
    // Obfuscation, but deliberately far weaker than OBFUSCATION_UNKNOWN_SCORE:
    // legitimate Linux release binaries (e.g. a GitHub "tool-linux-amd64"
    // asset) look exactly like this. Stronger than a young domain (-10) and
    // equal to CombinationScoring.CONFIG.STACK_MIN_SIGNAL, so it DOES stack
    // with a risky host — e.g. a Discord CDN attachment is then no longer a
    // "solo" RiskyHosting hit that gets halved. The warning itself is
    // guaranteed separately (APP.EXTENSIONLESS_BINARY_ALWAYS_WARN), not by
    // this score.
    EXTENSIONLESS_BINARY_SCORE:        -15,
    // Large extensionless binary on a file-sharing host (3P Matrix 4.5.6, user request after a real case:
    // an 80 MB extensionless blob from cdn.discordapp.com). Droppers are padded this large so virus
    // scanners skip them, and the content cannot be inspected from an extension. Same signal (Check 26),
    // made heavier: with the risky-host hit stacked on top the verdict reaches "Probably Suspicious"
    // (−30 + ½ × −20 = −40) instead of "Probably Inconclusive" (−27). Only with a RiskyHostingSites hit —
    // a large extensionless file from a vendor's own download host is not touched. Legitimate large Linux
    // binaries from GitHub release assets (also a RiskyHostingSites host) lose points too — accepted.
    // 4.5.8: threshold 50 → 32 MB (user decision 2026-11-06).
    LARGE_EXTENSIONLESS_BINARY_SCORE:  -30,
    LARGE_EXTENSIONLESS_BINARY_MIN_BYTES: 32 * BYTES_PER_MB,
    // Huge tier (3P Matrix 4.5.8, user request): same scope (extensionless + file-sharing host), at or above
    // VirusTotal's upload limit — heavier than the large tier because no AV scan will ever see the file.
    // It REPLACES Check 7 (SIZE_EXCEEDS_VT_SCORE) for such a file: one fact, one signal. Verdict with the
    // risky-host hit stacked: see 3P Matrix tools/test-large-binary.mjs and DS tests/ExtensionlessSizeTiers.test.js (stays "Probably Suspicious", never Malicious alone).
    HUGE_EXTENSIONLESS_BINARY_SCORE:   -45,
    HUGE_EXTENSIONLESS_BINARY_MIN_BYTES: VT_MAX_MB * BYTES_PER_MB,

    // ── Heuristics plan "Later steps" (v2.11.0 — Step 5) ──────────────────────
    // Five small filename/URL heuristics. See protection/FilenameUrlHeuristics.js
    // for full detection detail and rationale.

    // RLO/bidi-override character in the filename or URL — the classic
    // "gpj.exe" (reversed to display as "exe.jpg") disguise trick. Almost
    // never legitimate: same high-confidence tier as DOUBLE_EXTENSION_SCORE
    // / the FILE_DECEPTION family's other members, slightly above it since
    // this is an even more deliberate, purely-malicious construction.
    RLO_SCORE:                         -80,

    // Padded double extension (e.g. "Invoice_PDF____________________.exe") —
    // a near-pure attack pattern distinct from the plain double-extension
    // check above (see FilenameUrlHeuristics.checkPaddedDoubleExtension).
    // Same score tier as RLO_SCORE for the same reason.
    PADDED_DOUBLE_EXTENSION_SCORE:     -80,

    // v3.2.0 (3P Matrix alignment §1): BRAND_HOMOGLYPH_SCORE and
    // LOOKALIKE_TOP_SITE_SCORE below are REPLACED by these two —
    // protection/LookalikeDomainCheck.js's single unified check now decides
    // brand-vs-site, so only one of the two scores below is ever applied per
    // check result (never both). Same relative weighting/rationale as the
    // two scores they replace, carried over verbatim:

    // The character-substitution/confusable variant matched a brand's own
    // keyword (util/Brands.js — curated, exact-after-conversion) — high
    // confidence once it fires, one notch below RLO/padded-extension since a
    // domain-identity signal alone is a weaker proxy for "this specific
    // download is malicious" than a crafted filename is. Comparable to
    // HOST_DOMAIN_BASE_SCORE (−70, suspicious-domain-list hit).
    LOOKALIKE_BRAND_SCORE:             -65,

    // The variant matched the top-sites list instead (util/TopSitesFilter.js
    // — a Bloom filter over ~80,000 popular + brand/gov domains, not a
    // hand-curated brand list), e.g. "g00gle-update.com". Deliberately
    // weaker than LOOKALIKE_BRAND_SCORE: a hit against the curated brand
    // list is close to certain, while this one runs against a
    // ~1%-false-positive-rate Bloom filter, so an occasional coincidental
    // match against an unrelated popular name is expected, not exceptional.
    // Comparable to RiskyHosting's mid-tier scores rather than a
    // hard-warning tier on its own.
    // v3.4.0 weight review: −45 → −35 — alone it read as "Suspicious" for a
    // ~1%-false-positive Bloom-filter match; the curated brand list (−65) is
    // where a lookalike hit is near-certain.
    LOOKALIKE_SITE_SCORE:              -35,

    // URL shortener host — much weaker/more ambiguous than the other four:
    // shorteners are extremely common for entirely legitimate use, so this
    // is purely informational/contextual and never a hard warning on its own.
    URL_SHORTENER_SCORE:               -15,

    // Referrer resolves to a different, unrelated origin than the download
    // host itself. Conservative/low-confidence by design — see
    // FilenameUrlHeuristics.js's header for the tab-origin comparison that
    // was dropped (no chrome.tabs permission in this codebase) and why only
    // this weaker half shipped; this can and should stay low-weight even if
    // kept, since a referrer/host mismatch alone is extremely common for
    // entirely benign reasons (download managers, CDNs, link shorteners,
    // in-page "download" buttons that redirect through an ad network).
    REFERRER_MISMATCH_SCORE:           -12,

    // "This host is just a cheap/free hosting platform" is weaker evidence
    // on its own than when something else about the download also looks
    // wrong — so when RiskyHosting is the ONLY signal that clears the
    // combination engine's own stacking floor (CombinationScoring.CONFIG.
    // STACK_MIN_SIGNAL — i.e. nothing else present is strong enough to ever
    // stack with anything regardless), its score is halved rather than
    // reported at full strength. See evaluateHostReputation()'s "Check 10b"
    // for where this applies. Round (not floor/ceil) so halving a score
    // like -25 lands on the nearer whole number (-13), not always weaker or
    // always stronger.
    RISKY_HOSTING_SOLO_DIVISOR:         2,
    // v3.5.0 — weak signals that still count as corroboration for the halving
    // rule above: a file-sharing link clicked in a chat/webmail is the classic
    // lure, even though MessageOrigin (−10) is below the stacking floor.
    RISKY_HOSTING_CORROBORATING_SOURCES: Object.freeze(["MessageOrigin"]),

    // ── VT-unknown host-score multipliers ─────────────────────────────────────
    // Applied in background.js (onChanged) when VT has no data for the URL.
    // Scales negative host-reputation signals based on FP reduction level:
    //   HIGH   → no scaling since v3.5.0 (was 0.5, "dampen alarm") — see below
    //   MEDIUM → neutral (no scaling)
    //   LOW    → amplify (lean toward warning when VT data is absent)
    //   NONE   → most aggressive amplification
    // Positive host scores are never scaled (no free bonus from VT absence).
    // v3.5.0: HIGH's "fewer alarms" now comes from its reasoning
    // strategy (protection/DeliveryContext.js: recognised deliveries explained,
    // 4 weak oddities needed). Also halving every penalty made HIGH lenient
    // twice: real deception (a script lure from raw GitHub, invoice.pdf that is
    // a program) stayed "inconclusive". At 1.0 those reach Suspicious at HIGH,
    // while every legit flow in fp-corpus stays below it (user decision 2026-10-24).
    FP_UNKNOWN_MULTIPLIERS: Object.freeze({
        HIGH:   1.0,
        MEDIUM: 1.0,
        LOW:    1.5,
        NONE:   2.0,
    }),
};

export const ScoringEngineV2 = (function () {

    const Classification = {
        PROBABLY_SAFE:         "Probably Safe",
        PROBABLY_QUESTIONABLE: "Probably Inconclusive",
        PROBABLY_SUSPICIOUS:   "Probably Suspicious",
        PROBABLY_MALICIOUS:    "Probably Malicious"
    };

    const SECONDS_PER_DAY = 86400;

    // ─────────────────────────────────────────────────────────────────────────
    // A.1  Detection Score  (VT analysis stats)
    //      Age-weighted: recent first-seen dates amplify negative signals.
    // ─────────────────────────────────────────────────────────────────────────
    function scoreDetection(stats, ageDays) {

        const malicious  = stats.malicious  ?? 0;
        const suspicious = stats.suspicious ?? 0;
        const harmless   = stats.harmless   ?? 0;

        const under2 = ageDays !== null && ageDays < 2;
        const under7 = ageDays !== null && ageDays < 7;

        // ── Malicious ────────────────────────────────────────────────────────
        if (malicious >= 5) {
            return { score: SCORING_CONFIG.VT_MALICIOUS_5PLUS, label: "≥ 5 malicious detections" };
        }
        if (malicious >= 3) {
            const score = Math.round(SCORING_CONFIG.VT_MALICIOUS_3_4 * (under7 ? 1.0 : 0.5));
            return { score, label: "3–4 malicious detections" };
        }
        if (malicious >= 1) {
            const mult  = under2 ? 1.0 : under7 ? 0.5 : 0.1;
            const score = Math.round(SCORING_CONFIG.VT_MALICIOUS_1_2 * mult);
            const label = malicious === 1 ? "1 malicious detection" : "2 malicious detections";
            return { score, label };
        }

        // ── Suspicious ───────────────────────────────────────────────────────
        if (suspicious >= 10) {
            return { score: SCORING_CONFIG.VT_SUSPICIOUS_10PLUS, label: "≥ 10 suspicious detections" };
        }
        if (suspicious >= 5) {
            const score = Math.round(SCORING_CONFIG.VT_SUSPICIOUS_5_9 * (under7 ? 1.0 : 0.5));
            return { score, label: "5–9 suspicious detections" };
        }
        if (suspicious >= 3) {
            const score = Math.round(SCORING_CONFIG.VT_SUSPICIOUS_3_4 * (under7 ? 1.0 : 0.5));
            return { score, label: "3–4 suspicious detections" };
        }
        if (suspicious === 2) {
            const mult  = under2 ? 1.5 : under7 ? 1.0 : 0.1;
            const score = Math.round(SCORING_CONFIG.VT_SUSPICIOUS_2 * mult);
            return { score, label: "2 suspicious detections" };
        }
        if (suspicious === 1) {
            const mult  = under2 ? 2.0 : under7 ? 1.0 : 0.5;
            const score = Math.round(SCORING_CONFIG.VT_SUSPICIOUS_1 * mult);
            return { score, label: "1 suspicious detection" };
        }

        // Clean file — apply longevity bonus + ABC consensus bonus.
        // Longevity: file has been in VT's database long enough to be scrutinised.
        // ABC bonus: rewards clean consensus across many engines (see evaluate()).
        if (harmless > 0) {
            const over30      = ageDays !== null && ageDays >= 30;
            const over7       = ageDays !== null && ageDays >= 7;
            const longevity   = over30 ? SCORING_CONFIG.VT_LONGEVITY_30D : over7 ? SCORING_CONFIG.VT_LONGEVITY_7D : 0;
            const score       = SCORING_CONFIG.VT_CLEAN_BASE + longevity + (arguments[2] || 0); // abcBonus passed as 3rd arg
            const label       = over30
                ? "No malicious detections (established file)"
                : "No malicious detections";
            return { score, label };
        }
        return { score: 10, label: "Undetected" };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A.2  VT First-Seen Age Score
    //      Cut-points: < 2 days → −20,  2–7 days → −10,  > 7 days → 0
    // ─────────────────────────────────────────────────────────────────────────
    function scoreVtAge(firstSubmissionDate) {

        if (firstSubmissionDate === null || firstSubmissionDate === undefined) {
            return { score: 0, ageDays: null, label: "Unknown age" };
        }

        const ageDays = (Date.now() / 1000 - firstSubmissionDate) / SECONDS_PER_DAY;
        const days    = Math.max(0, Math.floor(ageDays));

        if (ageDays > 7)  return { score: 0, ageDays, label: `${days} days since first seen` };
        if (ageDays > 2)  return { score: SCORING_CONFIG.VT_AGE_UNDER7D, ageDays, label: `${days} days since first seen` };
        return                   { score: SCORING_CONFIG.VT_AGE_UNDER2D, ageDays, label: `${days} days since first seen` };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A.3  Confidence (VT axis only — reflects data richness, not score)
    // ─────────────────────────────────────────────────────────────────────────
    function computeVtConfidence(ageDays) {
        if (ageDays === null || ageDays === undefined) return "Low";
        if (ageDays > SCORING_CONFIG.CONFIDENCE_HIGH_DAYS) return "High";
        if (ageDays >= SCORING_CONFIG.CONFIDENCE_MED_DAYS) return "Medium";
        return "Low";
    }

    // ─────────────────────────────────────────────────────────────────────────
    // A.4  Hard Rules (VT axis — override score-based classification)
    // ─────────────────────────────────────────────────────────────────────────
    function applyHardRules(malicious, suspicious) {
        if (malicious >= 5) {
            return { classification: Classification.PROBABLY_MALICIOUS, reason: "≥ 5 malicious detections" };
        }
        if (suspicious >= 10) {
            return { classification: Classification.PROBABLY_MALICIOUS, reason: "≥ 10 suspicious detections" };
        }
        if (malicious >= 1) {
            return {
                classification: Classification.PROBABLY_SUSPICIOUS,
                reason: `${malicious} malicious detection${malicious > 1 ? "s" : ""}`
            };
        }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Score → Classification  (shared by both axes)
    // ─────────────────────────────────────────────────────────────────────────
    // Host-axis headline: signal count + verdict. 3P Matrix 4.5.8: one builder, exported, so a caller that changes
    // the score afterwards (3P Matrix's active-threat floor) rebuilds the same headline instead of retyping it.
    function heuristicLabel(signalCount, classification) {
        return `${signalCount} heuristic risk signal${signalCount === 1 ? "" : "s"} detected — ${String(classification).toLowerCase()}`;
    }

    function classifyByScore(score) {
        if (score >= SCORING_CONFIG.THRESHOLD_SAFE)         return Classification.PROBABLY_SAFE;
        if (score >= SCORING_CONFIG.THRESHOLD_QUESTIONABLE) return Classification.PROBABLY_QUESTIONABLE;
        if (score >= SCORING_CONFIG.THRESHOLD_SUSPICIOUS)   return Classification.PROBABLY_SUSPICIOUS;
        return Classification.PROBABLY_MALICIOUS;
    }

    // =========================================================================
    // B.  Host Reputation Scoring
    //
    // Base multipliers come from VT detection tiers:
    //   suspicious ≥ 9  → −70  (used for domain-list check)
    //   suspicious 5–8  → −50  (used for TLD check)
    //
    // The domain-list/TLD risk score (0–100) acts as a proportion of that
    // multiplier, e.g. a domain with score 80 contributes 80/100 × −70 = −56.
    //
    // RDAP registration age is applied additively after the base score, using
    // the 30-day cut-point:
    //   < 30 days  →  −20
    //   30–90 days →  −10
    //   > 90 days  →    0
    // =========================================================================

    // Host base scores are now in SCORING_CONFIG (HOST_DOMAIN_BASE_SCORE,
    // HOST_TLD_BASE_SCORE, HOST_SKETCHY_URL_BASE) — no local consts needed.

    /**
     * v3.5.0 — moved here from background.js's computeCombinedScore() so the
     * extension and tools/fp-sweep.mjs apply the identical math (single source).
     * When VirusTotal has no verdict, the NEGATIVE part of the host score is
     * scaled by the FP reduction level (SCORING_CONFIG.FP_UNKNOWN_MULTIPLIERS);
     * a positive part is never scaled (no free bonus from VT's absence).
     *
     * @param {number} hostScore
     * @param {string} fpLevel   HIGH | MEDIUM | LOW | NONE (unknown → 1.0)
     * @param {boolean} vtUnknown
     * @returns {{ scaled: number, multiplier: number }}
     */
    const NO_SCALING = 1.0; // multiplier that leaves a score unchanged (VT known, or MEDIUM)
    function scaleHostScoreForUnknownVt(hostScore, fpLevel, vtUnknown) {
        const multiplier = vtUnknown ? (SCORING_CONFIG.FP_UNKNOWN_MULTIPLIERS[fpLevel] ?? NO_SCALING) : NO_SCALING;
        const scaled = multiplier !== NO_SCALING
            ? Math.round(Math.min(0, hostScore) * multiplier) + Math.max(0, hostScore)
            : hostScore;
        return { scaled, multiplier };
    }

    /**
     * Evaluate host reputation from the four parallel checks.
     *
     * @param {object} params
     * @param {object[]} params.dnsChecks    - 1-2 results from
     *        DnsThreatProtection.check() — the user's configured "first"/
     *        "second" DNS threat-intel checks (v3.0.6; replaces the old
     *        single-provider Quad9-only check).
     * @param {object} [params.quad9]        - legacy alias for a single-entry
     *        dnsChecks array; kept so existing callers/tests that still pass
     *        a bare `quad9: {...}` continue to work unchanged.
     * @param {object} params.rdap           - result from RdapProtection.check()
     * @param {object|null} params.domainHit  - result from SuspiciousDomains.lookup()
     * @param {object|null} params.tldHit     - result from SuspiciousTlds.lookup()
     * @param {object|null} params.hostListHit - result from HostList.lookup()
     *        (v2.7.0 — merged HaGeZi/Kees list; see SCORING_CONFIG.HOST_LIST_BASE_SCORE)
     * @param {object|null} params.stagingKeywords - result from
     *        StagingCheck.checkKeywords(), { score, signals } (v2.8.0)
     * @param {object|null} params.stagingFormat - result from
     *        StagingCheck.checkFormat(), { tier, label, source } or null (v2.8.0)
     * @param {object|null} params.sketchyUrl - result from SketchyUrlCheck.check()
     * @param {string} params.fileType        - FilenameAnalysis.FILE_TYPE value
     *        ("executable" | "archive" | "unknown-binary" since v3.4.0)
     * @param {string|null} [params.fpLevel] - v3.5.0: FP reduction level —
     *        selects DeliveryContext's strategy (null = its default, MEDIUM)
     * @param {boolean} [params.isUnknownBinary] - v3.4.0 (R1): no extension
     *        anywhere + generic binary MIME type — see Check 26
     * @param {string|null} params.originalUrl - pre-redirect URL, used for the
     *        HTTPS-to-HTTP downgrade check (DS-H006); omit or pass same as
     *        url when there was no redirect.
     * @param {boolean} params.isLinuxLauncher - true when the confirmed
     *        extension is ".desktop" (DS-H001).
     */
    // Check 26's size tier (3P Matrix 4.5.6 large, 4.5.8 huge). Only an extensionless generic binary from a
    // file-sharing host is tiered; size 0 = not known yet → NORMAL (download-guard re-scores at completion).
    const BINARY_SIZE_TIER = Object.freeze({ NONE: "none", NORMAL: "normal", LARGE: "large", HUGE: "huge" });
    function extensionlessSizeTier(isUnknownBinary, riskyHosting, totalBytes) {
        if (!isUnknownBinary) return BINARY_SIZE_TIER.NONE;
        if (!riskyHosting) return BINARY_SIZE_TIER.NORMAL;
        if (totalBytes >= SCORING_CONFIG.HUGE_EXTENSIONLESS_BINARY_MIN_BYTES) return BINARY_SIZE_TIER.HUGE;
        if (totalBytes >= SCORING_CONFIG.LARGE_EXTENSIONLESS_BINARY_MIN_BYTES) return BINARY_SIZE_TIER.LARGE;
        return BINARY_SIZE_TIER.NORMAL;
    }

    function evaluateHostReputation({ dnsChecks = null, quad9 = null, rdap, domainHit, tldHit, hostListHit = null, stagingKeywords = null, stagingFormat = null, sketchyUrl, mimeResult, sizeResult, riskyHosting, url, originalUrl = null, fileType = "executable", isScript = false, obfuscation = null, doubleExt = null, isLinuxLauncher = false, filename = "", referrer = null, isUnknownBinary = false, fpLevel = null, totalBytes = 0 }) {

        const results = [];
        const sizeTier = extensionlessSizeTier(isUnknownBinary, riskyHosting, totalBytes);

        // Normalize to an array — see the dnsChecks/quad9 JSDoc above for why
        // both shapes are accepted. SKIPPED entries (a DNS-check slot the
        // user turned off in Options) are filtered out here so nothing below
        // has to special-case them.
        const dns = (dnsChecks || (quad9 ? [quad9] : [])).filter(c => c && c.status !== "SKIPPED");
        const dnsBlockedHit = dns.find(c => c.status === "BLOCKED");
        const dnsResolved   = dns.some(c => c.status === "ALLOWED"); // at least one configured check actually resolved the domain

        // ── Check 1: DNS threat-intel block ───────────────────────────────────
        if (dnsBlockedHit) {
            const who   = dnsBlockedHit.providerLabel || "a DNS threat-intel check";
            const label = `Confirmed malicious (${fileType} from a domain blocked by ${who})`;
            results.push({ score: SCORING_CONFIG.DNS_BLOCKED_SCORE, label, source: "DnsThreat" });
        }
        // ALLOWED / UNKNOWN contribute 0; RDAP and domain/TLD checks add their own signals

        // ── RDAP age signal ────────────────────────────────────────────────────
        // v2.9.0 (Step 3): RDAP is now its own independent HOST_AGE-family
        // signal, reported at its raw score — CombinationScoring applies the
        // "×2 when it's the only signal" rule at combine time, not here (see
        // this file's header comment, check 2, for the full rationale; this
        // replaces the pre-v2.9.0 rdapAdditive/rdapStandalone fold-in below).
        const rdapRaw   = rdap?.score ?? 0;
        // Parse URL once for protocol checks; hostname comes from
        // UrlUtils.getHostname() instead of parsedUrl.hostname directly,
        // since the latter is "" for blob: URLs (see UrlUtils.js) — using it
        // directly here would silently disable the IP-host check and blank
        // out the credentials-check label below for any blob: download.
        let parsedUrl = null;
        try { parsedUrl = new URL(url || ""); } catch { /* invalid/empty URL — parsedUrl stays null, isHttp/isIpHost fall through to false */ }
        const hostname = UrlUtils.getHostname(url) || "";

        // DS-H005 — IPv4 dotted-decimal OR IPv6 literal (bracketed by the URL
        // parser, e.g. "[2001:db8::1]"). Integer/hex/octal IPv4 forms
        // (e.g. "0x7f000001", "2130706433") need no extra handling here: the
        // WHATWG URL parser already canonicalizes those to dotted-decimal in
        // hostname before this code ever runs, so the IPv4 regex alone
        // already catches them.
        const isIpv4Host = /^\d+\.\d+\.\d+\.\d+$/.test(hostname);
        const isIpv6Host = hostname.startsWith("[") && hostname.endsWith("]");
        const isIpHost    = !!(isIpv4Host || isIpv6Host);
        const isHttp    = parsedUrl && parsedUrl.protocol === "http:";

        // DS-H006 — HTTPS-to-HTTP downgrade: compare the ORIGINAL URL's
        // protocol (before any redirect) against the final URL's protocol.
        // Parsed separately from parsedUrl above since originalUrl may be a
        // different URL entirely (redirect chain), not just a variant of url.
        let parsedOriginalUrl = null;
        if (originalUrl && originalUrl !== url) {
            try { parsedOriginalUrl = new URL(originalUrl); } catch { /* leave null — no downgrade signal without a valid original URL */ }
        }
        const isHttpsToHttpDowngrade = !!(
            parsedOriginalUrl && parsedUrl &&
            parsedOriginalUrl.protocol === "https:" &&
            parsedUrl.protocol === "http:"
        );

        // DS-H004 — URL contains embedded username and/or password. Parsed
        // fields only (url.username / url.password) — never string matching,
        // so an encoded "@" inside a normal path can't produce a false hit.
        const hasUrlCredentials = !!(parsedUrl && (parsedUrl.username || parsedUrl.password));

        // RDAP contributes its own entry whenever a configured DNS check
        // confirms the domain resolves and the age score is negative — no
        // longer gated on "only when nothing else fired" (v2.9.0; see header
        // comment).
        if (dnsResolved && rdapRaw < 0) {
            results.push({
                score:  rdapRaw,
                label:  `New domain registration: ${rdap.label}`,
                source: "RDAP"
            });
        }

        // ── Check 3: Suspicious domain list ──────────────────────────────────
        if (domainHit) {
            const baseScore = Math.round((domainHit.score / 100) * SCORING_CONFIG.HOST_DOMAIN_BASE_SCORE);
            results.push({
                score:  Math.max(SCORING_CONFIG.SCORE_FLOOR, baseScore),
                label:  `Suspicious domain "${domainHit.matchedDomain}"`,
                source: "DomainList"
            });
        }

        // ── Check 4: Suspicious TLD ───────────────────────────────────────────
        if (tldHit) {
            const baseScore = Math.round((tldHit.score / 100) * SCORING_CONFIG.HOST_TLD_BASE_SCORE);
            results.push({
                score:  Math.max(SCORING_CONFIG.SCORE_FLOOR, baseScore),
                label:  `Top Level Domain .${tldHit.tld} is on the much abused TLD list`,
                source: "TldList"
            });
        }

        // ── Check 4a: Merged host-risk list (HostList.js — v2.7.0 Step 1) ────
        // Same scaling pattern as the domain/TLD list checks above: the
        // entry's own 0-100 risk value is scaled through HOST_LIST_BASE_SCORE.
        // See SCORING_CONFIG.HOST_LIST_BASE_SCORE for why a hit here alone
        // stays moderate rather than decisive (combination, not a fixed
        // rdapAdditive fold-in, is what lets it become decisive — v2.9.0).
        if (hostListHit) {
            const baseScore = Math.round((hostListHit.score / 100) * SCORING_CONFIG.HOST_LIST_BASE_SCORE);
            results.push({
                score:  Math.max(SCORING_CONFIG.SCORE_FLOOR, baseScore),
                label:  `Host "${hostListHit.matchedDomain}" is on a known free-hosting/dynamic-DNS risk list (${hostListHit.source})`,
                source: "HostList"
            });
        }

        // ── Check 18: Staging keywords (StagingCheck.checkKeywords — v2.8.0) ──
        // Lure words + command-injection patterns + hidden Base64 payloads
        // found in the URL path/query/fragment or filename. Same scaling
        // pattern as the domain/TLD/HostList checks above: a 0-100 score
        // scaled through HOST_STAGING_BASE. `meta` carries the command-vs-
        // lure split CombinationScoring's C3/C5 rules need (derived from the
        // signal strings StagingCheck.js already produces, not re-scanned).
        if (stagingKeywords && stagingKeywords.score > 0) {
            const baseScore = Math.round((stagingKeywords.score / 100) * SCORING_CONFIG.HOST_STAGING_BASE);
            const topSignal = (stagingKeywords.signals && stagingKeywords.signals[0]) || "Staging-stage lure/command pattern";
            const signals   = stagingKeywords.signals || [];
            results.push({
                score:  Math.max(SCORING_CONFIG.SCORE_FLOOR, baseScore),
                label:  `Possible malware staging signal: ${topSignal}`,
                source: "StagingKeywords",
                meta: {
                    hasCommandSignal: signals.some(s => s.includes("Command pattern") || s.includes("hidden in Base64")),
                    hasLureSignal:    signals.some(s => s.includes("Lure word group")),
                }
            });
        }

        // ── Check 19: Staging file format (StagingCheck.checkFormat — v2.8.0) ─
        // Each tier maps directly to its own fixed score — not a 0-100 value
        // to scale, so no rdapAdditive combination here (same direct-score
        // pattern as Check 10 RiskyHosting below).
        if (stagingFormat) {
            const tierScore = {
                HIGH:               SCORING_CONFIG.STAGING_FORMAT_HIGH,
                MED:                SCORING_CONFIG.STAGING_FORMAT_MED,
                CONTAINER_SMALL:    SCORING_CONFIG.STAGING_CONTAINER_SMALL,
                CONTAINER_UNKNOWN:  SCORING_CONFIG.STAGING_CONTAINER_UNKNOWN,
            }[stagingFormat.tier];
            if (tierScore !== undefined) {
                results.push({
                    score:  tierScore,
                    label:  stagingFormat.label,
                    source: "StagingFormat"
                });
            }
        }

        // ── Check 5: Sketchy URL pattern heuristics ──────────────────────────
        if (sketchyUrl && sketchyUrl.score > 0) {
            const baseScore = Math.round((sketchyUrl.score / 100) * SCORING_CONFIG.HOST_SKETCHY_URL_BASE);
            const topSignal = (sketchyUrl.signals && sketchyUrl.signals[0]) || "Suspicious URL pattern";
            // Strip the score suffix from signal text e.g. "(+20)" or "(+15)"
            const cleanSignal = topSignal.replace(/\s*\(\+\d+\).*$/, "").trim();
            results.push({
                score:  Math.max(SCORING_CONFIG.SCORE_FLOOR, baseScore),
                label:  `Suspicious URL pattern: ${cleanSignal}`,
                source: "SketchyUrl"
            });
        }

        // ── Check 6: MIME type consistency ───────────────────────────────────
        if (mimeResult && !mimeResult.neutral) {
            if (mimeResult.score < 0) {
                results.push({
                    score:  Math.max(SCORING_CONFIG.SCORE_FLOOR, mimeResult.score),
                    label:  `File extension ".${mimeResult.ext || ""}" does not match MIME type "${mimeResult.mime || ""}"`,
                    source: "MimeCheck"
                });
            }
            // Consistent result (score 0) — added as informational after scoring
        }

        // ── Check 7: File size vs VirusTotal maximum ──────────────────────────
        // 4.5.8: skipped for a huge Check-26 file — its own signal already says "too big to be scanned".
        if (sizeResult && sizeResult.exceeds && sizeTier !== BINARY_SIZE_TIER.HUGE) {
            results.push({
                score:  sizeResult.score,
                label:  "File size exceeds scan maximum, only use if you are 100% certain it is safe",
                source: "SizeCheck"
            });
        }

        // ── Check 8: HTTP protocol ───────────────────────────────────────────
        // Only penalise when a configured DNS check confirms the domain
        // resolves (ALLOWED). If blocked or unknown, other signals already
        // cover the risk.
        if (isHttp && dnsResolved) {
            results.push({
                score:  SCORING_CONFIG.HTTP_PENALTY,
                label:  "Download served over unencrypted HTTP (not HTTPS)",
                source: "ProtocolCheck"
            });
        }

        // ── Check 9: IP address as download host ──────────────────────────────
        // Covers IPv4, IPv6, and noncanonical IPv4 (see isIpv4Host/isIpv6Host
        // derivation above) — DS-H005.
        if (isIpHost) {
            results.push({
                score:  SCORING_CONFIG.IP_HOST_PENALTY,
                label:  `Download hosted directly on an IP address (${hostname}) rather than a normal domain`,
                source: "IpAddressCheck"
            });
        }

        // ── Check 13: HTTPS-to-HTTP redirect downgrade ─────────────────────────
        // DS-H006 — the download began on an encrypted connection but the
        // final URL is unencrypted HTTP, implying a redirect stripped TLS.
        if (isHttpsToHttpDowngrade) {
            results.push({
                score:  SCORING_CONFIG.HTTPS_DOWNGRADE_SCORE,
                label:  "Download was redirected from an encrypted HTTPS connection to an unencrypted HTTP connection",
                source: "ProtocolDowngrade"
            });
        }

        // ── Check 15: URL contains embedded credentials ────────────────────────
        // DS-H004 — e.g. https://trusted.example@evil.example/file — the text
        // before "@" can be crafted to look like a trusted host while
        // hostname (the actual destination) is something else.
        if (hasUrlCredentials) {
            results.push({
                score:  SCORING_CONFIG.URL_CREDENTIALS_SCORE,
                label:  `Download URL contains embedded credentials — the actual destination is "${hostname}"`,
                source: "UrlCredentials"
            });
        }

        // ── Check 16: Linux desktop launcher file ───────────────────────────────
        // DS-H001 — a .desktop file can define an Exec= line that runs an
        // arbitrary shell command when opened.
        if (isLinuxLauncher) {
            results.push({
                score:  SCORING_CONFIG.LINUX_LAUNCHER_SCORE,
                label:  "This file is a Linux desktop launcher and may execute a command when opened",
                source: "LinuxLauncher"
            });
        }

        // ── Check 10: Risky hosting platform ─────────────────────────────────
        if (riskyHosting) {
            results.push({
                score:  riskyHosting.score,
                label:  riskyHosting.label,
                source: "RiskyHosting"
            });
        }

        // ── Check 11: Script format (LOLBin-style interpreted scripts) ────────
        // A download that is a raw script (.ps1, .vbs, .sh, .py, etc.) rather
        // than a compiled binary is a meaningful anomaly: legitimate software
        // distribution overwhelmingly ships compiled installers, not bare
        // scripts. Scripts execute via a trusted system interpreter (LOLBin
        // technique), which is a common malware delivery and evasion pattern.
        // -25: notable signal on its own, but not enough alone to reach the
        // "probably malicious" threshold (-60) since legitimate scripts
        // (setup.sh, install.py, dev tooling) do exist.
        if (isScript) {
            results.push({
                score:  SCORING_CONFIG.SCRIPT_FORMAT_SCORE,
                label:  "The download is a script, not a program — this is suspicious",
                source: "ScriptFormat"
            });
        }

        // ── Check 12: Extension obfuscation ───────────────────────────────────
        // Fires when the confirmed extension (onChanged) reveals danger that was
        // hidden at download-creation time (onCreated). Two tiers:
        //   UNKNOWN_REVEALED  : no extension was detectable at creation; the
        //                       server actively concealed what it was serving.
        //   CATEGORY_CHANGED  : an extension was known but switched risk category
        //                       (e.g. archive → executable) after redirect/rename.
        if (obfuscation) {
            if (obfuscation.type === "UNKNOWN_REVEALED") {
                // v3.5.0: own source/family (HiddenExtension → DELIVERY, a ROUTE
                // question) — a missing extension in the link is how many
                // vendors deliver, unlike a disguised one (CATEGORY_CHANGED).
                results.push({
                    score:  SCORING_CONFIG.OBFUSCATION_UNKNOWN_SCORE,
                    label:  `Dangerous file type (.${obfuscation.confirmedExt}) was hidden — no extension visible at download start`,
                    source: "HiddenExtension"
                });
            } else if (obfuscation.type === "CATEGORY_CHANGED") {
                results.push({
                    score:  SCORING_CONFIG.OBFUSCATION_CATEGORY_CHANGE_SCORE,
                    label:  `File type category changed from ${obfuscation.fromCategory} (.${obfuscation.originalExt}) to ${obfuscation.toCategory} (.${obfuscation.confirmedExt})`,
                    source: "Obfuscation"
                });
            }
        }

        // ── Check 14: Deceptive extension chain ─────────────────────────────────
        // e.g. invoice.pdf.exe, invoice.pdf.zip.exe — a dangerous extension
        // hidden behind one or more decoy extensions. Virtually never seen in
        // legitimate software. High-confidence signal. DS-H003 generalized
        // this from a strict "last two labels" check to the full chain.
        if (doubleExt) {
            const repeatedDotsNote = doubleExt.repeatedDots
                ? " (with repeated or empty extension segments)" : "";
            results.push({
                score:  SCORING_CONFIG.DOUBLE_EXTENSION_SCORE,
                label:  `The filename contains a misleading extension chain${repeatedDotsNote}: "${doubleExt.decoy}" hiding ".${doubleExt.dangerous}"`,
                source: "DoubleExtension"
            });
        }

        // ── Check 26: Extensionless generic binary (v3.4.0, heuristic R1) ──────
        // The download shows no extension anywhere and the server only says
        // "some bytes" (DangerousMimes.GENERIC_BINARY_MIMES) — what it really
        // is stays hidden until it is opened. See SCORING_CONFIG.
        // EXTENSIONLESS_BINARY_SCORE for the weight's rationale.
        // 3P Matrix 4.5.6/4.5.8: from a file-sharing host (riskyHosting), a large (≥ LARGE_…_MIN_BYTES) or huge
        // (≥ HUGE_…_MIN_BYTES) file gets the heavier score and a label that says why — extensionlessSizeTier().
        if (sizeTier !== BINARY_SIZE_TIER.NONE) {
            const mb = Math.round(totalBytes / SCORING_CONFIG.BYTES_PER_MB);
            const tierSignal = {
                [BINARY_SIZE_TIER.HUGE]:   { score: SCORING_CONFIG.HUGE_EXTENSIONLESS_BINARY_SCORE,
                                             label: `Very large file (${mb} MB) with no extension from a file-sharing site — large downloads are often used by malware to evade AV detection` },
                [BINARY_SIZE_TIER.LARGE]:  { score: SCORING_CONFIG.LARGE_EXTENSIONLESS_BINARY_SCORE,
                                             label: `Large file (${mb} MB) with no extension from a file-sharing site — often padded or packed malware` },
                [BINARY_SIZE_TIER.NORMAL]: { score: SCORING_CONFIG.EXTENSIONLESS_BINARY_SCORE,
                                             label: "The file has no extension and the server does not say what it is (generic binary)" }
            }[sizeTier];
            results.push({ ...tierSignal, source: "ExtensionlessBinary" });
        }

        // ── Checks 21-25: Filename/URL heuristics (heuristics plan Step 5, v2.11.0;
        // check 23 replaced in v3.2.0 — see below) ──────────────────────────────
        // See protection/FilenameUrlHeuristics.js for checks 21/22/24/25's full
        // detection detail and the tab-origin sub-feature that was dropped
        // rather than forced in unreliable.
        const rloSignal = FilenameUrlHeuristics.checkRlo(filename, url);
        if (rloSignal) {
            results.push({
                score:  SCORING_CONFIG.RLO_SCORE,
                label:  rloSignal.label,
                source: "RloObfuscation"
            });
        }

        const paddedDoubleExt = FilenameUrlHeuristics.checkPaddedDoubleExtension(filename);
        if (paddedDoubleExt) {
            results.push({
                score:  SCORING_CONFIG.PADDED_DOUBLE_EXTENSION_SCORE,
                label:  `The filename contains a padded extension chain: "${paddedDoubleExt.decoy}" followed by ${paddedDoubleExt.paddingLength} padding characters hiding ".${paddedDoubleExt.dangerous}"`,
                source: "PaddedDoubleExtension"
            });
        }

        // Check 23 — look-alike/imitation-character domain check (v3.2.0, 3P
        // Matrix alignment §1). Replaces checkBrandHomoglyph()/
        // checkLookalikeTopSite() with one unified check
        // (LookalikeDomainCheck.check()), run against BOTH the final URL's
        // host and — when its registered domain differs — the original
        // (pre-redirect) URL's host too, keeping whichever result is worse.
        // Same "worse of two hosts" pattern BrowserProtection.js's DNS checks
        // already use (see its worseDns() helper) for exactly the same
        // reason: a redirect chain can land on a clean final host while the
        // originally-requested host was itself the imitation.
        //
        // LOOKALIKE_RANK below orders the two possible hit types so "worse"
        // is a simple numeric comparison — lower rank wins. A brand-list
        // match outranks a top-sites-only match (see SCORING_CONFIG's
        // LOOKALIKE_BRAND_SCORE/LOOKALIKE_SITE_SCORE comments for why); "no
        // match" is never worse than a match, so it has no rank entry at all.
        const LOOKALIKE_RANK = Object.freeze({ brand: 0, site: 1 });

        const originalHostname = parsedOriginalUrl ? (UrlUtils.getHostname(originalUrl) || "") : "";
        const finalRegisteredDomain    = hostname        ? UrlUtils.getRegisteredDomain(hostname)        : null;
        const originalRegisteredDomain = originalHostname ? UrlUtils.getRegisteredDomain(originalHostname) : null;

        let lookalikeHit = hostname ? LookalikeDomainCheck.check(hostname) : null;
        if (lookalikeHit) lookalikeHit = { ...lookalikeHit, hostname };

        if (originalHostname && originalRegisteredDomain && originalRegisteredDomain !== finalRegisteredDomain) {
            const originalHit = LookalikeDomainCheck.check(originalHostname);
            if (originalHit && (!lookalikeHit || LOOKALIKE_RANK[originalHit.type] < LOOKALIKE_RANK[lookalikeHit.type])) {
                lookalikeHit = { ...originalHit, hostname: originalHostname };
            }
        }

        if (lookalikeHit) {
            const isBrand = lookalikeHit.type === "brand";
            results.push({
                score:  isBrand ? SCORING_CONFIG.LOOKALIKE_BRAND_SCORE : SCORING_CONFIG.LOOKALIKE_SITE_SCORE,
                label:  isBrand
                    ? `Host "${lookalikeHit.hostname}" closely resembles the brand "${lookalikeHit.keyword}" (${lookalikeHit.resembles}) via imitation-character substitution`
                    : `Host "${lookalikeHit.hostname}" closely resembles the popular site "${lookalikeHit.resembles}" via imitation-character substitution`,
                source: "LookalikeDomain"
            });
        }

        const urlShortener = FilenameUrlHeuristics.checkUrlShortener(hostname);
        if (urlShortener) {
            results.push({
                score:  SCORING_CONFIG.URL_SHORTENER_SCORE,
                label:  `Download host "${urlShortener.matchedShortener}" is a known URL-shortener service`,
                source: "UrlShortener"
            });
        }

        const referrerMismatch = FilenameUrlHeuristics.checkReferrerMismatch(referrer, url);
        if (referrerMismatch) {
            results.push({
                score:  SCORING_CONFIG.REFERRER_MISMATCH_SCORE,
                label:  `Download referrer ("${referrerMismatch.referrerHost}") is unrelated to the download host ("${referrerMismatch.finalHost}")`,
                source: "ReferrerMismatch"
            });
        }

        // ── Check 28: brand name on an open platform (v3.5.2) ─────────────────
        // e.g. a download from paypal-login.vercel.app — impersonation on a
        // platform where anyone can publish (moved from 3P Matrix's site check
        // into the shared engine, so downloads and sites score it the same).
        // Platform = the RiskyHosting host, or a DomainList hit on an
        // OPEN_PLATFORMS domain (util/DeliveryPatterns.js).
        const platformDomain = (riskyHosting && riskyHosting.host)
            || (domainHit && DeliveryPatterns.isOpenPlatform(domainHit.matchedDomain) ? domainHit.matchedDomain : null);
        const platformBrand = platformDomain ? DeliveryPatterns.brandOnPlatform(hostname, platformDomain) : null;
        if (platformBrand) {
            results.push({
                score:  SCORING_CONFIG.LOOKALIKE_SITE_SCORE,
                label:  `Uses the brand name "${platformBrand.keyword}" on a platform where anyone can publish (${platformDomain})`,
                source: "PlatformBrand"
            });
        }

        // ── Check 27: link opened from webmail / chat (v3.5.0) ────────────────
        const messageOrigin = DeliveryPatterns.messageOriginOf(referrer)
            || (originalUrl && originalUrl !== url ? DeliveryPatterns.messageOriginOf(originalUrl) : null);
        if (messageOrigin) {
            results.push({
                score:  SCORING_CONFIG.MESSAGE_ORIGIN_SCORE,
                label:  `The download link was opened from a webmail or chat page (${messageOrigin})`,
                source: "MessageOrigin"
            });
        }

        // ── Delivery context (v3.5.0) ──────────────────────────────────────────
        // Explain recognised delivery patterns, add the weak-signal cluster —
        // see protection/DeliveryContext.js. `scoring` is what is combined from
        // here on; `display` (explained entries at 0 with their reason) is what
        // the breakdown shows.
        const context = DeliveryContext.apply({ results, url, originalUrl, fpLevel });
        results.length = 0;
        results.push(...context.scoring);
        const display = context.display;

        if (!results.some(r => r.score < 0)) {
            // No negative signal left (none at all, or every one explained) —
            // report as Probably Clean, still listing what was explained.
            if (display.length > 0) {
                return {
                    score:           0,
                    classification:  Classification.PROBABLY_SAFE,
                    label:           "Only ordinary delivery details found — probably safe",
                    hardRuleApplied: null,
                    breakdown:       [...display].sort((a, b) => a.score - b.score)
                };
            }
        }

        if (results.length === 0) {
            // All checks passed with no negative signals — report as Probably Clean.
            // Score 0 maps to PROBABLY_QUESTIONABLE by threshold, so we override
            // the classification directly to PROBABLY_SAFE here.
            return {
                score:           0,
                classification:  Classification.PROBABLY_SAFE,
                label:           "No alarming signals found — domain probably safe",
                hardRuleApplied: null,
                breakdown:       []
            };
        }

        // ── v3.5.6: two verdicts from the same signals ──────────────────────
        // `verdict(false)` — VirusTotal knows the file: small signals never stack
        // (the result's top level, exactly as before v3.5.6).
        // `verdict(true)`  — heuristics are the only indicator (VirusTotal does not
        // know the file, or there is none): small signals stack on a dubious
        // source (CombinationScoring.smallSignalsStack). Returned as
        // `heuristicsOnly`; hostVerdict() picks the one that applies.
        // Each verdict works on its own copies — `results`/`display` are never mutated.
        const parsedHttps = !!(parsedUrl && parsedUrl.protocol === "https:");
        const topSite = TopSitesFilter.mightBeTopSite(UrlUtils.getRegisteredDomain(hostname));
        function verdict(heuristicsOnly) {
            // ── Check 10b: RiskyHosting solo mitigation ──────────────────────────
            // "This host is just a cheap/free hosting platform" is weaker
            // evidence alone than when something else about the download also
            // looks wrong. Halve RiskyHosting's score when it is the only
            // signal present strong enough to stack with anything on its own
            // (CombinationScoring.canStack(score, false) — v3.5.6: a small signal
            // that only stacks because the source is dubious does not count as
            // corroboration; user decision, FP sweep 7-Zip via SourceForge).
            // Reusing that one test — rather than hand-picking which other checks
            // "count" — keeps this from becoming an arbitrary, hard-coded short list.
            // Skipped entirely when a DNS threat-intel block already fired: that hard rule
            // overrides everything below it regardless.
            const original = results.find(r => r.source === "RiskyHosting");
            let scoring = results;
            let shown = display;
            if (original) {
                const corroborated = results.some(r =>
                    r !== original && (CombinationScoring.canStack(r.score, false)
                        || (r.score < 0 && SCORING_CONFIG.RISKY_HOSTING_CORROBORATING_SOURCES.includes(r.source))));
                if (!corroborated) {
                    const halved = { ...original,
                        score: Math.round(original.score / SCORING_CONFIG.RISKY_HOSTING_SOLO_DIVISOR),
                        label: original.label + " (no other corroborating signal, so halved)" };
                    scoring = results.map(r => (r === original ? halved : r));
                    shown   = display.map(r => (r === original ? halved : r));
                }
            }

            // A DNS threat-intel block is always Probably Malicious regardless of
            // any other signal (Step 3 algorithm, step 1) — short-circuits before
            // combination runs at all; it isn't part of any family.
            const dnsHit = scoring.find(r => r.source === "DnsThreat" && r.score === SCORING_CONFIG.DNS_BLOCKED_SCORE);

            let worst, hardRule;
            if (dnsHit) {
                worst    = dnsHit;
                hardRule = dnsHit.label;
            } else {
                // v2.9.0 (Step 3): combine every signal gathered above instead of
                // "worst single signal wins" (see this file's header comment,
                // check 20, and CombinationScoring.js for the full algorithm).
                // The breakdown list below is unaffected — every individual
                // signal still shows its own, uncombined score.
                worst    = CombinationScoring.combineHostResults(scoring, { heuristicsOnly });
                hardRule = null;
            }

            // ── Established-site credit (v3.5.0) — after combination, never with a
            // hard rule; DeliveryContext.creditFor() decides whether it applies.
            let finalScore = worst.score;
            const shownAll = [...shown];
            if (!hardRule) {
                const credit = DeliveryContext.creditFor({
                    scoring, url, isHttps: parsedHttps, dnsResolved, fpLevel, isTopSite: topSite,
                });
                if (credit) {
                    finalScore = Math.min(finalScore + credit.score, credit.score);
                    shownAll.push(credit);
                }
            }

            const classification = hardRule
                ? Classification.PROBABLY_MALICIOUS
                : classifyByScore(finalScore);

            const hostLabel = hardRule
                ? hardRule
                // Plain signal count, nothing about combining/independence or VT —
                // the old "N independent risk signals combined" wording read as a
                // claim about VirusTotal agreement, which this has nothing to do
                // with (VT is evaluated entirely separately; see evaluate() below).
                // v3.5.0: count AND verdict, from the actual classification — the
                // combined case used to show only the count (no verdict), and the
                // single-signal case always said "probably suspicious", even when
                // the score was only inconclusive.
                : heuristicLabel(worst.signalCount, classification);

            // Breakdown display order: most negative first. The old LAST_SOURCES
            // de-prioritization (SketchyUrl/IpAddressCheck/ProtocolCheck/
            // RiskyHosting shown last regardless of score) is superseded by
            // Step 3's family grouping, which already treats those sources as
            // full peers of whatever else is in their family — nothing special
            // left to de-prioritize.
            const breakdown = shownAll.sort((a, b) => a.score - b.score);

            return {
                score:           finalScore,
                classification,
                label:           hostLabel,
                hardRuleApplied: hardRule,
                breakdown
            };
        }

        return { ...verdict(false), heuristicsOnly: verdict(true) };
    }

    /**
     * v3.5.6 — the host verdict that applies once VirusTotal's answer is in:
     * VirusTotal unknown → the heuristics-only verdict (small signals stack on a
     * dubious source), otherwise the result's own top level. A result without a
     * `heuristicsOnly` part (an early "nothing found" return) is its own verdict.
     * Fields a caller added next to the engine's own (dnsChecks, rdap …) are kept.
     *
     * @param {object|null} hostResult - evaluateHostReputation() result (or a floored copy)
     * @param {boolean} vtUnknown
     * @returns {object|null} { score, classification, label, hardRuleApplied, breakdown }
     */
    function hostVerdict(hostResult, vtUnknown) {
        if (!hostResult) return null;
        const { heuristicsOnly, ...vtKnown } = hostResult;
        return vtUnknown && heuristicsOnly ? { ...vtKnown, ...heuristicsOnly } : vtKnown;
    }

    // =========================================================================
    // A.  VirusTotal URL Evaluation  (public — called by BrowserProtection)
    // =========================================================================

    /**
     * Evaluate VT analysis results.
     * Weights: detection 70 %, age 30 %.  Community removed.
     */
    function evaluate({
        stats               = {},
        rawStats            = null,
        firstSubmissionDate = null,
        fpLevel             = "NONE"
    } = {}) {

        const safeStats  = (stats !== null && typeof stats === "object") ? stats : {};
        const malicious  = safeStats.malicious  ?? 0;
        const suspicious = safeStats.suspicious ?? 0;

        const age = scoreVtAge(firstSubmissionDate);

        // ── ABC consensus bonus ───────────────────────────────────────────────
        // Rewards a strong clean consensus across responding VT engines.
        // Percentage-based: cleanCount / (cleanCount + suspicious + malicious)
        // so 21/21 = 100% regardless of how many engines total responded.
        //
        // Hard block — bonus cannot fire when:
        //   • URL first seen at VT < 7 days ago  (too new to trust consensus)
        //   • Any engine at the current FP level flagged suspicious or malicious
        //
        // Cut-offs:    A ≥ 90% → +30,  B ≥ 70% → +20,  C ≥ 50% → +10
        const cleanCount     = (safeStats.harmless || 0) + (safeStats.undetected || 0);
        const respondedCount = cleanCount + (safeStats.suspicious || 0) + (safeStats.malicious || 0);
        const cleanPct       = respondedCount > 0 ? (cleanCount / respondedCount) * 100 : 0;
        const vtTooNew       = age.ageDays !== null && age.ageDays < SCORING_CONFIG.ABC_MIN_DAYS;

        let abcBonus = 0;
        let abcLabel = null;
        if (cleanCount > 0 && malicious === 0 && suspicious === 0 && !vtTooNew) {
            if      (cleanPct >= SCORING_CONFIG.ABC_A_PCT) { abcBonus = SCORING_CONFIG.ABC_A_BONUS; abcLabel = "A"; }
            else if (cleanPct >= SCORING_CONFIG.ABC_B_PCT) { abcBonus = SCORING_CONFIG.ABC_B_BONUS; abcLabel = "B"; }
            else if (cleanPct >= SCORING_CONFIG.ABC_C_PCT) { abcBonus = SCORING_CONFIG.ABC_C_BONUS; abcLabel = "C"; }
        }

        const detection = scoreDetection(safeStats, age.ageDays, abcBonus);

        // VT score = detection score + age score — simple addition, no weighting.
        // Age influence comes through two clean mechanisms:
        //   1. Longevity bonus inside scoreDetection (+10 at >7 days, +30 at >30 days)
        //   2. Age penalty here (−10 at 2–7 days, −20 at <2 days)
        //   3. ABC hard block prevents bonus firing when first seen < 7 days
        // The old 70/30 weighted split is removed — it was redundant with the
        // longevity bonus already baked into detection.
        const total = Math.max(SCORING_CONFIG.SCORE_FLOOR, Math.min(SCORING_CONFIG.SCORE_CEILING, detection.score + age.score));

        const hardRule       = applyHardRules(malicious, suspicious);
        const classification = hardRule ? hardRule.classification : classifyByScore(total);

        return {
            classification,
            score:           total,
            confidence:      computeVtConfidence(age.ageDays),
            hardRuleApplied: hardRule?.reason ?? null,
            breakdown:       { detection: { ...detection, abcLabel }, age },
            rawStats:        rawStats || safeStats,
            filteredStats:   safeStats,
            fpLevel
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Compose the full "count votes → filter → score" sequence from a raw VT
    // last_analysis_results object. Shared by background.js and
    // BrowserProtection.js, which previously ran this identical 3-call
    // sequence (FpReductionEngines.getRawStats → .filterResults →
    // ScoringEngineV2.evaluate) independently (jscpd-flagged duplicate, audit
    // pass). No behavior change — same three calls, same order, same inputs.
    //
    // Returns { eval, raw, filtered } — matches the shape both call sites
    // already used.
    // ─────────────────────────────────────────────────────────────────────────
    function evaluateFromAnalysisResults(results, fpLevel, firstSubmissionDate) {
        const raw      = FpReductionEngines.getRawStats(results);
        const filtered = FpReductionEngines.filterResults(results, fpLevel);
        const evalResult = evaluate({
            stats:               filtered,
            rawStats:            raw,
            firstSubmissionDate: firstSubmissionDate ?? null,
            fpLevel
        });
        return { eval: evalResult, raw, filtered };
    }

    // ─────────────────────────────────────────────────────────────────────────
    return {
        Classification,
        evaluate,
        evaluateFromAnalysisResults,
        evaluateHostReputation,
        scaleHostScoreForUnknownVt,
        hostVerdict,       // v3.5.6
        classifyByScore,
        heuristicLabel
    };

})();
