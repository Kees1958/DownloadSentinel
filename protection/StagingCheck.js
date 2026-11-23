"use strict";

import { SCORING_CONFIG } from "./ScoringEngineV2.js"; // BYTES_PER_MB — 3P Matrix 4.5.8: one byte unit for every size rule

// ── StagingCheck.js ───────────────────────────────────────────────────────────
// Heuristics plan Step 2 (v2.8.0): staging-stage malware-delivery signals.
//
// Scope limit (see the heuristics plan): Download Sentinel never sees file
// contents — chrome.downloads gives no bytes, and re-fetching the file would
// need <all_urls> host permission. "Keywords" here means URL path, query,
// fragment, filename and redirect chain only — never the file itself.
//
// Two independent checks, both pure functions of their arguments (no chrome.*
// access, no shared mutable state — C1/C11):
//
//   checkKeywords({ finalUrl, originalUrl, filename, registeredDomain })
//       2a — lure words + command-injection patterns + hidden Base64 payloads
//       in the URL/filename. Returns { score: 0-100, signals: string[] }
//       (same shape as SketchyUrlCheck.check()).
//
//   checkFormat({ ext, totalBytes, sizeKnown })
//       2b — first-stage staging file formats (Excel add-ins, shortcut
//       formats, disk-image containers) used to bypass Windows'
//       Mark-of-the-Web warning or launch the next stage. Returns
//       { score, label, source: "StagingFormat" } or null when ext isn't a
//       recognised staging format.
//
// Public interface:
//   StagingCheck.checkKeywords(params) — see above
//   StagingCheck.checkFormat(params)   — see above
//
// Dependencies: none (pure string/regex logic only)
//
// State owned: none — all tables (CONFIG, COMMAND_PATTERNS, LURE_GROUPS,
// STAGING_FORMATS) are built once and frozen at module load (B3a/B8 — truly
// stateless constants).
// ─────────────────────────────────────────────────────────────────────────────

export const StagingCheck = (function () {

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIG — every magic number for this module, gathered here (B1).
    // Host-axis scores (HOST_STAGING_BASE, STAGING_FORMAT_*) live in
    // ScoringEngineV2.js's SCORING_CONFIG per project convention — this block
    // holds only this module's own internal tuning.
    // ─────────────────────────────────────────────────────────────────────────
    const CONFIG = Object.freeze({
        MAX_FIELD_LENGTH:      2048,  // cap each input field before any processing (ReDoS/perf guard)
        MAX_DECODE_PASSES:     2,     // percent-decode passes (catches double-encoding like %2520)
        MAX_B64_TOKENS:        3,     // cap Base64 candidate tokens scanned per URL (perf guard)
        HIDDEN_PAYLOAD_BONUS:  20,    // added when a decoded Base64 token itself contains a command pattern
        LURE_MAX:              50,    // cap on summed lure-group weights
        COMPACT_MIN_KEYWORD_LEN: 8,   // only keywords this long or longer are checked against the
                                      // separator-stripped "compact" text (shorter LOLBIN names like
                                      // "mshta"/"pwsh"/"cmstp" produce too many coincidental matches
                                      // once punctuation is stripped)
        MIN_PRINTABLE_RATIO:   0.90,  // decoded Base64 must be ≥ this printable-ASCII ratio to be trusted
        UTF16LE_NULL_RATIO:    0.30,  // ≥ this fraction of 0x00 bytes → treat decoded bytes as UTF-16LE
    });

    // ─────────────────────────────────────────────────────────────────────────
    // Zero-width characters stripped from the normalised `text` field —
    // ZERO WIDTH SPACE/NON-JOINER/JOINER, WORD JOINER, ZERO WIDTH NO-BREAK
    // SPACE (BOM) — a cheap, common evasion for splitting up a keyword.
    // ─────────────────────────────────────────────────────────────────────────
    const ZERO_WIDTH_RE = /[\u200B-\u200D\u2060\uFEFF]/g;

    // ─────────────────────────────────────────────────────────────────────────
    // Command patterns (2a, step 4) — every repetition bounded, no nested
    // quantifiers (ReDoS-safe). Field factor applied separately (see
    // FIELD_FACTOR below); LOLBIN_NAME is query/fragment-only by design (it
    // would otherwise false-positive on a legitimate filename like
    // "PowerShell-7.4.6-win-x64.msi" served from GitHub — see heuristics plan).
    // ─────────────────────────────────────────────────────────────────────────
    const COMMAND_PATTERNS = Object.freeze([
        { id: "ENCODED_PS",    weight: 80, queryFragmentOnly: false,
          re: /(?:^|[\s"'])-(?:e|ec|en|enc|enco|encod|encode|encodedcommand)\s+[a-z0-9+/=]{20,}/ },
        { id: "CRADLE",        weight: 70, queryFragmentOnly: false,
          re: /\b(?:iex|invoke-expression|downloadstring|downloadfile|net\.webclient|invoke-webrequest|frombase64string|start-bitstransfer)\b|\b(?:iwr|irm)\s+https?:/ },
        { id: "PIPE_TO_SHELL", weight: 70, queryFragmentOnly: false,
          re: /\b(?:curl|wget)\b[^|]{0,200}\|\s{0,5}(?:sudo\s+)?(?:ba|z|da|k)?sh\b/ },
        { id: "LOLBIN_ARGS",   weight: 60, queryFragmentOnly: false,
          re: /\bmshta(?:\.exe)?\s+(?:https?|vbscript|javascript):|\bregsvr32\b[^\n]{0,100}\/i:https?:|\bcertutil(?:\.exe)?\b[^\n]{0,100}-(?:urlcache|decode)\b|\bbitsadmin(?:\.exe)?\b[^\n]{0,100}\/transfer\b|\brundll32(?:\.exe)?\s+[^\s,]{1,200},/ },
        { id: "POLICY_BYPASS", weight: 50, queryFragmentOnly: false,
          re: /-(?:ep|exec|executionpolicy)\s+bypass\b|-(?:w|windowstyle)\s+hidden\b|(?:^|\s)-nop(?:rofile)?\b/ },
        { id: "CMD_EXEC",      weight: 40, queryFragmentOnly: false,
          re: /\bcmd(?:\.exe)?\s+\/[ck]\b|\bchmod\s+\+x\b|\bbase64\s+(?:-d|--decode)\b|\bosascript\s+-e\b/ },
        { id: "GATE_PARAM",    weight: 30, queryFragmentOnly: false,
          // (?:^|[?&]) — not just [?&]: extractFields() strips the leading
          // "?" from url.search before this ever sees the query text, so a
          // single-param query like "?cmd=whoami" starts the normalised
          // string directly with "cmd=" (no leading boundary character at
          // all). A [?&]-only anchor silently never matched that extremely
          // common case — found and fixed while writing this module's tests.
          re: /(?:^|[?&])(?:cmd|exec|command|shell|payload)=/ },
        { id: "LOLBIN_NAME",   weight: 30, queryFragmentOnly: true,
          re: /\b(?:powershell|pwsh|mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|msiexec|installutil|msbuild|cmstp|forfiles)\b/ },
    ]);

    // LOLBIN_NAME's literal keyword list, reused for the "compact" (separator-
    // stripped) secondary check — defeats "p.o.w.e.r.s.h.e.l.l" / "power^shell"
    // for keywords long enough that a coincidental substring match in ordinary
    // text is implausible (CONFIG.COMPACT_MIN_KEYWORD_LEN).
    const LOLBIN_NAMES = Object.freeze([
        "powershell", "pwsh", "mshta", "rundll32", "regsvr32", "certutil",
        "bitsadmin", "wscript", "cscript", "msiexec", "installutil",
        "msbuild", "cmstp", "forfiles",
    ].filter(k => k.length >= CONFIG.COMPACT_MIN_KEYWORD_LEN));

    // Field factor — query/fragment ×1.0, path ×0.75, filename ×1.0 (plan Step 2a.4).
    const FIELD_FACTOR = Object.freeze({
        query:    1.0,
        fragment: 1.0,
        path:     0.75,
        filename: 1.0,
    });

    // ─────────────────────────────────────────────────────────────────────────
    // Lure word groups (2a, step 6) — built once at load. S = optional
    // separator (space, dot, underscore, hyphen) inside a multi-word phrase.
    // Deliberately excluded: "setup", "patch", "loader" (too common in
    // legitimate installers — see heuristics plan).
    // ─────────────────────────────────────────────────────────────────────────
    const S = "[\\s._-]?";
    const LURE_GROUPS = Object.freeze([
        {
            id: "FINANCE", weight: 25,
            words: ["invoice", "payment", "remittance", "receipt", "overdue", "statement",
                    "refund", "payroll", "proforma", "quotation",
                    `purchase${S}order`, `wire${S}transfer`, `tax${S}(?:return|form|refund)`],
        },
        {
            id: "DELIVERY", weight: 25,
            words: ["shipment", "shipping", "delivery", "tracking", "waybill", "customs"],
        },
        {
            id: "DOCUMENT", weight: 25,
            words: ["scan(?:ned)?", "voicemail", "fax",
                    `secure${S}(?:doc|document|message)`, "e-?signature"],
        },
        {
            id: "URGENCY", weight: 20,
            words: ["urgent", `final${S}notice`, `action${S}required`, `past${S}due`],
        },
        {
            id: "PIRACY", weight: 35,
            words: ["crack(?:ed)?", "keygen", `key${S}generator`, "activator",
                    "kms(?:pico|auto)", `serial${S}key`, "nulled", "warez",
                    `full${S}version`, `pre${S}activated`],
        },
        {
            id: "GAME_CHEAT", weight: 35,
            words: ["aimbot", "wallhack", "injector", "executor",
                    `mod${S}menu`, `free${S}robux`, "spoofer"],
        },
        {
            id: "FAKE_UPDATE", weight: 45,
            words: [`(?:chrome|browser|firefox|edge|flash|java)${S}(?:update|updater|upgrade)`,
                    "flashplayer", `update${S}(?:required|now|critical)`],
        },
    ].map(group => ({
        ...group,
        // Letter-only lookarounds so "invoice_2026" and "invoice2026" both
        // match (digits/underscores don't count as "still inside the word").
        re: new RegExp(`(?<![a-z])(?:${group.words.join("|")})(?![a-z])`),
    })));

    // FAKE_UPDATE is skipped entirely when the registered domain is one of
    // these — the vendor's own real update mechanism legitimately uses this
    // exact vocabulary (heuristics plan Step 2a.6).
    const FAKE_UPDATE_VENDOR_DOMAINS = Object.freeze(new Set([
        "google.com", "mozilla.org", "microsoft.com", "adobe.com", "java.com", "oracle.com",
    ]));

    // ─────────────────────────────────────────────────────────────────────────
    // Staging file formats (2b) — first-stage formats used to bypass
    // Windows' Mark-of-the-Web warning or launch the next stage. Formats
    // already scored as scripts (lnk, hta, wsf, chm, msc) are excluded here
    // to avoid double counting with SCORING_CONFIG.SCRIPT_FORMAT_SCORE.
    //
    // RESOLVED (v2.8.0, alongside this module's own release — see CHANGELOG):
    // every extension in the FORMATS table below is now also in
    // util/DangerousExts.js's DANGEROUS set, so a bare .xll/.url/.iqy/…
    // download IS gated into the monitored set on its own, not only when
    // served with an already-dangerous/archive MIME type.
    // ─────────────────────────────────────────────────────────────────────────
    const FORMATS = Object.freeze({
        // STAGING_FORMAT_HIGH — Excel add-in, Windows settings shortcut, OneNote
        xll:                 "HIGH",
        "settingcontent-ms": "HIGH",
        one:                 "HIGH",
        onepkg:              "HIGH",
        // STAGING_FORMAT_MED — shortcuts, query files, ClickOnce
        url:                 "MED",
        iqy:                 "MED",
        slk:                 "MED",
        "library-ms":        "MED",
        "search-ms":         "MED",
        "appref-ms":         "MED",
        application:         "MED",
        diagcab:             "MED",
    });

    // Disk-image/container extensions sized against the small-container
    // threshold (CONTAINER_SMALL_BYTES) — these ARE already in
    // util/DangerousExts.js's ARCHIVE set, so this half of the check is live
    // today with no DangerousExts change needed.
    const CONTAINER_EXTS = Object.freeze(new Set(["iso", "img", "vhd", "vhdx"]));
    const CONTAINER_SMALL_BYTES = 100 * SCORING_CONFIG.BYTES_PER_MB; // real OS images are ≥ 300 MB; staging images a few MB

    // ─────────────────────────────────────────────────────────────────────────
    // Normalisation helpers (2a, steps 2-3)
    // ─────────────────────────────────────────────────────────────────────────

    /** Percent-decode up to CONFIG.MAX_DECODE_PASSES times, each in try/catch. */
    function percentDecode(input) {
        let s = input.replace(/\+/g, " ");
        for (let i = 0; i < CONFIG.MAX_DECODE_PASSES; i++) {
            let decoded;
            try { decoded = decodeURIComponent(s); }
            catch { break; } // malformed percent sequence — stop, keep what we have
            if (decoded === s) break; // nothing further to decode
            s = decoded;
        }
        return s;
    }

    /**
     * Build the three normalised forms of one input field.
     * @returns {{ raw: string, text: string, compact: string }}
     */
    function normaliseField(input) {
        const capped  = (input || "").slice(0, CONFIG.MAX_FIELD_LENGTH);
        const raw     = capped; // original case, kept for Base64 token scanning
        const decoded = percentDecode(capped);
        const text    = decoded.normalize("NFKC").toLowerCase().replace(ZERO_WIDTH_RE, "");
        const compact = text.replace(/[^a-z0-9]/g, "");
        return { raw, text, compact };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // URL field extraction — path, query, fragment (hostname excluded;
    // other checks already cover it).
    // ─────────────────────────────────────────────────────────────────────────
    function extractFields(urlString) {
        if (!urlString) return null;
        let url;
        try { url = new URL(urlString); } catch { return null; }
        return {
            path:     url.pathname || "",
            query:    (url.search || "").replace(/^\?/, ""),
            fragment: (url.hash   || "").replace(/^#/, ""),
        };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Command-pattern scan (2a, step 4) — returns the best (highest-weighted)
    // contribution per matched pattern id, plus which ids matched, across all
    // supplied field sources. `sources` is an array of { fieldType, value }
    // where fieldType is one of "query" | "fragment" | "path" | "filename".
    // ─────────────────────────────────────────────────────────────────────────
    function scanCommandPatterns(sources) {
        const hitWeights = new Map(); // pattern id -> best (field-factor-scaled) contribution
        const signals    = [];

        for (const { fieldType, value } of sources) {
            if (!value) continue;
            const { text, compact } = normaliseField(value);
            const factor = FIELD_FACTOR[fieldType];

            for (const pattern of COMMAND_PATTERNS) {
                if (pattern.queryFragmentOnly && fieldType !== "query" && fieldType !== "fragment") continue;
                if (!pattern.re.test(text)) continue;

                const contribution = pattern.weight * factor;
                const existing = hitWeights.get(pattern.id) ?? -Infinity;
                if (contribution > existing) hitWeights.set(pattern.id, contribution);
            }

            // Compact (separator-stripped) secondary check for LOLBIN names —
            // only meaningful in query/fragment, same scope as LOLBIN_NAME itself.
            if (fieldType === "query" || fieldType === "fragment") {
                for (const name of LOLBIN_NAMES) {
                    if (!compact.includes(name)) continue;
                    const contribution = 30 * factor; // same weight as LOLBIN_NAME
                    const existing = hitWeights.get("LOLBIN_NAME") ?? -Infinity;
                    if (contribution > existing) hitWeights.set("LOLBIN_NAME", contribution);
                }
            }
        }

        for (const [id, contribution] of hitWeights) {
            signals.push(`Command pattern: ${id} (+${Math.round(contribution)})`);
        }

        return { hitWeights, signals };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Hidden Base64 payload scan (2a, step 5)
    // ─────────────────────────────────────────────────────────────────────────
    const B64_TOKEN_RE = /[A-Za-z0-9+/_-]{40,4096}={0,2}/g;

    function decodeBase64Token(token) {
        const normalised = token.replace(/-/g, "+").replace(/_/g, "/");
        let binary;
        try { binary = atob(normalised); }
        catch { return null; }

        let bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

        const nullCount = bytes.reduce((n, b) => n + (b === 0 ? 1 : 0), 0);
        if (bytes.length > 0 && (nullCount / bytes.length) >= CONFIG.UTF16LE_NULL_RATIO) {
            // Treat as UTF-16LE (PowerShell -enc format) — strip zero bytes
            bytes = bytes.filter(b => b !== 0);
        }

        let printable = 0;
        let decodedStr = "";
        for (const b of bytes) {
            decodedStr += String.fromCharCode(b);
            if (b === 9 || b === 10 || b === 13 || (b >= 0x20 && b <= 0x7e)) printable++;
        }
        if (bytes.length === 0 || (printable / bytes.length) < CONFIG.MIN_PRINTABLE_RATIO) return null;

        return decodedStr;
    }

    /**
     * Scan `raw` text for Base64-looking tokens, decode each (bounded by
     * CONFIG.MAX_B64_TOKENS), and re-run the command-pattern scan on any that
     * decode to plausible, mostly-printable text.
     */
    function scanHiddenPayloads(rawSources) {
        let bonus = 0;
        const signals = [];

        let tokensChecked = 0;
        for (const { value } of rawSources) {
            if (!value || tokensChecked >= CONFIG.MAX_B64_TOKENS) break;
            const tokens = value.match(B64_TOKEN_RE) || [];
            for (const token of tokens) {
                if (tokensChecked >= CONFIG.MAX_B64_TOKENS) break;
                tokensChecked++;

                const decoded = decodeBase64Token(token);
                if (decoded === null) continue;

                const { hitWeights } = scanCommandPatterns([{ fieldType: "query", value: decoded }]);
                if (hitWeights.size > 0) {
                    bonus = CONFIG.HIDDEN_PAYLOAD_BONUS;
                    signals.push(`Command hidden in Base64 (+${CONFIG.HIDDEN_PAYLOAD_BONUS})`);
                    break; // one bonus per URL, no stacking
                }
            }
            if (bonus > 0) break;
        }

        return { bonus, signals };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lure word scan (2a, step 6) — filename + path fields only.
    // ─────────────────────────────────────────────────────────────────────────
    function scanLureWords(sources, registeredDomain) {
        const hitGroups = new Set();
        const signals    = [];

        for (const { value } of sources) {
            if (!value) continue;
            const { text } = normaliseField(value);

            for (const group of LURE_GROUPS) {
                if (hitGroups.has(group.id)) continue; // already counted (distinct groups only)
                if (group.id === "FAKE_UPDATE" && registeredDomain && FAKE_UPDATE_VENDOR_DOMAINS.has(registeredDomain)) continue;
                if (group.re.test(text)) {
                    hitGroups.add(group.id);
                    signals.push(`Lure word group: ${group.id} (+${group.weight})`);
                }
            }
        }

        return { hitGroups, signals };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public: checkKeywords (2a) — full algorithm, steps 1-8.
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @param {object} params
     * @param {string} params.finalUrl        - the actual download URL
     * @param {string|null} params.originalUrl - pre-redirect URL (omit/pass same as finalUrl if none)
     * @param {string} params.filename        - confirmed or suggested filename
     * @param {string|null} params.registeredDomain - final URL's registered domain (FAKE_UPDATE exception)
     * @param {string} params.fileCategory    - "executable" | "script" | "staging" | "archive" | "other"
     *        — controls lure-word weighting (full for executable/script/staging, ×0.6 for archive, 0 otherwise)
     * @returns {{ score: number, signals: string[] }}
     */
    function checkKeywords({ finalUrl, originalUrl = null, filename = "", registeredDomain = null, fileCategory = "other" }) {
        const finalFields    = extractFields(finalUrl);
        const originalFields = (originalUrl && originalUrl !== finalUrl) ? extractFields(originalUrl) : null;

        const commandSources = [];
        const lureSources     = [];
        const rawSources      = [];

        if (filename) {
            commandSources.push({ fieldType: "filename", value: filename });
            lureSources.push({ value: filename });
            rawSources.push({ value: filename });
        }
        for (const fields of [finalFields, originalFields]) {
            if (!fields) continue;
            commandSources.push({ fieldType: "path",     value: fields.path });
            commandSources.push({ fieldType: "query",    value: fields.query });
            commandSources.push({ fieldType: "fragment", value: fields.fragment });
            lureSources.push({ value: fields.path });
            rawSources.push({ value: fields.path }, { value: fields.query }, { value: fields.fragment });
        }

        const { hitWeights, signals: commandSignals } = scanCommandPatterns(commandSources);
        const { bonus: payloadBonus, signals: payloadSignals } = scanHiddenPayloads(rawSources);

        let lureMultiplier = 0;
        if (fileCategory === "executable" || fileCategory === "script" || fileCategory === "staging") lureMultiplier = 1.0;
        else if (fileCategory === "archive") lureMultiplier = 0.6;

        const { hitGroups, signals: lureSignalsRaw } = lureMultiplier > 0
            ? scanLureWords(lureSources, registeredDomain)
            : { hitGroups: new Set(), signals: [] };

        // ── Combine (step 7) ───────────────────────────────────────────────
        const commandWeights = [...hitWeights.values()];
        const maxCommand     = commandWeights.length > 0 ? Math.max(...commandWeights) : 0;
        const otherGroups    = Math.max(0, hitWeights.size - 1);
        const command        = Math.min(100, maxCommand + (10 * otherGroups) + payloadBonus);

        const lureGroupWeights = [...hitGroups].map(id => LURE_GROUPS.find(g => g.id === id).weight * lureMultiplier);
        const lure = Math.min(CONFIG.LURE_MAX, lureGroupWeights.reduce((sum, w) => sum + w, 0));

        const score = Math.min(100, Math.round(command + lure));

        const signals = [...commandSignals, ...payloadSignals, ...lureSignalsRaw];

        return { score, signals };
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public: checkFormat (2b)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @param {object} params
     * @param {string} params.ext         - confirmed extension, lowercase, no dot
     * @param {number} params.totalBytes  - reported size in bytes (0 if unknown)
     * @param {boolean} [params.sizeKnown] - true once Chrome has reported a real
     *        size (onChanged) — omit/false at onCreated when size is typically 0
     * @returns {{ tier: string, label: string, source: "StagingFormat" } | null}
     *        `tier` is one of "HIGH" | "MED" | "CONTAINER_SMALL" |
     *        "CONTAINER_UNKNOWN" — the caller (ScoringEngineV2) maps each tier
     *        to its SCORING_CONFIG score.
     */
    function checkFormat({ ext, totalBytes = 0, sizeKnown = false }) {
        if (!ext) return null;

        const formatTier = FORMATS[ext];
        if (formatTier) {
            return {
                tier:  formatTier,
                label: `File format ".${ext}" is a known first-stage staging format`,
                source: "StagingFormat",
            };
        }

        if (CONTAINER_EXTS.has(ext)) {
            if (!sizeKnown || !totalBytes || totalBytes <= 0) {
                return {
                    tier:  "CONTAINER_UNKNOWN",
                    label: `Disk-image container ".${ext}" — size not yet known`,
                    source: "StagingFormat",
                };
            }
            if (totalBytes < CONTAINER_SMALL_BYTES) {
                const mb = (totalBytes / SCORING_CONFIG.BYTES_PER_MB).toFixed(1);
                return {
                    tier:  "CONTAINER_SMALL",
                    label: `Disk-image container ".${ext}" is unusually small (${mb} MB) for a real OS image`,
                    source: "StagingFormat",
                };
            }
            return null; // large container — real OS image, e.g. Ubuntu/Debian ISO
        }

        return null;
    }

    return {
        checkKeywords,
        checkFormat,
        CONFIG,
        FORMATS,
        CONTAINER_EXTS,
        CONTAINER_SMALL_BYTES,
    };

})();
