"use strict";

// ── AppConstants.js ───────────────────────────────────────────────────────────
// Single source of truth for all application-wide magic numbers, limits, and
// timing values that are not specific to the VT scoring algorithm.
//
// Scoring thresholds and VT-analysis weights live in SCORING_CONFIG inside
// ScoringEngineV2.js because they are tightly coupled to the algorithm.
// Everything else — timeouts, collection caps, UI limits — lives here.
//
// Public interface:
//   APP  {Object}  — frozen map of named constants
//
// Dependencies: none
//
// Usage:
//   Service worker:   importScripts("util/AppConstants.js")
//   Page contexts:    <script src="../../util/AppConstants.js">
// ─────────────────────────────────────────────────────────────────────────────

// ── DNS block-style enum (v3.3.1) ─────────────────────────────────────────────
// Single source of truth for HOW a DNS threat-intel resolver says "blocked".
// Declared before APP (APP is one frozen literal and can't reference itself)
// and exposed as APP.DNS_BLOCK_STYLE. Consumed by DNS_PROVIDERS below and by
// protection/DnsThreatProtection.js — never compare against raw strings.
const DNS_BLOCK_STYLE = Object.freeze({
    NXDOMAIN_NO_AUTHORITY: "nxdomain-no-authority", // NXDOMAIN + empty Authority section (Quad9)
    ZERO_IP:               "zero-ip",               // answers 0.0.0.0 / :: (Cloudflare Security, Control D)
    BLOCKPAGE_IP:          "blockpage-ip",          // answers the provider's own block-page IP, listed
                                                    // per provider in `blockPageIps` (DNS4EU); 0.0.0.0 / ::
                                                    // are also treated as blocked for this style
    RPZ_SOA:               "rpz-soa",               // no answer + an Authority SOA whose primary-NS (MNAME)
                                                    // ends in the provider's `rpzSoaMnameSuffix` — the
                                                    // synthetic SOA of a Response Policy Zone (CleanBrowsing)
});

export const APP = Object.freeze({

    // ── VirusTotal ─────────────────────────────────────────────────────────────

    // Single source of truth for VT's "join us" / free-API-key signup page —
    // used by the Options page's own link and by the startup VT-key nudge
    // popup (pages/vtkeyprompt/VtKeyPrompt.js, v3.0.7).
    VT_JOIN_URL: "https://www.virustotal.com/gui/join-us",

    // Fixed size for the VT-key nudge popup window (background.js's
    // openVtKeyPrompt()) — a small dialog, not maximized like the warning
    // page, since it's a short read with two buttons. Height is measured
    // content height (~337px at this width, via headless rendering) plus
    // just enough slack that the empty space below the Ignore/Request
    // buttons never exceeds the buttons' own height (~33px) — any more
    // reads as a visibly oversized window.
    VT_KEY_PROMPT_WINDOW_WIDTH:  520,
    VT_KEY_PROMPT_WINDOW_HEIGHT: 348,

    // ── Timing — service worker ───────────────────────────────────────────────

    // Total budget (ms) from download-created timestamp to when we give up
    // waiting for VT in the onChanged handler.
    // Breakdown: 3000 ms VT timeout + 100 ms BP startup delay +
    //            50 ms Settings.get overhead + 50 ms event-loop jitter +
    //            50 ms network RTT buffer.
    // The timestamp is set BEFORE API calls start so the budget covers all
    // setup overhead.
    VT_WAIT_BUDGET_MS: 3250,

    // How long a pendingChecks entry may live before the sweep removes it.
    ENTRY_MAX_AGE_MS: 30 * 60 * 1000,      // 30 minutes

    // How often the stale-entry alarm fires (minutes, as required by chrome.alarms).
    SWEEP_ALARM_PERIOD_MINUTES: 5,

    // Name of the chrome.alarms alarm used for stale-entry sweeping.
    SWEEP_ALARM_NAME: "sweepStaleEntries",

    // ── Timing — VT fetch (BrowserProtection.js) ─────────────────────────────

    // Hard timeout on the VT GET request; users get impatient beyond this.
    // Cached VT lookups typically resolve in 200–800 ms.
    VT_FETCH_TIMEOUT_MS: 3000,

    // Small pause before VT fetch so the warning page is mounted before the
    // result arrives (avoids a race where the result fires before listeners
    // are registered).
    VT_FETCH_STARTUP_DELAY_MS: 100,

    // ── Timing — VT submission polling (background.js SUBMIT_URL_TO_VT) ──────

    // Maximum time to wait for a freshly submitted URL to be analysed by VT.
    VT_SUBMIT_POLL_DEADLINE_MS: 15000,

    // Interval between poll attempts while waiting for VT analysis results.
    VT_SUBMIT_POLL_INTERVAL_MS: 1000,

    // ── Timing — DNS threat-intel / RDAP ──────────────────────────────────────

    // v3.3.0 (3P Matrix alignment item 21) — lowered from 8000 to match 3P
    // Matrix's own DNS timeout. A failed/timed-out lookup now scores neutral
    // (see RdapProtection.js's header / item 2), so a faster timeout costs
    // nothing in accuracy and saves real wait time on every check that would
    // have timed out anyway.
    //
    // Hard timeout on a DNS-over-HTTPS threat-intel request (whichever two
    // providers the user picked; see DNS_PROVIDERS below). Renamed from
    // QUAD9_TIMEOUT_MS in v3.0.6 when the single-provider Quad9 check became
    // "pick 2 of 3" (now "pick 2 of 5" since v3.3.1).
    DNS_TIMEOUT_MS: 3000,

    // Hard timeout on RDAP domain-registration-age requests. Same v3.3.0
    // alignment as DNS_TIMEOUT_MS above.
    RDAP_TIMEOUT_MS: 3000,

    // v3.5.2 — domain-age cut-points and scores, single source (were literals in
    // RdapProtection.scoreAge() and a copy in 3P Matrix's data/constants.js).
    // Age in days → score: ≤ RDAP_YOUNG_DAYS = RDAP_YOUNG_SCORE ("very new"),
    // ≤ RDAP_RECENT_DAYS = RDAP_RECENT_SCORE ("moderately new"), older = 0.
    // A real RDAP answer without a registration date = RDAP_NO_DATE_SCORE.
    // RDAP_YOUNG_SCORE also marks the "domain younger than 30 days" warn
    // exception (protection/WarnPolicy.js).
    RDAP_YOUNG_DAYS:    30,
    RDAP_RECENT_DAYS:   90,
    RDAP_YOUNG_SCORE:   -30,
    RDAP_RECENT_SCORE:  -10,
    RDAP_NO_DATE_SCORE: -10,

    // v3.3.0 (item 16) — when the FIRST VirusTotal check (VT_FETCH_TIMEOUT_MS
    // above) times out, one silent retry runs with this longer budget before
    // giving up for good. It's silent/non-blocking (the warning page is
    // already open and usable on the heuristic-only result), so there's far
    // less cost to waiting longer here than there was for the original
    // blocking checks — see BrowserProtection.js's checkIfUrlIsMalicious.
    // 3000 (first attempt) + 7000 (this retry) = 10000ms worst case, spent
    // only when actually needed, not on every check.
    VT_RETRY_TIMEOUT_MS: 7000,

    // ── DNS threat-intel providers (v3.0.6; DNS4EU added v3.3.1) ─────────────
    // Single source of truth: every provider the user can pick as their
    // "first"/"second" DNS check, keyed by its storage id. Consumed by
    // protection/DnsThreatProtection.js (to build/parse the actual DoH
    // request) and pages/options/OptionsPage.js (to populate the two
    // dropdowns) — add a provider here once and both pick it up.
    // NOTE: every provider's `host` also needs a matching manifest.json entry,
    // or the service-worker fetch fails:
    //   optionalPermission absent/false → in "host_permissions" (granted at install)
    //   optionalPermission true         → in "optional_host_permissions"; asked
    //                                     only when the user selects it
    //                                     (util/DnsPermissions.js). Use this for
    //                                     every provider added after release, so
    //                                     an update never pauses the extension
    //                                     for a new permission prompt.
    //
    // blockStyle — how each resolver signals "blocked"; one of
    // DNS_BLOCK_STYLE (see the enum above APP).
    // rpzSoaMnameSuffix — only for DNS_BLOCK_STYLE.RPZ_SOA: domain suffix of
    // the policy zone's SOA primary nameserver (matched on a label boundary).
    // blockPageIps — only for DNS_BLOCK_STYLE.BLOCKPAGE_IP: the provider's
    // block-page address(es). If a provider moves its block page, a block
    // falls through as ALLOWED (neutral score, never a false "malicious") —
    // update the list here.
    DNS_BLOCK_STYLE,
    DNS_PROVIDERS: Object.freeze({
        quad9:      Object.freeze({ id: "quad9",      label: "Quad9",                          host: "dns.quad9.net",               url: "https://dns.quad9.net/dns-query",               blockStyle: DNS_BLOCK_STYLE.NXDOMAIN_NO_AUTHORITY }),
        cloudflare: Object.freeze({ id: "cloudflare", label: "Cloudflare Security (malware)",   host: "security.cloudflare-dns.com", url: "https://security.cloudflare-dns.com/dns-query", blockStyle: DNS_BLOCK_STYLE.ZERO_IP }),
        controld:   Object.freeze({ id: "controld",   label: "Control D (malware)",             host: "freedns.controld.com",        url: "https://freedns.controld.com/p1",               blockStyle: DNS_BLOCK_STYLE.ZERO_IP }),
        // v3.3.1 — DNS4EU "Protective" profile (EU-backed, run by Whalebone):
        // blocks malware, phishing and botnet C&C. Note: DNS4EU also applies
        // court-ordered blocks on every profile, so a domain blocked by a
        // court order (e.g. piracy) can also come back as "blocked".
        // Verified live 2026-10-24 against 86.54.11.1 (same Protective profile):
        //   malware.wicar.org.          A   51.15.69.11   ← block page → BLOCKED
        //   thisdoesnotexist-12345.com  NXDOMAIN, "com." registry SOA → UNKNOWN
        //   example / clean domains     real A records → ALLOWED
        dns4eu:     Object.freeze({ id: "dns4eu",     label: "DNS4EU Protective (malware)",     host: "protective.joindns4.eu",      url: "https://protective.joindns4.eu/dns-query",      blockStyle: DNS_BLOCK_STYLE.BLOCKPAGE_IP,
                                    blockPageIps: Object.freeze(["51.15.69.11"]),
                                    optionalPermission: true }),
        // v3.3.1 — CleanBrowsing "Security Filter" (free; malware/phishing
        // only, no ads/adult filtering). A block returns no answer plus a
        // synthetic SOA from its policy zone, e.g. observed 2026-10-24:
        //   malware.wicar.org. SOA cleanbrowsing.rpz.noc.org. accesspolicy.rpz.noc.org. …
        // whereas a genuinely non-existent name returns the TLD registry's
        // own SOA (e.g. "com. SOA a.gtld-servers.net. …") — so the MNAME
        // suffix separates "blocked" from "doesn't exist" exactly.
        cleanbrowsing: Object.freeze({ id: "cleanbrowsing", label: "CleanBrowsing Security (malware)", host: "doh.cleanbrowsing.org", url: "https://doh.cleanbrowsing.org/doh/security-filter/", blockStyle: DNS_BLOCK_STYLE.RPZ_SOA,
                                    rpzSoaMnameSuffix: "rpz.noc.org",
                                    optionalPermission: true }),
    }),

    // Storage value meaning "don't run this DNS check slot at all".
    DNS_NONE: "none",

    // Global defaults for a first install: Quad9 as the first check, Control D
    // as the second (two different threat feeds, neither needing an account).
    // Do NOT read these directly for "what is this user's default" — use
    // util/DnsDefaults.js, which applies DNS_REGION_DEFAULTS below first and
    // falls back to these two.
    DEFAULT_DNS_FIRST:  "quad9",
    DEFAULT_DNS_SECOND: "controld",

    // v3.3.1 — region-specific first-install DNS defaults. First matching rule
    // wins; no match → DEFAULT_DNS_FIRST/SECOND above. Region is detected
    // OFFLINE from the browser's IANA time zone (util/DnsDefaults.js) — no
    // network call, no geolocation permission. Never name an
    // optionalPermission provider here — a default can't trigger a prompt.
    // Only affects users with no
    // stored dnsFirst/dnsSecond; a choice the user saved is never overridden.
    //
    //   FR — Quad9 is fighting French court orders (beIN/Canal+ IPTV piracy
    //        blocking) and has said it may stop serving France, so French
    //        users default to Control D + Cloudflare Security instead.
    //        Time zones: metropolitan France + overseas departments and
    //        territories (Europe/Monaco deliberately excluded — not France).
    DNS_REGION_DEFAULTS: Object.freeze([
        Object.freeze({
            region: "FR",
            first:  "controld",
            second: "cloudflare",
            timeZones: Object.freeze([
                "Europe/Paris",
                "America/Cayenne", "America/Guadeloupe", "America/Martinique",
                "America/Marigot", "America/St_Barthelemy", "America/Miquelon",
                "Indian/Reunion", "Indian/Mayotte", "Indian/Kerguelen",
                "Pacific/Tahiti", "Pacific/Marquesas", "Pacific/Gambier",
                "Pacific/Noumea", "Pacific/Wallis",
            ]),
        }),
    ]),

    // ── Collection caps ───────────────────────────────────────────────────────

    // Maximum number of safe URLs held in BrowserProtection.allowedUrls
    // (FIFO eviction when exceeded).
    ALLOWED_URLS_MAX: 200,

    // ── UI limits — Options page ──────────────────────────────────────────────

    // Maximum number of custom trusted-domain entries the user can add.
    DOMAIN_WHITELIST_MAX: 12,

    // Minimum and maximum values for the auto-allow threshold input.
    AUTO_ALLOW_THRESHOLD_MIN: 30,
    AUTO_ALLOW_THRESHOLD_MAX: 100,

    // Default auto-allow threshold when not set.
    AUTO_ALLOW_THRESHOLD_DEFAULT: 80,

    // (v3.4.0: the unused OBFUSCATION_UNKNOWN_SCORE −40 / _CATEGORY_CHANGE_SCORE
    // −20 copies that stood here were removed — they disagreed with the values
    // actually used. The obfuscation scores live only in SCORING_CONFIG,
    // protection/ScoringEngineV2.js.)

    // ── Extensionless generic binary (v3.4.0, heuristic R1) — switch ─────────
    // true  = such a download ALWAYS opens the warning page, even when
    //         "Silent when probably safe" (autoAllow) would have let a good
    //         combined score through. A fresh malicious upload is usually
    //         still unknown to VirusTotal, so a "probably safe" verdict says
    //         little here. Never blocks: the user decides on the warning page.
    // false = treat it like any other signal (score only, autoAllow applies).
    // Its score is SCORING_CONFIG.EXTENSIONLESS_BINARY_SCORE (ScoringEngineV2.js).
    EXTENSIONLESS_BINARY_ALWAYS_WARN: true,

    // ── Quiet downloads — toolbar badge + popup list (v3.5.2) ────────────────
    // A download that is checked but gets no warning window (protection/
    // WarnPolicy.js) is listed in the popup and counted on the toolbar badge
    // until the popup is opened (util/QuietLog.js). Kept in storage.session.
    QUIET_LOG_KEY:          "quietDownloads",
    QUIET_LOG_MAX:          10,           // newest kept; older ones drop off
    QUIET_BADGE_COLOR:      "#6B7280",    // neutral grey: informational, not a warning
    QUIET_BADGE_TITLE:      "{count} download(s) checked without a warning window — open for details",
    QUIET_COUNT_TOKEN:      "{count}",

    // ── Default UI strings — shared between Settings, OptionsPage, WarningPage ─
    // Changing a default here updates all three consumers automatically.
    // v3.3.0 (item 11): plain text only — WarningPage.js renders it via
    // textContent (no innerHTML), so no HTML markup here, ever.
    WARNING_TITLE_DEFAULT:
        "Download requires your attention!",

    // ── Default warning window color ("Google Red") ──────────────────────────
    // Single source of truth for the default RGB triplet. Shared between
    // Settings.js (stored default), OptionsPage.js (color pickers + the
    // "reset to default when Personalize is unchecked" logic) and any future
    // consumer — never hardcode 179/38/30 anywhere else.
    WARNING_COLOR_DEFAULT_R: 179,
    WARNING_COLOR_DEFAULT_G: 38,
    WARNING_COLOR_DEFAULT_B: 30,

    // ── Built-in trusted domains — never checked ──────────────────────────────
    // Only platform-vetted app stores belong here. User-controlled cloud storage
    // (Google Drive, OneDrive, iCloud) and org-controlled hosting (SharePoint)
    // are intentionally excluded so malicious files served from those domains
    // are still inspected. SharePoint is offered as a starter entry in the user
    // whitelist (Settings.js → customDomains) so users can restore it if needed.
    // Shared between background.js (enforcement) and OptionsPage.js (display)
    // so the options page never shows a stale hardcoded list.
    BUILTIN_DO_NOT_CHECK_DOMAINS: [
        "chromewebstore.google.com",
        "apps.microsoft.com",
        "apps.apple.com",
    ],

    // ── AI-assistant download domains — opt-in trust category (v3.3.0, item 25) ─
    // Unlike BUILTIN_DO_NOT_CHECK_DOMAINS above, these are NOT trusted by
    // default — the user opts in via Settings.js's trustAiDownloads toggle
    // (OptionsPage.js's "Trust AI downloads" checkbox). Files from these
    // sites are typically sandboxed, in-browser-generated artifacts (chat
    // exports, generated documents/images) rather than something hosted at
    // an address an attacker controls — see item 27's referrer-fallback fix
    // for the specific bug (claude.ai's blob:null/… downloads) this
    // category grew out of. Shared between background.js (enforcement) and
    // OptionsPage.js (display) so the options page never shows a stale list.
    AI_DOWNLOAD_DOMAINS: [
        "claude.ai",
        "chatgpt.com",
        "chat.openai.com",
        "copilot.microsoft.com",
        "gemini.google.com",
    ],

});
