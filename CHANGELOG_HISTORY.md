# Changelog History — DownloadSentinel

Full technical record of releases: what changed, why, how, known limitations and the source worked from.
The brief user-facing summary is CHANGELOG.md.

---

## 3.5.6 — small signals add up when heuristics are the only indicator and the source is dubious (2026-11-09)

Source worked from: DownloadSentinel 3.5.5 (DOCS/EXTENSION/TOOLS zips) together with 3P Matrix 5.0.3, built as
one change in the shared library (protection/CombinationScoring.js, protection/ScoringEngineV2.js — byte-identical
in both projects) and carried into 3P Matrix 5.0.4 unchanged.

**Why.** User report: a hidden `.bin` from `drive.google.com/uc?export=download&id=…` (VirusTotal does not know
it) stayed quiet. `drive.google.com` is on SuspiciousDomains (−24); the "opaque download path" SketchyUrl signal
(−7) is weaker than STACK_MIN_SIGNAL (−15), so it never stacked. User decision: small signals (1) do not add up when
VirusTotal knows the file, (2) add up when the heuristics are the only indicator and the source is dubious.
"Dubious" (confirmed): a counted hit from DomainList, RiskyHosting, HostList, ActiveThreatHost, TldList, DnsThreat,
or RDAP at "very young" (APP.RDAP_YOUNG_SCORE). (The silence itself was "Silent when inconclusive", on by choice.)

**How.**
- CombinationScoring: `combineHostResults(results, { heuristicsOnly })`; `smallSignalsStack()`, `canStack()`,
  `isDubiousSource()`; CONFIG.DUBIOUS_SOURCES / DUBIOUS_AGE_SOURCE / DUBIOUS_AGE_AT (from APP, not retyped).
- ScoringEngineV2.evaluateHostReputation returns the VT-known verdict at the top level (unchanged) plus
  `heuristicsOnly`; both are built from copies (the shared `results`/`display` are no longer mutated by Check 10b).
  New `hostVerdict(hostResult, vtUnknown)` picks one, keeping caller-added fields (dnsChecks, rdap).
- BrowserProtection.checkHostReputation passes `heuristicsOnly` through (it builds its own result object; without
  this the extension never saw the new verdict — found by 3P Matrix's end-to-end test on the real Drive case, which
  goes through this function, while fp-sweep and the unit tests call the engine directly).
- background.js computeCombinedScore uses hostVerdict and stores `record.hostVerdict` (warnDecision entries, the
  warning page, and VT_RESULT_UPDATE — a late VirusTotal answer switches the verdict). ActiveThreatHosts.applyFloor
  floors both verdicts.
- tools/fp-sweep.mjs scores with the VirusTotal-unknown verdict (the worst case, the one this rule changes).

**Measured (fp-sweep, before → after).** Attacks: A01 Discord extensionless −42 → −45, A07 Discord .exe −35 → −40
(MEDIUM). Legit: L07 GitHub Linux binary −15 → −20 (still inconclusive; already warned at every level before);
L16 7-Zip via SourceForge −12 → −18 (quiet). No gate failed, no knownGood entry changed level.
A first version also let a dubious-source small signal count as "corroboration" for the RiskyHosting solo rule and
dropped the WeakSignalCluster in favour of individual stacking; the sweep showed 7-Zip via SourceForge warning
(−31, gate failed) and an attack getting weaker (A03 −59 → −50). Both were taken out: corroboration stays at
STACK_MIN_SIGNAL, and a present cluster keeps its full sum (small signals then do not stack a second time).

**Tests.** tests/SmallSignalStacking.test.js (11 cases: the rule, the dubious-source definition, the cluster,
both verdicts on the real Drive case, hostVerdict field-keeping, floor on both verdicts, and the real path through
BrowserProtection.checkHostReputation — fault-verified: fails without the pass-through).

**Known limitation.** fp-sweep assumes VirusTotal unknown throughout; with a VT key, popular legit installers are
usually known to VirusTotal and keep the unchanged verdict.

---

## 3.5.5 — full parity with 3P Matrix 4.5.9: Check 26 size tiers, one VirusTotal limit, active-threat floor −30 without the platform row, PSL rebuilt, lazy list format, list snapshot rule (2026-11-06)

Source worked from: DownloadSentinel 3.5.4 (DOCS/EXTENSION/TOOLS zips) and 3P Matrix 4.5.8 (as packaged the same
day). User request: "check last update in DS and apply all relevant changes in 3PM (for download check and
heuristics etc) to DS", then "bring it up to par with 3PM" (data format and list tooling included). DS 3.5.4 was
built against 3PM 4.5.3, so the gap is 3PM 4.5.4–4.5.9. Built as one release (3.5.5 was not published in between).

**Gap review (3PM 4.5.4–4.5.8), by comparing 3PM's lib/downloadsentinel/ with DS 3.5.4 file by file:**
- **Ported (detection code):** protection/ScoringEngineV2.js, MimeCheck.js, StagingCheck.js, BrowserProtection.js
  taken over unchanged — their only differences were 3PM 4.5.6 (large extensionless binary) and 4.5.8 (size tiers,
  shared VT limit / MB unit, heuristicLabel()).
- **Ported into DS's own util/ActiveThreatHosts.js:** 3PM 4.5.8 floor −40 → −30, platform row left out with a hit,
  label from ScoringEngineV2.heuristicLabel() (was a retyped copy, `countLabel`).
- **Ported (data + format + tooling):** every util/*.default.js and its wrapper differed by 3PM 4.5.4's precompiled
  lazy-JSON format (util/LazyJson.js), and the Public Suffix List by content (see below). Curated lists
  (RiskyHostingSites, SuspiciousDomains, SuspiciousTlds, UrlShorteners) compared parsed: identical. 3PM 4.5.4's
  `sameSnapshotAs` freshness rule ported as a DS hard gate (see below).
- **Not applicable to DS:** 4.5.5 paused-not-deleted blocked downloads (3PM protection 21 blocks; DS never does);
  4.5.6/4.5.7 site whitelist review (3PM's site trust list; DS's BUILTIN_DO_NOT_CHECK_DOMAINS holds only app
  stores, no Discord) — DS's "Trust AI downloads" list is a DS design choice and was left as is; 4.5.8 DNS
  defaults (3PM: Control D + DNS4EU — in DS DNS4EU is an optionalPermission provider, and a default must never
  trigger a permission prompt; DS keeps Quad9 + Control D).

### Check 26 size tiers (3PM 4.5.6 + 4.5.8)
- SCORING_CONFIG: BYTES_PER_MB and VT_MAX_BYTES (650 MB) declared once; MimeCheck.checkSize() (Check 7) and
  StagingCheck read them (were typed `1024 * 1024` / `650 * 1024 * 1024`).
- extensionlessSizeTier(): only an extensionless generic binary from a RiskyHostingSites host is tiered —
  ≥ LARGE_EXTENSIONLESS_BINARY_MIN_BYTES (32 MB) → −30, ≥ HUGE_EXTENSIONLESS_BINARY_MIN_BYTES (= VT_MAX_BYTES) → −45.
  The huge tier REPLACES Check 7 for that file (one fact, one signal). Size 0 = unknown → normal −15; background.js
  already re-runs host reputation when the size becomes known at completion (v2.8.0 sizeNewlyKnown), so the tier
  applies there.
- BrowserProtection passes totalBytes into evaluateHostReputation().
- Verdicts (real-case host cdn.discordapp.com, risky-host hit stacked): 32 MB → −40 "probably suspicious";
  700 MB → −55 "probably suspicious" with one size line. A file with an extension, or from a non-file-sharing host,
  keeps Check 7 unchanged. Known effect (accepted in 3PM): large extensionless Linux binaries from GitHub release
  assets also lose points.

### Active-threat floor (3PM 4.5.8)
- CONFIG.FLOOR_SCORE −30 (3PM SCORE.ACTIVE_THREAT_HOST, user decision: the host list is a dated snapshot, not a live
  feed). Alone "Probably Inconclusive"; a floor, not an addend.
- CONFIG.PLATFORM_SOURCE ("RiskyHosting") rows are dropped from the prior breakdown when the floor applies. This also
  removes the contradiction reported in 3PM: "(no other corroborating signal, so halved)" directly above "Currently
  used to deliver malware". The engine decides on halving before the floor adds its row; dropping the row is the
  simpler of the two fixes tried in 3PM (the first carried the unhalved row back and was replaced the same day).
- Label: ScoringEngineV2.heuristicLabel(count, classification) — the engine's own builder, now exported.
- DS's two deliberate differences from 3PM (original link checked; verdict re-derived) are no longer differences:
  3PM 4.5.8 re-derives the verdict, and 3PM 4.5.9 took over the original-link check and the `explained`-rows rule
  (isCountedNegative) from here.

### Tests / checks
- NEW tests/ExtensionlessSizeTiers.test.js (12): port of 3PM tools/test-large-binary.mjs, expected values from
  SCORING_CONFIG/MimeCheck.
- tests/ActiveThreatHosts.test.js: case 6 now uses a file signal (MessageOrigin) as the corroborating signal — the
  platform row no longer counts; + 4 cases (row left out, no-hit passthrough, heuristicLabel, real engine + floor).
- Fault check (C42): the new cases were run against the DS 3.5.4 extension first — 9 size-tier and 3 active-threat
  cases fail there, all pass on 3.5.5.
- `npm run check`: suite 546 → 562, all hard gates pass.

### Public Suffix List rebuilt; list data identical to 3P Matrix

- Finding: tools/lists-raw/ in DS and 3PM are byte-identical, and every generated list has identical content except
  util/PublicSuffixList.default.js — DS's was built 2026-10-21 from the previous raw file. 3.5.1 refreshed the raw PSL
  and PlatformSuffixes (same upstream file) but never re-ran tools/update-psl.mjs, so the two lists derived from one
  upstream file came from two releases. 3P Matrix found the identical gap in its 4.5.4 (C44) and added a
  `sameSnapshotAs` check to its check-list-freshness.mjs; DS's freshness check has no such rule and passed.
- Fix: `node tools/update-psl.mjs` (cached raw, no fetch) → rules 10018 → 10077, wildcard rules 310 → 312, exceptions
  8 (66 entries added, 5 removed). data/PublicSuffixList.json regenerated.
- Verified: parsed content AND export names of all eleven lists equal 3P Matrix 4.5.9's lib/downloadsentinel.

### Lazy list format (3PM 4.5.4, perf P4)
- tools/gen-data-defaults.mjs (the one writer of util/*.default.js — every other list tool calls it) now emits
  `export const <Name>DefaultJson = "<one JSON string>"` instead of an object literal: a string costs almost nothing
  when the service worker evaluates its static imports at every start; the data is parsed on first lookup.
- NEW util/LazyJson.js and util/ListSetModule.js + the eleven wrappers taken from 3PM 4.5.9's lib/downloadsentinel —
  code identical (verified with comments stripped); headers say DS's own generator and EXTENSION/data/ sources.
  Lifecycle per wrapper: built on first lookup, resetToDefault() releases its derived structures, next lookup rebuilds.
- tools/build-top-sites-filter.mjs read BrandsDefault/GovSuffixesDefault from the generated modules; it now reads
  EXTENSION/data/Brands.json and GovSuffixes.json (their single source of truth).
- NEW tests/LazyLists.test.js (4): importing all wrappers parses nothing; each module exports one JSON string equal to
  data/<Name>.json; wrappers answer from the shipped data; resetToDefault() releases and rebuilds. The format case
  fails on 3.5.4.
- All data JSON files are byte-identical before and after (the rebuilds below run from the cached raw files).

### List snapshot rule (3PM 4.5.4 `sameSnapshotAs`, C44)
- NEW tools/source-snapshots.mjs: snapshotId() (sha256, 12 hex), recordBuiltFrom(feed) — the one writer of the new
  register field `builtFromSnapshot`. Called by update-psl, update-domain-age-lists (×2), update-lists and
  build-top-sites-filter right after they write their data file. Seeded by running all four from the cached raw
  files (no fetch): 7 sources recorded, data unchanged.
- tools/check-list-freshness.mjs: a source whose builtFromSnapshot is missing or differs from its cached raw file now
  ("raw file refreshed, list not rebuilt") → "SNAPSHOT MISMATCH", exit 1. Sources sharing one raw file (PSL and its
  PRIVATE section) must both match it, so they can never come from two snapshots again — 3PM's twin rule without a
  pairing to maintain, and it covers every source, not only the PSL pair. Age stays advisory (exit 0).
- tools/complete-check.mjs step 12: a snapshot mismatch is a hard FAIL; a check that did not run FAILS too (was a WARN).
- NEW tests/SourceSnapshots.test.js (4): replays the 3.5.1 gap in a throw-away copy of the tools (raw PSL refreshed,
  lists not rebuilt) → exit 1 naming both lists; after recording again → passes with one shared snapshot.
- Suite 562 → 570; advisory sections (knip, magic numbers, derived literals) unchanged from 3.5.4; jscpd 51 → 31 clones
  (the generated lists are single strings now).

---

## 3.5.4 — active-threat delivery floor and warning-window button scheme, ported from 3P Matrix 4.4.6–4.5.1 (2026-11-02)

Source worked from: DownloadSentinel 3.5.3 (DOCS/EXTENSION/TOOLS zips) and 3P Matrix 4.5.3 (extension +
tools zips). User request: "add the improvements of 3PM to DS, use the changelog to see what DS has missed",
narrowed to **the download-check improvements only**, plus the new button scheme. DS 3.5.3 was built together
with 3P Matrix 4.4.4, so the gap is 3PM 4.4.5–4.5.3 (identified from the version tags in 3PM's code; its zips
do not include a changelog).

**Gap review (3PM 4.4.5–4.5.3):**
- lib/downloadsentinel/ (the vendored DS library) is byte-identical to DS 3.5.3, apart from generated-file headers
  (3PM's own rebuild tools and timestamps; the list data itself is identical) and a 3PM-specific doc comment in
  util/HostList.js — nothing to take over.
- **Ported:** 4.4.9/4.5.0/4.5.1 active-threat delivery floor (download path = 4.5.1 core/download-guard.js
  applyActiveThreatFloor()); 4.4.6 warning-window buttons + ui/focus-ring.js.
- **Not applicable to DS:** 4.4.5 tab band / per-tenant site locks / state schema 4; 4.4.7 whitelist review and
  4.4.8 suspicious-hosting refresh (3PM's site-blocking protection 6; DS's HostList raw lists are identical);
  4.5.3 blob: export never blocked (3PM protection 18 cancels downloads, DS never does); 4.5.1 e2e flakiness and
  check-no-eval / shipped-terms / protection-keys tooling (left out on request — tooling is not part of the
  download check).

### Active-threat delivery floor
- NEW util/ActiveThreatHosts.js (DS-only, like Settings.js/QuietLog.js — not part of the files 3P Matrix vendors,
  so lib/downloadsentinel/ stays byte-identical). Same host list, RISKY_DELIVERY_EXT_RE, shapes and "Download ZIP"
  note as 3PM data/active-threat-hosts.js; same floor value (CONFIG.FLOOR_SCORE −40 = 3PM SCORE.ACTIVE_THREAT_HOST —
  keep in sync). Constants in one CONFIG block. Pure, no chrome.*.
- Applied AFTER BrowserProtection.checkHostReputation(), never inside CombinationScoring: an unregistered family
  degrades to NEUTRAL and is dropped as soon as RiskyHosting (present for nearly every one of these hosts) is
  there — same reason as 3PM.
- background.js: ONE wrapper, checkHostReputationFloored(), replaces the three direct checkHostReputation() calls
  (onCreated, late entry, re-check at completion), so the floor cannot be missed by one path.
- Differences from 3PM, both deliberate:
  1. **Original link also checked** (`[url, originalUrl]`, first match decides): github.com/…/releases/download/…/x.exe
     redirects to a release-assets.githubusercontent.com path WITHOUT an extension; 3PM checks only the final URL
     and can miss it. Same redirect gap as DS 2.0.1.
  2. **Verdict and label re-derived** (ScoringEngineV2.classifyByScore + the engine's own v3.5.0 count wording):
     DS's warning page shows hostResult.label/classification prominently, so a floored −40 must not still read
     "probably safe". A hard-rule result (DNS-blocked) keeps its own verdict and label.
- The "Download ZIP" disclaimer is added (score 0, `explained: true`) only when no other counted negative signal
  exists — same sole-signal rule as 3PM.
- Not a WarnPolicy exception (same as 3PM): at FP High (window from −45) a lone −40 stays quiet when
  "Silent when inconclusive" is on; with the default (off) every such download gets a window.
- fp-sweep is unaffected (it calls the engine and WarnPolicy directly, not background.js) — as with 3.5.3's gate.
  Known effect: a legitimate binary from a GitHub release now scores −40 "probably suspicious"; accepted in 3PM
  for the campaign's duration. Prune the list when the campaign dies down.

### Warning-window buttons (3PM 4.4.6)
- pages/warning/WarningPage.html: "Check download at VT" first (`btn btn-safe`), "Proceed anyway" second
  (`btn btn-risky`) — risk rises left to right; `type="button"`.
- WarningPage.css: :root tokens (--choice-safe #4ADE80, --choice-risky #FF8A1F, dark text #0F1117 on both fills
  per STYLE_GUIDE_DARK "Solid-fill button text", min width 176 px, height 44 px, font 14 px). `.actions` is an
  inline grid with equal columns, so both buttons always have the same size and fit the longest label
  ("Check download at Hybrid Analysis"); stacked full width under 640 px. Unused #btn-allow rules removed.
- NEW pages/warning/FocusRing.js (port of 3PM ui/focus-ring.js): idempotent init(), listeners removed on
  pagehide. WarningPage.js focuses btn-vt at start — Enter checks instead of proceeding; no ring until the user
  navigates by keyboard.
- Rendered in headless Chromium: both buttons 176×44, btn-vt focused, no ring after load, ring after Tab,
  stacked at 420 px, no console errors.

### Tests / checks
- NEW tests/ActiveThreatHosts.test.js (14): the 8 cases of 3PM tools/test-download-active-threat.mjs plus
  original-link fallback, verdict/label re-derivation, hard-rule passthrough, no mutation, guards
  (null result, blob:/garbage URL, uppercase host). Expected values from CONFIG/ScoringEngineV2, never typed.
- `npm run check`: all hard gates pass; suite 532 → 546. New soft warning only for FocusRing.js "not reachable
  from manifest.json" — same pre-existing class as WarningPage.js itself (opened via chrome.windows).

## 3.5.3 — "Silent when inconclusive" split out from the 3.5.2 staged quiet behaviour, off by default (2026-10-26)

Source worked from: DownloadSentinel 3.5.2 (delivered 2026-10-25), built together with 3P Matrix 4.4.4.
User report: "The don't-show-inconclusive levels which are applied according to the FP reduction should
have their own setting (just above 'Silent when probably safe') called 'Silent when inconclusive'."
3.5.2's WarnPolicy staging made every download whose score didn't cross its FP-level threshold (and had
no exception) quiet by default, with no way to turn just that part off — this gives it its own toggle.
**User correction during the build: default is OFF**, not on. Off means every such download gets a
warning window, matching pre-3.5.2 behaviour, until the user explicitly opts into staying quiet.

**Where the gate lives.** `protection/WarnPolicy.js` itself is UNCHANGED — its own doc comment already
says "Not decided here: 'Silent when probably safe' (autoAllow) ... run first in the glue, unchanged,"
so this follows the same precedent: it gates the existing `warnDecision()` call in `background.js`
rather than becoming a parameter of the pure decision function:
```
if (!mustWarn && record.silentWhenInconclusive && !warnDecision(record, combined).warn) {
    record.quiet = true;
    QuietLog.add(quietEntryOf(record, combined));
    releaseDownload(delta.id, "quiet: below the warning threshold, no exception");
    return;
}
```
Off skips this block entirely, falling through to `openWarningPage()` unconditionally (unless
`mustWarn` or the earlier `autoAllow` check already returned) — the toolbar badge / popup quiet list
(`QuietLog`) then simply has nothing added while it's off, since nothing is ever marked quiet.

**New setting, full wiring:**
- `util/Settings.js`: `defaultSettings.silentWhenInconclusive = false` — a brand-new key with a
  sensible default needs no migration entry in `SETTINGS_SCHEMA_VERSION`'s scheme.
- `background.js`: `buildSettingsSnapshot()` → `silentWhenInconclusive: !!settings.silentWhenInconclusive`
  (same `!!` pattern `autoAllow` already uses — an absent/non-boolean stored value reads as `false`,
  matching the default); the gate above.
- `pages/options/OptionsPage.html`: new `silentWhenInconclusiveSection`, same placement as 3P Matrix —
  just above "Silent when probably safe" — with "Off by default" stated in its own hint text.
- `pages/options/OptionsPage.js`: `loadSilentWhenInconclusive()` (new), added to the
  `unlockSections()` id list (so it gets the same visual unlock as the other four sections, which
  are not actually VT-key-gated — see that function's own 3.3.0 comment), and the save handler reads
  `silentWhenInconclusiveToggle` into the `Settings.set()` payload.

**Verification.** `npm test` — 532/532 unit tests pass (including the existing `Settings.test.js`
"get() on first run returns full defaults" case, which covers the new key's default automatically, no
new assertion needed). `tools/complete-check.mjs` passes (the pre-existing magic-numbers/
derived-literals WARN-level findings it reports are unrelated — none are in a file this change
touched). `fp-sweep` is unaffected because it calls `WarnPolicy.downloadDecision()` directly — the
pure function this feature deliberately leaves untouched — never through `background.js`'s new gate,
so it could not have caught a regression in the gate either way. DownloadSentinel has no Playwright-
style real-download e2e suite (unlike 3P Matrix's `tools/e2e-flows.mjs`), so the gate itself was
verified by code review/trace against the identical, already-shipped `autoAllow` wiring it mirrors,
rather than by an end-to-end test exercising a real `chrome.downloads` completion.

## 3.5.2 — staged warning window (WarnPolicy: thresholds per FP level + exceptions); quiet-download badge

Source worked from: DownloadSentinel 3.5.1 (delivered 2026-10-25). Design agreed with the user 2026-10-25 (user idea:
no window above −30 at FP Medium/High; refined together: exceptions that always warn, staged values per level, same
mechanism for 3P Matrix's site dialog). Built first in 3P Matrix 4.4.1's copy of this library, identical here.

### Shared library
- NEW protection/WarnPolicy.js — see its header. DOWNLOAD_WARN_FROM { HIGH −45, MEDIUM −30, LOW −15, NONE always };
  exceptions per check (download: KNOWN_BAD = DnsThreat or VT malicious ≥ 1, IMPERSONATION = LookalikeDomain /
  PlatformBrand, FILE_ITSELF = any WHAT-question signal, LURE_ROUTE = MessageOrigin, YOUNG_DOMAIN = RDAP ≤
  APP.RDAP_YOUNG_SCORE; site: KNOWN_BAD, IMPERSONATION). Explained entries never count. `windowHint()` = the Options
  sentence per level (both extensions).
- APP.RDAP_YOUNG_DAYS / RECENT_DAYS / YOUNG_SCORE / RECENT_SCORE / NO_DATE_SCORE (were literals in
  RdapProtection.scoreAge and copied in 3P Matrix).
- util/DeliveryPatterns.js: OPEN_PLATFORMS / ORG_PAGE_PLATFORMS + isOpenPlatform() / brandOnPlatform() (moved from
  3P Matrix 4.4.0's site check). ScoringEngineV2 Check 28 "PlatformBrand" for downloads (LOOKALIKE_SITE_SCORE);
  CombinationScoring FAMILY_MAP PlatformBrand → URL_SHAPE.
- SCORING_CONFIG.SCORE_FLOOR / SCORE_CEILING / DNS_BLOCKED_SCORE replace seven −100 / 100 literals in the engine.

### background.js
- After R1 always-warn and autoAllow ("Silent when probably safe", unchanged): `warnDecision(record, combined)`. Quiet →
  `record.quiet`, QuietLog.add({ filename, host, verdict, score, at }), releaseDownload() (keeps the record while a
  silent VT retry runs). The final-record fields (combinedScore, …) are now stored before this decision.
- handleLateVtResult: a quiet record opens the window only when warnDecision now says so; a dismissed window reopens
  when worse (unchanged).

### Quiet downloads — toolbar badge + popup
- NEW util/QuietLog.js (init / add / read / clear): newest APP.QUIET_LOG_MAX (10) entries in chrome.storage.session
  (APP.QUIET_LOG_KEY) — survives service-worker restarts, cleared on browser restart; badge text = count, colour
  APP.QUIET_BADGE_COLOR, title APP.QUIET_BADGE_TITLE. No new permission (storage + action already present).
- util/Storage.js: getFromSessionStore / setToSessionStore (single storage layer, C4).
- Popup: "Checked without a warning window" list (file, host · verdict (score)); opening the popup clears list + badge.
  Rendered and checked in headless Chromium.

### Options
- FP hint: "Higher = fewer false alarms: filters VirusTotal results and sets from which score a download gets a
  warning window." + WarnPolicy.windowHint(level).

### Tests
- tests/WarnPolicy.test.js (23): thresholds per level (boundary ±1), order, default level, every exception at every
  level, non-exceptions (route quirks, moderately new domain, explained), site check list, siteDecision, windowHint,
  brandOnPlatform incl. org page and DDNS, Check 28, RDAP constants. No typed scores — all from constants.
- tools/fp-sweep.mjs flows: "W / ·" (window / quiet) per FP level; attack flows must get a window wherever gated
  (Medium, Low, None). Result: at High and Medium 15 of 16 legit flows quiet (the extensionless Linux binary warns
  by design); every attack flow gets a window at every level, High included (A04 via LURE_ROUTE).
- Suite 509 → 532.

---

## 3.5.1 — hosting-platform list refreshed; IDN platform rules stored as punycode

Source worked from: DownloadSentinel 3.5.0 (zipped and delivered 2026-10-24). Trigger: 3P Matrix 4.4.0 is a minor
release, which rebuilds the shared lists (lib/downloadsentinel/ stays byte-identical to DS, so DS gets them too).
- PlatformSuffixes rebuilt from
  a fresh PSL (github.com/publicsuffix/list main, 2026-10-25 — publicsuffix.org itself is not reachable from the
  build sandbox): 3,447 → 3,448 entries. BUG FIXED in tools/update-domain-age-lists.mjs: PRIVATE rules were stored
  verbatim, so the 13 internationalized ones ("günstigbestellen.de", "биз.рус", …) were Unicode and could never
  match a hostname (the URL API reports punycode) — now converted with `toAscii()` (same as 3P Matrix's builder);
  DS and 3P Matrix builds are now identical. RdapCctlds and TopSitesFilter (CrUX 202609 is still the newest)
  unchanged. Runtime PublicSuffixList.json not rebuilt (its own 180-day freshness rule). Note: the freshness
  advisory reads raw-file dates, so tools/lists-raw/public_suffix_list.dat now reads "0 days old" for both.
- tools/check-mv3.mjs: header comment "3P Matrix 4.3.8" → "4.4.0" (4.3.8 was never released); identical file in both.
- util/PlatformSuffixes.js header: the typed "3,447 entries" (stale after the refresh — derived-literal check)
  replaced by a reference to data/PlatformSuffixes.json.

---

## 3.5.0 — delivery context: explained route quirks, weak-signal cluster, established-site credit, FP-level strategies; flow corpus

Source worked from: DownloadSentinel 3.4.0 (this session, never zipped). Trigger (user, 2026-10-24): weak signals
count when alone but never add up when several co-occur; asked for better decision rules / grouping, e.g. CDN
deliveries, and different strategies per FP reduction level ("think out of the box"). Approved plan: 1) richer
test collection first, 2) then the rules; ship as 3.5.0 (3.4.0 folded in).

### Step 1 — flow corpus (tests/fixtures/fp-corpus.json "flows", 23 entries)
- Complete journeys (referrer, redirect, domain age mock, extension hidden at start) the single-URL corpus could
  not express. 16 legit vendor flows (expect "quiet") and 7 attack flows (expect "flag"); see each entry's story.
- Found first: the old corpus never had more than ONE weak signal per download (good or bad), so no threshold
  could be tested; the sweep never passed referrer/obfuscation context.
- tools/fp-sweep.mjs scores every flow at HIGH/MEDIUM/LOW/NONE with VirusTotal unknown, through the new shared
  `ScoringEngineV2.scaleHostScoreForUnknownVt()` (moved out of background.js computeCombinedScore — single
  source). Gates (FLOW_GATES): quiet → below Suspicious at HIGH/MEDIUM, never Malicious at LOW (NONE listed
  only: it counts everything in full and doubles it); flag → Suspicious or worse (or R1 always-warn) at
  MEDIUM/LOW/NONE (HIGH listed only).
- Measured on 3.4.0 rules (MEDIUM): VLC HTTP mirror −35 Suspicious, 7-Zip via SourceForge link −35 Suspicious,
  Discord attachment .exe from chat −12 (RiskyHosting −20 HALVED as "solo" because the −12 referrer is below the
  stacking floor), raw-GitHub PowerShell from chat −25, webmail → 2-month domain −12 (identical to the legit
  2-month startup) — 6 gate failures.

### Step 2 — rules
- util/DeliveryPatterns.js (new, pure tables + matchers): VENDOR_DELIVERY (vendor-owned delivery hosts only —
  never user-content hosts, rent-a-CDN domains or keywords; whole-label match), MIRROR_NETWORKS,
  PLATFORM_DOWNLOAD_LINKS (SourceForge `projects/*/files/…/download`), MESSAGE_ORIGINS (webmail/chat; Discord
  only under /channels/).
- protection/DeliveryContext.js (new, pure), run in evaluateHostReputation after all checks, before
  combination:
  - EXPLAIN (HIGH/MEDIUM): ReferrerMismatch, UrlShortener, MessageOrigin, HiddenExtension → vendor host;
    HiddenExtension also → platform download link; ProtocolDowngrade → chain starts at a mirror network.
    Blocked by any WHO signal (identity lists, domain age, TLD), except a platform link may coexist with that
    platform's RiskyHosting entry (which still counts). WHAT signals are never explainable. Explained entries are
    removed from combination (so they cannot make a family "present" for combo rules) and shown at 0 with
    plain-language text (`EXPLAINED_TEXT` + " — normal for <reason>"; original kept as `rawLabel`).
  - CLUSTER: worst entry per family; families whose worst is weaker than STACK_MIN_SIGNAL (−1…−14) are weak;
    when their count ≥ strategy.weakClusterMin (HIGH 4, MEDIUM 3, LOW/NONE 2; −1 on a RiskyHosting host,
    floor 2) one `WeakSignalCluster` entry (family CLUSTER) = their sum, floored at −45, is added. It stacks, and
    also counts as corroboration for the RiskyHosting solo-halving rule.
  - CREDIT (HIGH/MEDIUM): `EstablishedSite` +10 after combination (final = min(score + 10, 10)) when the host's
    registered domain is in TopSitesFilter, HTTPS, a DNS check resolved, and no WHO/WHAT signal. Never with a
    hard rule. (TopSitesFilter is a Bloom filter, ~1% false matches — worst case +10 where nothing else is wrong.)
  - Strategies: `DeliveryContext.CONFIG.FP_STRATEGIES`; the SCORING_CONFIG.FP_UNKNOWN_MULTIPLIERS still apply.
- CombinationScoring: new families DELIVERY (HiddenExtension), ORIGIN (MessageOrigin), CLUSTER
  (WeakSignalCluster); `QUESTION` / `FAMILY_QUESTION` / `questionOf()` (WHAT / WHO / ROUTE); rule C2 also fires
  on DELIVERY (young domain + extension hidden until landing).
- ScoringEngineV2: Obfuscation UNKNOWN_REVEALED now has source "HiddenExtension" (family DELIVERY, a ROUTE
  question; CATEGORY_CHANGED stays "Obfuscation"/FILE_DECEPTION); Check 27 MessageOrigin
  (`MESSAGE_ORIGIN_SCORE` −10, referrer or start of the redirect chain); param `fpLevel`; when every negative
  signal is explained the result is Probably Safe with the explained rows listed.
- Plumbing: `DownloadShape.shapeOf` → `contextOf(record)` now also carries `fpLevel`;
  `BrowserProtection.checkHostReputation(…, downloadShape)` → `downloadContext` (both unreleased 3.4.0 names).
- Warning page: explained rows (`.host-signal-explained`, grey) and the credit (`.host-signal-credit`, green)
  are listed; other 0-score rows stay hidden. `sanitizeLabel()` now keeps U+2010–2015 dashes, U+2018–201F
  quotes, U+2026, U+2192 (the em dash used to be deleted: "was hidden no extension"); bidi controls are still
  stripped. Rendered in headless Chromium with engine-built records for CCleaner (MEDIUM/LOW) and a Discord .exe.

### Result (MEDIUM, VT unknown) — every flow gate passes
| Flow | 3.4.0 | 3.5.0 |
|---|---|---|
| L01/L02 CCleaner / Avast (avcdn.net) | −20 | 0 (explained) |
| L08 VLC via HTTP mirror | −35 Suspicious | −25 |
| L16 7-Zip via SourceForge link | −35 Suspicious | −12 |
| L06 GitHub release asset | −12 | −22 (open-platform cluster of 2) |
| L13 2-month-old indie domain | −12 | −12 |
| A07 Discord attachment .exe from chat | −12 | −32 Suspicious |
| A03 raw GitHub .ps1 from chat | −25 | −44 Suspicious |
| A04 webmail → 2-month domain | −12 | −32 Suspicious |
| A01 Discord extensionless (R1) | −27 (always warns) | −36 Suspicious |
| A05 `cdn-ccleaner-update.top` | −72 | −72 (the word "cdn" gives nothing) |
- HIGH column: attacks A03/A04/A06/A07 stay Inconclusive (×0.5 multiplier and cluster needs 4) — listed, not
  gated; see "open" below.

### Tests
- tests/DeliveryContext.test.js (28): anchors (label boundary, keywords, user-content hosts, table shape),
  explain (modes, WHO block, WHAT never, platform tolerance, mirror downgrade, no mutation), cluster (thresholds,
  same-family = one oddity, strong family excluded, open platform, floor, explained excluded), credit conditions,
  integration (screenshot case Probably Safe at MEDIUM, LOW keeps signals, C2 on DELIVERY, families registered).
- Suite 478 → 506, all pass; complete-check passes (fp-sweep incl. 23 flows × 4 levels, MV3).

### Also in 3.5.0 (added before release) — FP level HIGH multiplier; shared MV3 check; IANA list
User decision 2026-10-24 on the "open" item below, folded into 3.5.0 (nothing published yet).
- `SCORING_CONFIG.FP_UNKNOWN_MULTIPLIERS.HIGH` 0.5 → 1.0. HIGH was lenient twice (DeliveryContext strategy +
  halving). Flows at HIGH, before → after: A03 raw-GitHub .ps1 from chat −22 → −44 Suspicious; A06 invoice.pdf as an
  executable −22 → −45 Suspicious; A02/A05 −36 → −72 Malicious; A01 −13 → −27, A04/A07 −6 → −12 (stay
  Inconclusive: HIGH needs 4 weak oddities by design). Every legit flow stays below Suspicious at HIGH (worst:
  VLC HTTP mirror and Ubuntu over HTTP −25). No test pinned the old value; no UI text promised halving.
- tools/check-mv3.mjs: no longer imports repoPaths.mjs (3P Matrix's flat tools folder has none); default folder
  computed from its own location (DS layout); accepts `--ext` and `--extension`. Byte-identical with
  3P Matrix 4.4.0's copy.
- IANA RDAP bootstrap refreshed from the user-supplied dns.json (publication 2026-10-22T23:00:04Z):
  RdapCctlds 72 → 73 (`sc` added). The tool also regenerated PlatformSuffixes from the CACHED
  tools/lists-raw/public_suffix_list.dat, which is OLDER than the PSL the shipped list was built from (it would
  drop 78 recent entries, e.g. new AWS suffixes, and re-add 18 removed ones) — that output was discarded and the
  shipped PlatformSuffixes kept in 3.5.0 (refreshed in 3.5.1).

### Same-company referrers + rule C7 (user report 2026-10-24, Discord screenshot)
- Report: a Discord attachment (cdn.discordapp.com) clicked in a Discord chat showed "Download referrer
  ("discord.com") is unrelated to the download host" — false: one company. User proposed dropping the referrer
  signal when the host name contains "CDN"; not done that way (keyword is attacker-controlled — fp flow A05
  `cdn-ccleaner-update.top`), replaced by an anchored table, as agreed.
- util/DeliveryPatterns.js `SAME_COMPANY` (Discord, GitHub, Google, Microsoft, Mozilla, Gen Digital, Valve, Dropbox,
  Apple, Meta, Telegram, MEGA) + `companyOf(host)` / `sameCompany(hostA, hostB)`, matched on host labels — not via
  the registered domain, because the PSL lists some as platform suffixes (githubusercontent.com).
  FilenameUrlHeuristics.checkReferrerMismatch returns null for same-company pairs (a relation, not trust:
  user-content domains are listed on purpose; RiskyHosting still scores the host).
- Side effect found by measuring: without the false −12 the Discord .exe fell to −10 (RiskyHosting halved as
  "solo", MessageOrigin −10 below the stacking floor). Fixed with the agreed rule:
  CombinationScoring C7 (−15) "File on a file-sharing platform, link opened from a chat or webmail" = RiskyHosting +
  MessageOrigin, and `SCORING_CONFIG.RISKY_HOSTING_CORROBORATING_SOURCES = ["MessageOrigin"]` (no halving then).
  Result MEDIUM: Discord .exe from chat −35 Suspicious (was −32 via the false referrer).
- Flows (MEDIUM): L06 GitHub release −22 → −5; L07 −29 → −15; A01 −36 → −42; A03 −44 → −59; A07 −32 → −35; at LOW,
  Firefox/Steam/Discord-app now 0 (referrer no longer counted). All gates pass.
- Host label (ScoringEngineV2): always "<n> heuristic risk signal(s) detected — <classification>". Before: the
  combined case showed only the count (no verdict — user report, Discord screenshot), and the single-signal case
  always said "domain probably suspicious"/"probably malicious", even for an Inconclusive −12. Test updated.
- WarningPage.css: `#bpResult, #hostResult { word-break: normal; overflow-wrap: anywhere }` — the longer verdict
  line broke inside a word ("suspicio/us") under `.value`'s break-all (kept for URLs). 3P Matrix already had this.
- A "Together: <rule>" line on the warning page was tried and removed at the user's request (the page already
  says how many signals were found); combination rules stay internal, as before.
- Tests: CCleaner case (no referrer signal any more), Discord case (−35, C7, not halved), C7 needs both, same-company
  matching incl. negatives (notdiscord.com, evil.github.io). Suite 506 → 509.

### Open
- Vendor table is hand-curated: add vendors on request; review yearly (hosts move).
- Decided 2026-10-24: cdn.jsdelivr.net stays on SuspiciousDomains; `vue.global.js` remains an accepted knownGood exception.
- Public Suffix List raw file in tools/lists-raw is stale (see above): refresh before the next PlatformSuffixes rebuild.

---

## 3.4.0 (not released separately — included in 3.5.0) — heuristics R1/R2/R4 (extensionless binaries, risky hosts, name vs type); signal weight review; MV3 compliance check; fp-sweep as a hard gate

Source worked from: DownloadSentinel 3.3.1 extension + tools + docs (uploaded 2026-10-24).
Trigger (user, 2026-10-24): URLhaus #3982093 — `https://cdn.discordapp.com/attachments/…/6962f1be0c?ex=…`,
80.3 MB, `application/octet-stream`, saved as `6962f1be0c`; no warning. Root cause: `classifyDownload()`
returned null (no dangerous/archive extension, MIME not in EXECUTABLE_MIMES), so none of the existing signals
(RiskyHosting −20 for cdn.discordapp.com, MimeCheck) ever ran. Decided with the user: R1 = always warn plus a
score (−15 chosen over the user's first idea −5: −5 sits below the stacking floor and would never combine);
R2 and R4 as proposed; each signal its own value. Same change to be ported to 3P Matrix (shared lib).

### R1 — extensionless generic binary (util/FilenameAnalysis.js, util/DangerousMimes.js)
- New `DangerousMimes.GENERIC_BINARY_MIMES` (single source): application/octet-stream, binary/octet-stream,
  application/x-octet-stream, application/binary, application/x-binary, application/unknown,
  application/force-download, application/x-download, application/download.
- New `FilenameAnalysis.FILE_TYPE` enum { EXECUTABLE, ARCHIVE, UNKNOWN_BINARY } replaces the two literals.
- "Visible extension" = text after the last dot matching `VISIBLE_EXT_PATTERN` (1–10 of [a-z0-9], ≥1 letter);
  `getVisibleExt()`, `findVisibleExt(url, rawUrl, filename)` (filename → final URL → original URL).
  So `tool-v1.2` and `rg-14.1.0-x86_64-linux` count as extensionless; `notes.txt` does not.
- classifyDownload: `isUnknownBinary` = no monitored ext, no visible ext, MIME ∈ GENERIC_BINARY_MIMES →
  fileType UNKNOWN_BINARY. An empty MIME (common at onCreated) never triggers it; the late-entry path does.
- Score: `SCORING_CONFIG.EXTENSIONLESS_BINARY_SCORE = −15` (Check 26, source "ExtensionlessBinary", family
  FILE_DECEPTION). Equal to `CombinationScoring.CONFIG.STACK_MIN_SIGNAL`, so it stacks — a Discord hit is then
  no longer a "solo" RiskyHosting (halved to −10) but −20 combined with −15.
- Switch `APP.EXTENSIONLESS_BINARY_ALWAYS_WARN = true`: skips autoAllow ("Silent when probably safe") for
  these records — a minutes-old upload is usually unknown to VirusTotal, so "probably safe" says little.
- StagingCheck lure words weigh an UNKNOWN_BINARY like an executable (was: 0, as "other").

### R1 completion handling — new util/DownloadShape.js (pure, shared with 3P Matrix)
- `reevaluate(record, confirmedFilename)` → OUTCOME.KEEP | RELEASE | BECAME_KNOWN, using classifyDownload
  with the confirmed name: ordinary name (`clip.mp4`) → RELEASE (background.js `releaseWithoutWarning()`:
  pendingChecks entry deleted, in-flight VT aborted, checkedIds kept for dedup — cleaned by onErased/sweep as
  before); dangerous/archive name (`setup.exe`) → BECAME_KNOWN: record updated, host reputation re-run, and the
  existing obfuscation signal (UNKNOWN_REVEALED −50) reports the hidden extension instead of R1.
- `mustAlwaysWarn(record)`, `shapeOf(source)` → the new trailing `downloadShape` argument of
  `BrowserProtection.checkHostReputation(…, dnsSettings, downloadShape)` ({ visibleExt, isUnknownBinary };
  null keeps old behaviour — every existing caller/test unchanged).

### R2 — risky hosting
- No list change: cdn.discordapp.com / media.discordapp.net / attachments.discord.com stay −20. What changed is
  that R1 lets these downloads reach the check at all, and corroboration stops the halving (see R1 score).

### R4 — visible extension vs MIME type
- MimeCheck now receives `ext || visibleExt`: `invoice.pdf` served as application/x-msdownload scores the
  mismatch (−45 after the weight review below) (before: ext null → "MIME type unavailable", 0).
- New derived `DangerousMimes.ARCHIVE_MIMES`; classifyDownload `isMimeArchive`: archive MIME + visible ext the
  MIME table does not list for it → monitored as ARCHIVE (e.g. `invoice.pdf` as application/zip).
- New `ZIP_CONTAINER_EXTS` (docx/docm/xlsx/xlsm/pptx/pptm, odt/ods/odp/odg, epub, whl/egg/nupkg/vsix/aar,
  jar/apk/xpi, kmz/3mf/xps/oxps) added to the three zip MIME entries — found by fp-sweep: the knownGood PyPI
  wheel (`requests-…-none-any.whl` as application/zip) became monitored without it. Back to "Not monitored".
- MimeCheck's neutral set is now GENERIC_BINARY_MIMES + text/plain (was three literals): an `.exe` served as
  application/force-download (or x-download, …) no longer gets a false −60.

### Signal weight review (user request 2026-10-24, with a CCleaner warning page as example)
- Example: `https://bits.avcdn.net/productfamily_CCLEANER7/…` (no extension, ccsetup.exe), referrer
  www.ccleaner.com → −50 "Probably Suspicious". Replayed: ONE signal decided it (Obfuscation UNKNOWN_REVEALED
  −50); ReferrerMismatch −12 is weaker than CombinationScoring.CONFIG.STACK_MIN_SIGNAL (−15), so it never
  stacks. Several weights date from before combination scoring (v2.9.0, "worst single signal wins").
- Method: scratch replay of fp-corpus (56 knownGood, 24 stagingSynthetic) plus hand-made attack cases, each
  also as "extension hidden at start", "plain HTTP" and "VT unknown" at FP level Low/None.
- Changed (SCORING_CONFIG; each stays ≤ STACK_MIN_SIGNAL, so it still stacks):
  | Signal | Was | Now | Evidence |
  |---|---|---|---|
  | OBFUSCATION_UNKNOWN_SCORE | −50 | −20 | hidden variant: 54/54 knownGood ≥ Suspicious (11 Malicious) → 0 Malicious, 11 Suspicious (10 install scripts + 7-Zip on SourceForge) |
  | HTTP_PENALTY | −40 | −25 | HTTP variant: 54/54 ≥ Suspicious → 12, none Malicious |
  | MIME_MISMATCH_SCORE (new; was a −60 literal in MimeCheck.js) | −60 | −45 | see MIME table gaps below |
  | LOOKALIKE_SITE_SCORE | −45 | −35 | ~1% Bloom-filter false matches; curated brand stays −65 |
  - SIZE_EXCEEDS_VT_SCORE (−20) also moved from a MimeCheck.js literal into SCORING_CONFIG, value unchanged.
- Attack cases after the change: hidden .exe on a DuckDNS host −91 → −76 Malicious; invoice.pdf as an
  executable −78 → −63 Malicious; hidden .exe on a 5-day-old domain −75 → −50 Suspicious; bare IP + HTTP + .exe
  −65 → −52 Suspicious; invoice.pdf.exe −50 unchanged. CCleaner: −20 Inconclusive (Low −30, None −40).
- Kept: double extension, RLO/padded, URL credentials, HTTPS→HTTP downgrade, IP host, script, launcher, staging
  formats, list scores, RDAP ages, combination rules and floor, FP-level multipliers (user's own choice).
- MIME table (util/DangerousMimes.js): 9 official/common types gave a FALSE −60 mismatch — added
  application/vnd.debian.binary-package (deb — Docker's own .deb was frozen as "Suspicious" in the fp
  baseline), application/x-redhat-package-manager (rpm), application/vnd.android.package-archive (apk),
  application/x-xpinstall (xpi), application/x-chrome-extension (crx), application/x-shellscript (sh, bash),
  application/x-cd-image (iso), application/vnd.appimage, application/x-ole-storage (msi/msp + doc/xls/ppt/msg),
  bat under application/x-msdos-program. New `AMBIGUOUS_CONTAINER_MIMES` (x-ole-storage) is excluded from the
  derived EXECUTABLE_MIMES — otherwise every legacy .doc served as an OLE container would open a warning page.
  application/x-shellscript now counts as an executable MIME (like application/x-sh).
- Removed `APP.OBFUSCATION_UNKNOWN_SCORE` (−40) / `APP.OBFUSCATION_CATEGORY_CHANGE_SCORE` (−20): unused copies
  that disagreed with SCORING_CONFIG.
- Tests that pinned old numbers now derive them from the constants (MimeCheck.test.js; ScoringEngineV2.test.js
  "SKIPPED slot" test — intent "only the HTTP signal counts, no hard rule" kept).

### Tools — false-positive sweep is now a hard gate (#17 in complete-check)
- tools/fp-sweep.mjs was never run by complete-check (its header called it a hard gate — C38).
- New gates: (1) absolute — an as-is knownGood entry at Probably Suspicious or worse FAILS unless it carries
  `acceptedRisk` + `acceptedReason`; (2) variants — every knownGood entry is also scored with the extension
  hidden at start (`FilenameAnalysis.getObfuscationSignal(null, ext)`) and over plain HTTP; Malicious FAILS,
  Suspicious is listed for review. Verified: with the pre-review weights the sweep fails (11 variant scores at
  Malicious); with the new weights it passes. (3) R1/R4 inputs passed like checkHostReputation().
- `cdn.jsdelivr.net/npm/vue@3.5.12/dist/vue.global.js` (ScriptFormat −25 + DomainList −24 = −37) marked
  `acceptedRisk` — owner decided (2026-10-24): keep warning, jsdelivr stays on SuspiciousDomains.
- Baseline refreshed (`--update`) after the review.

### Tools — MV3 compliance check (tools/check-mv3.mjs, new; hard gate #16 in complete-check)
- Manifest: M1 manifest_version 3; M2 service-worker-only background; M3 no browser_action/page_action;
  M4 no webRequestBlocking, host patterns only in host_permissions; M5 CSP object form, extension_pages script
  sources limited to 'self'/'none'/'wasm-unsafe-eval'/localhost; M6 web_accessible_resources object form;
  M7 DNR rule_resources fields + file exists + JSON array.
- Code (espree AST, not regex): C1 eval / Function / string timers; C2 remote code (import, import(),
  importScripts, re-exports, HTML `<script src>` to http(s):// or //); C3 MV2-only APIs (extension.getURL,
  tabs.executeScript, browserAction, …); C4 DOM-only globals (window, document, localStorage, …) in the service
  worker and every module it statically imports (eslint-scope free references; `typeof x` allowed);
  C5 a file that cannot be parsed is a finding, never silently skipped.
- Same file for 3P Matrix: `--ext <folder>`; `--json`; exit 0/1/2 (2 = could not run → FAIL in complete-check).
- `npm run mv3`; devDependencies `espree ^9.6.1`, `eslint-scope ^7.2.2` (already installed via ESLint 8, now
  declared); knip entry added for the tool so they don't show as unused.
- tests/CheckMv3.test.js builds a broken MV2-style extension in a temp folder (released in afterEach) and
  asserts every rule id fires; a clean MV3 one passes. DS 3.4.0 and 3P Matrix 4.3.7 are both compliant.

### Also
- package-lock.json was still at 3.3.0 in the 3.3.1 zip (complete-check FAIL on the baseline) — now 3.4.0.
- Tests: tests/DownloadShapeHeuristics.test.js (29 cases incl. the Discord URL end-to-end with the network
  stubbed), tests/CheckMv3.test.js (7). Suite 442 → 478, all pass; fp-sweep: no knownGood regressions.

### Known limitations / not done
- `IANA RDAP bootstrap registry` not refreshed: minor bump policy (`updateOn: minor`), but this environment
  cannot reach data.iana.org. Run `node tools/update-domain-age-lists.mjs --fetch` before publishing.
- R1 is bypassed by any made-up extension (`payload.dat`); only the magic-bytes check (R3, deliberately out of
  scope) would catch that.
- A GitHub Linux release binary (`tool-linux-amd64`) now always warns — by decision (warn, never block).
- Residual review items from the sweep (Suspicious, not failing): install scripts from an extensionless link or
  over HTTP (script −25 stacks), 7-Zip from SourceForge with a hidden extension (RiskyHosting −25 stacks).

---

## 3.3.1 — DNS4EU + CleanBrowsing as DNS checks 4 and 5; France defaults; optional host permissions

Source worked from: DownloadSentinel 3.3.0 extension + tools (uploaded 2026-10-24).
Trigger (user, 2026-10-24): Quad9 refuses the Paris court's blocking order (beIN/Canal+, WTA streams; beIN seeks
up to €10,000 per domain per day, ~€580k/day for 58 domains) and says it may leave France — not left as of
2026-10-24. Asked: a fourth malware-blocking DNS, and France default = Control D first, Cloudflare 1.1.1.2 second.

### Providers (util/AppConstants.js — single source of truth)
- New enum `DNS_BLOCK_STYLE` (declared above `APP`, exposed as `APP.DNS_BLOCK_STYLE`): NXDOMAIN_NO_AUTHORITY,
  ZERO_IP, BLOCKPAGE_IP, RPZ_SOA. Providers and DnsThreatProtection compare against it, no raw strings.
- `dns4eu` — DNS4EU Protective (EU-funded, run by Whalebone), `https://protective.joindns4.eu/dns-query`,
  BLOCKPAGE_IP, `blockPageIps: ["51.15.69.11"]`. Verified live 2026-10-24 against 86.54.11.1 (same profile, via
  digwebinterface.com): malware.wicar.org → A 51.15.69.11; thisdoesnotexist-12345.com → NXDOMAIN with the "com."
  registry SOA; malware.testcategory.com → real A records. DNS4EU applies court orders on every profile.
- `cleanbrowsing` — CleanBrowsing Security Filter, `https://doh.cleanbrowsing.org/doh/security-filter/`,
  RPZ_SOA, `rpzSoaMnameSuffix: "rpz.noc.org"`. Verified live 2026-10-24 against 185.228.168.9:
  malware.wicar.org → no answer + SOA `malware.wicar.org. SOA cleanbrowsing.rpz.noc.org. accesspolicy.rpz.noc.org.`;
  thisdoesnotexist-12345.com → `com. SOA a.gtld-servers.net.`; example.com → real A records. A block and a
  non-existent name are both answerless; only the Authority SOA's MNAME tells them apart.
- Considered and not taken: Mullvad base / AdGuard (also block ads → harmless ad domains would score as malware);
  OpenDNS (left France in 2024); dns0.eu (closed 2025).

### Detection (protection/DnsThreatProtection.js)
- parseDnsResponse now also reads the Authority section and returns `authoritySoas: [{ owner, mname }]`
  (lower-case, no trailing dot; SOA = type 6, `DNS.TYPE_SOA`). Guard: the section is supplementary — a
  truncated/malformed Authority section stops collection (collectAuthoritySoas in try/catch) without discarding
  the answers/rcode already parsed; an unreadable section can never yield BLOCKED.
- RPZ_SOA: BLOCKED when there is no usable answer and an SOA MNAME equals or ends on a label boundary with
  `rpzSoaMnameSuffix` (so "evilrpz.noc.org" does not match); else NXDOMAIN → UNKNOWN/NXDOMAIN. Missing/empty
  suffix → never BLOCKED (fail open).
- BLOCKPAGE_IP: BLOCKED when an answer is in `blockPageIps` or is 0.0.0.0 / ::. Other styles ignore both lists.
- If a provider moves its block page / policy zone, blocks fall through as ALLOWED (neutral), never a false
  "Confirmed malicious" — update the constant.

### Region defaults (util/DnsDefaults.js, new)
- `APP.DNS_REGION_DEFAULTS`: rule FR → first `controld`, second `cloudflare`; time zones Europe/Paris + overseas
  (Cayenne, Guadeloupe, Martinique, Marigot, St_Barthelemy, Miquelon, Reunion, Mayotte, Kerguelen, Tahiti,
  Marquesas, Gambier, Noumea, Wallis). Europe/Monaco deliberately excluded.
- DnsDefaults.get() detects the IANA zone offline (Intl; no network, no permission), caches a frozen
  { first, second, region }; reset() clears the cache; resolveForTimeZone(tz) is pure. Every failure (Intl
  throwing, unknown zone, a rule naming a removed provider or an optional-permission provider) → the global
  APP.DEFAULT_DNS_FIRST / _SECOND (quad9 / controld, unchanged).
- All former direct reads of APP.DEFAULT_DNS_* now go through DnsDefaults: Settings.js defaultSettings,
  background.js buildSettingsSnapshot (validDnsProviderId fallback), BrowserProtection.checkHostReputation,
  OptionsPage.js (load + Save All guard).
- Known limitation: Settings.set persists the full merged object, so a user who ever saved any setting has the
  old defaults stored and keeps Quad9 — no migration (offered to the user, not requested).

### Optional host permissions (util/DnsPermissions.js, new)
- Providers with `optionalPermission: true` (dns4eu, cleanbrowsing) are in manifest `optional_host_permissions`,
  not `host_permissions`, so the 3.3.0 → 3.3.1 update triggers no Chrome re-approval (a new required host would
  disable the extension until approved).
- Lifecycle: OptionsPage requests the origin synchronously in the dropdown's change handler (user gesture kept;
  declined → dropdown reverts to its previous value, message in #dnsStatus); after each save,
  releaseUnused([first, second]) removes grants no slot uses. On Options load, a selected provider without its
  grant shows a notice.
- DnsThreatProtection.check: optional provider without grant → no fetch, UNKNOWN with new reason code
  `PERMISSION_MISSING`; WarningPage DNS_UNKNOWN_TEXT: "not checked — permission not granted (allow it in Options)".
- Every DnsPermissions function guards a missing chrome.permissions and never throws (failure = not granted).

### UI
- OptionsPage.html DNS section shortened (user: text too long): heading "Threat-intel DNS — two of five"; one-line
  intro; "Pick two you do not already use as your own DNS — that one already blocks bad sites."; NextDNS
  "Block Bypass Methods" hint reduced to one sentence + "check unavailable, never as safe". No France note in
  the UI (the default simply applies). Dropdown entries come from APP.DNS_PROVIDERS as before.

### Manifest / versions
- manifest.json 3.3.0 → 3.3.1; optional_host_permissions: protective.joindns4.eu, doh.cleanbrowsing.org.
- TOOLS package.json 3.3.0 → 3.3.1.

### Tests (TOOLS)
- 410 → 442, all passing (also with TZ=Europe/Paris). New: tests/DnsDefaults.test.js (regions, fallbacks, cache,
  manifest ↔ provider consistency, no optional provider as a region default), tests/DnsPermissions.test.js.
  DnsThreatProtection.test.js: dns4eu and cleanbrowsing suites from the live-observed records, truncated
  Authority section, look-alike MNAME, permission guard. Fixture builder takes real Authority SOA records.
- helpers/chromeMock.js: chrome.permissions mock (contains/request/remove) with init/clear/release
  + setGrantedOrigins().
- eslint clean; check-magic-numbers unchanged vs 3.3.0 (38 lines, all pre-existing); no circular imports;
  knip: only the pre-existing AGE_NA.

### Not verified here
- The Chrome permission prompt itself (no real Chrome in the build environment).
- DoH endpoints directly (build environment cannot reach DNS servers); verification used the same profiles'
  plain-DNS addresses. Check once in the browser: a download from malware.wicar.org.

### For 3P Matrix
- When 3P Matrix moves to DS 3.3.1: SPEC_levels_and_protections.md lists three DNS providers (lines ~134–136) —
  add DNS4EU and CleanBrowsing with their block styles; its own core/online-checks.js DNS code (two
  implementations kept, 4.3.4 item 21) needs the same RPZ_SOA / BLOCKPAGE_IP handling and the France default
  if it should match.
