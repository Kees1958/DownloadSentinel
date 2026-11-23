# Changelog — DownloadSentinel

Short, per-release summary of what changed. The full technical account is CHANGELOG_HISTORY.md.

## 3.6.0
- **Built-in lists refreshed** (minor release; the same snapshots 3P Matrix 5.0 ships, so both extensions again
  carry identical list data): Public Suffix List and hosting-platform list (Public Suffix List of 2026-11-06), and
  the risky-hosting table (HaGeZi DynDNS and Badware Hoster of 5 November 2026). Popular-sites and RDAP lists were
  already current.
- **Hardening** (from 3P Matrix 5.0.6–5.0.7): DownloadSentinel's own pages now refuse plug-ins, forms and
  page-address tricks; only DownloadSentinel's own pages may send it messages (not just anything carrying its id);
  the VirusTotal re-check message acts only on the download of the warning page that sent it; a refused message
  is logged with the sender's site only, and no log line contains a download address any more.
- Downloads are judged exactly as in 3.5.6 — 3P Matrix 5.0.5–5.0.8 changed nothing in the download check.
- Project: the GitHub repository now holds the unpacked source like uBlock Dynamic and 3P Matrix (extension in the
  root, `tools/`, changelogs in the root). Tools: one new release check (only runtime files in the extension zip,
  versions match, no new permission without approval) that can also cut the three zips, and new seeded fuzz tests
  for download addresses, file names and the message gate.

## 3.5.6
- **Small warning signs now add up when they are all we have, from a dubious source.** Until now a sign weaker
  than −15 (e.g. "file served via a script or parameter") never counted next to a stronger one. Now it does — with
  the usual decay — when VirusTotal does not know the file (no key, no answer in time, or never seen) AND the source
  is dubious: a host on the misused-for-malware, file-sharing, campaign or host-threat list, an abused TLD, a very
  young domain or a DNS threat hit. When VirusTotal knows the file, nothing changes. Real case: a hidden `.bin` from
  a Google Drive link. A small sign does not also undo the "file-sharing platform alone counts half" rule, and a
  group of small signs that already counts as a cluster is not counted twice.
- The warning page shows the host verdict that was actually used, and switches when a late VirusTotal answer
  changes which one applies.

## 3.5.5
- **Large files without an extension from a file-sharing site** (from 3P Matrix 4.5.6 + 4.5.8): from 32 MB they
  are rated "Probably Suspicious" ("Large file … often padded or packed malware"). From 650 MB the warning is
  stronger: "large downloads are often used by malware to evade AV detection". For such a file it replaces the
  "exceeds VirusTotal maximum" line, so the same fact is not counted twice; other large downloads keep that line.
- **GitHub/GitLab campaign links:** the "currently used to deliver malware" line no longer also shows the
  file-sharing platform line (both said the same thing about the host, and that line could read "no other
  corroborating signal, so halved" right above it). The line now weighs −30 instead of −40: on its own it is
  "Probably Inconclusive" (the warning still opens unless "Silent when inconclusive" is on); it is a minimum, so
  the verdict only gets worse when other signals already score lower on their own.
- Public Suffix List rebuilt from the same snapshot (2026-10-25) that the hosting-platform list already used since
  3.5.1: 66 platform and cloud entries added (e.g. Amazon Bedrock consent portals), 5 retired ones removed. It was
  still the 2026-10-21 build. DownloadSentinel and 3P Matrix now ship identical list data.
- **Faster start:** the built-in lists are now read only when a download is actually checked, not every time the
  extension wakes up (from 3P Matrix 4.5.4).
- Tools: a list built from an older copy of its source than the one cached now (the Public Suffix List case above)
  fails the release check.

## 3.5.4
- **Downloads from GitHub/GitLab campaign links are now flagged** (from 3P Matrix 4.4.9–4.5.1). Since late
  October these hosts are the main way malware is spread (≈ 84 % of the URLhaus feed). An archive or program
  (`.zip`, `.exe`, `.ps1`, …) from `raw.githubusercontent.com` and GitHub's other file hosts, or from a
  GitHub release / raw link or a GitLab raw link, now scores at least −40 ("probably suspicious"), shown as
  "Currently used to deliver malware as a .exe file (github.com)". Ordinary files from these hosts
  (`.js`, `.md`, images, …) and normal GitHub browsing are not affected. DownloadSentinel also checks the
  original link, so a release download that GitHub redirects to an address without a file extension is
  still recognised.
- GitHub's own **"Download ZIP"** button produces the same kind of link; when nothing else about that download is
  wrong, the warning page adds "When you pressed the “Download ZIP” button on GitHub, it might be a false alarm."
- **New button scheme in the warning window** (from 3P Matrix 4.4.6): colour follows risk, rising from left to
  right — "Check download at VT" (green) comes first, "Proceed anyway" (orange) second, and both buttons are the
  same size. Enter now checks the download instead of proceeding. The focus ring only appears when you use the
  keyboard (Tab / arrow keys).

## 3.5.3
- **New setting: "Silent when inconclusive"** (just above "Silent when probably safe") — **off by
  default.** Splits out the staged, false-positive-reduction-based quiet behaviour added in 3.5.2:
  when a download is neither clearly safe (auto-allow) nor clearly risky (an exception), it used to
  stay quiet below the false-positive setting's threshold. Now that only happens when you turn this
  on; off (the default), every such download gets a warning window, whatever its score — matching how
  downloads worked before 3.5.2. "Silent when probably safe" and the exceptions that always warn are
  unaffected either way.

## 3.5.2
- **Fewer interruptions, never for the dangerous cases.** The warning window is now staged by the false-positive
  setting: it opens from score −45 (High), −30 (Medium), −15 (Low), and for every checked download at None.
  It always opens, whatever the score, when VirusTotal or a DNS check flags the file, it imitates a brand or popular
  site, the file itself looks deceptive or is a script, the link came from a chat or webmail, or the domain is very
  new. Ordinary vendor downloads (CCleaner, Firefox, VLC mirrors, 7-Zip, …) no longer interrupt at Medium.
- **Nothing is hidden:** a download checked without a window is counted on the toolbar icon and listed in the popup
  ("Checked without a warning window"); opening the popup clears the count.
- A file from a brand name on an open platform (e.g. `paypal-login.vercel.app`) is now recognised as imitation.
- If VirusTotal answers late and the file now deserves a window, it still opens.
- Options explain from which score a window opens at each setting.

## 3.5.1
- Hosting-platform list refreshed (Public Suffix List of 2026-10-25), and 13 platforms with non-English names
  (e.g. `günstigbestellen.de`) are now actually recognised — they were stored in a form that never matched.
- Tools: the Manifest V3 check comment now refers to 3P Matrix 4.4.0 (file identical in both projects).

## 3.5.0
- **Downloads are now judged as a whole journey, not as a pile of separate points.**
  - **Ordinary vendor deliveries are recognised.** When a file comes from a vendor's own download servers
    (Microsoft, Mozilla, Google, Gen Digital/CCleaner/Avast, Steam, Discord's app installer, Brave, Adobe,
    JetBrains, Opera, NVIDIA, Spotify), the usual quirks of such a download no longer count against it: a
    different referring page, no extension in the link, a short link, or a link shared in a chat. They are
    still listed on the warning page, in grey, with "normal for … downloads". A CCleaner download: from
    −50 to 0 ("probably safe"). Only real vendor servers count, never a name containing "cdn" or "download".
  - **Several small oddities together now add up.** On their own they are everyday noise; three of them
    together (e.g. a link from webmail + a two-month-old domain + an unrelated referrer) now count in full.
    On file-sharing sites (Discord, Dropbox, GitHub raw, …) two are enough.
  - **New small signal: "link opened from a chat or webmail page"** (Gmail, Outlook, Discord chat, WhatsApp
    Web, Telegram Web, Teams, Slack).
  - **Established, well-known sites get a small bonus** when nothing about the sender or the file is wrong.
  - **The false-positive setting now changes how the extension reasons**, not just how hard it scores:
    High and Medium recognise vendor deliveries and need 4 / 3 small oddities; Low and None count everything
    and need 2.
  - Mirror networks (VideoLAN, LibreOffice, SourceForge) that switch to plain HTTP, and SourceForge's own
    "latest download" links, are recognised as such.
- Examples at the default setting: a Discord-attachment program from a chat link −12 → −32, a PowerShell
  script from raw GitHub via a chat −25 → −44, a webmail link to a two-month-old domain −12 → −32 (all now
  "suspicious"); VLC from an HTTP mirror and 7-Zip via SourceForge's download link are no longer "suspicious".
- Warning page: the reputation box now always gives the verdict with the count ("2 heuristic risk signals
  detected — probably suspicious"); a single weak signal no longer says "probably suspicious" when it is only
  inconclusive.
- Warning page: dashes and quotes in messages are no longer dropped ("was hidden — no extension").
- **False-positive setting "High" no longer halves every warning signal** when VirusTotal does not know the
  download. High now gets its fewer alarms from the smarter rules above (recognised vendor deliveries, more small
  oddities needed); halving on top made real deception slip through. A PowerShell script from raw GitHub via a
  chat now scores −44 and a fake `invoice.pdf` that is really a program −45 at High (were −22, "inconclusive").
  Legitimate downloads stay quiet.
- Tools: the Manifest V3 check is now one identical file in DownloadSentinel and 3P Matrix.
- Country-code list for domain age refreshed from IANA (2026-10-22): `.sc` added (73 codes).
- **A page and a download host of the same company are no longer called "unrelated"** (e.g. discord.com →
  cdn.discordapp.com, github.com → objects.githubusercontent.com, ccleaner.com → avcdn.net).
- **New combination: "file on a file-sharing platform + link opened from a chat or webmail"** — the classic lure
  (e.g. a `Nitro_Generator.exe` on Discord's file host clicked in a Discord chat: now −35, "suspicious").
- Includes everything from 3.4.0 (not released separately).

## 3.4.0 (not released separately — included in 3.5.0)
- **Files that hide what they are now get checked.** A download with no extension anywhere (link and file name)
  that the server only calls "binary data" (`application/octet-stream` and similar) used to pass unchecked. It
  now always opens the warning page (−15), even with "Silent when probably safe" on. Trigger: a URLhaus malware
  sample on Discord's CDN (`…/6962f1be0c`, 80 MB, octet-stream) on 2026-10-24.
  If the finished download turns out to have an ordinary name (e.g. `clip.mp4`), nothing is shown.
- **Risky hosting now counts for those files too**: such a file from Discord's CDN scores −15 + −20 together
  instead of slipping through.
- **Name and type must agree**: `invoice.pdf` served as a program or as an archive is now flagged (−45).
  Formats that really are zip files (Word, OpenDocument, e-books, Python wheels, …) are not.
- **Fewer false alarms — signal weights reviewed now that signals add up:**
  - "Extension hidden at download start" −50 → −20. Vendor download links (Microsoft, Mozilla, Google, Adobe,
    CCleaner) work this way; a CCleaner installer went from −50 "Suspicious" to −20 "Inconclusive".
  - Plain HTTP −40 → −25, name/type mismatch −60 → −45, look-alike of a popular site −45 → −35.
- **Nine correctly served file types no longer count as a "type mismatch"**, e.g. `.deb`, `.rpm`, `.apk`,
  `.xpi`, `.sh`, `.iso`, `.AppImage` sent with their official type.
- An `.exe` sent as `application/force-download` is no longer a false "type mismatch".
- Tools: new Manifest V3 compliance check (`npm run mv3`) and the false-positive sweep, both now part of
  `npm run check`; the sweep also tests hidden-extension and plain-HTTP versions of every known-good download.

## 3.3.1
- **Two new DNS checks: DNS4EU Protective and CleanBrowsing Security** (both free, malware and phishing only).
  The DNS checks now offer **two of five**: Quad9, Cloudflare Security, Control D, DNS4EU, CleanBrowsing.
- **In France the default is now Control D + Cloudflare Security (1.1.1.2)** instead of Quad9 + Control D.
  A DNS choice you saved is never changed.
- Options: shorter DNS text.
- DNS4EU and CleanBrowsing **ask for permission only when you pick them** — updating needs no new approval.
  The permission is dropped again when neither DNS check uses them. If it is missing, the warning page says
  "not checked — permission not granted", never "safe".
- Note: DNS4EU also applies court-ordered blocks (e.g. piracy sites); such a site can show as blocked too.
