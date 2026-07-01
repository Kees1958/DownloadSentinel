"use strict";

/**
 * RiskyHostingSites.js
 *
 * Identifies download URLs hosted on platforms where the main domain is
 * reputable but content is user-uploaded and unvetted, OR platforms with
 * a high historical malware distribution rate.
 *
 * Match modes:
 *   exact: true  — only the specified hostname matches
 *   exact: false — hostname OR any subdomain matches (suffix match)
 *
 * Score guidance:
 *   -15  Reputable platform, accountable users (Dropbox, OneDrive direct)
 *   -10  Accountable platform, auditable content (GitHub CDN subdomains)
 *   -15  Accountable platform, less mainstream (GitLab, Bitbucket, Codeberg)
 *   -20  Requires account, content unvetted (Discord CDN)
 *   -35  Mixed reputation, some moderation (SourceForge, NexusMods, paste sites)
 *   -45  High abuse rate, some anonymous uploads (MEGA, MediaFire, ROM sites)
 *   -55  Primarily used for piracy/cracks (getintopc, softonic-type)
 *   -65  Designed for anonymous uploads (AnonFiles variants)
 *   -70  Cheat/hack forums, game exploit sites
 *   -75  Crack/warez/nulled software sites
 *   -80  Roblox/child-targeted exploit sites (extremely high risk)
 */
const RiskyHostingSites = (function () {

    const SITES = [

        // ── GitHub content subdomains ─────────────────────────────────────────
        // Main github.com is trusted; these subdomains serve unvetted user content
        { host: "raw.githubusercontent.com",              score: -10, exact: true  },
        { host: "release-assets.githubusercontent.com",   score: -10, exact: true  },
        { host: "codeload.github.com",                    score: -10, exact: true  },
        { host: "objects.githubusercontent.com",          score: -10, exact: true  },
        { host: "media.githubusercontent.com",            score: -10, exact: true  },

        // ── GitLab / Bitbucket content ────────────────────────────────────────
        { host: "gitlab.com",                             score: -15, exact: false },
        { host: "bitbucket.org",                          score: -15, exact: false },
        { host: "codeberg.org",                           score: -15, exact: false },

        // ── SourceForge ───────────────────────────────────────────────────────
        // Historically abused for bundleware and adware installers
        { host: "sourceforge.net",                        score: -35, exact: false },
        { host: "downloads.sourceforge.net",              score: -35, exact: true  },

        // ── Discord CDN ───────────────────────────────────────────────────────
        // Legitimate platform; attachments are anonymous and unscanned
        { host: "cdn.discordapp.com",                     score: -20, exact: true  },
        { host: "media.discordapp.net",                   score: -20, exact: true  },
        { host: "attachments.discord.com",                score: -20, exact: true  },

        // ── Dropbox / OneDrive direct download ───────────────────────────────
        // More accountability (requires account) but direct links bypass scanning
        { host: "dl.dropboxusercontent.com",              score: -15, exact: true  },
        { host: "dl.dropbox.com",                         score: -15, exact: true  },

        // ── MEGA ──────────────────────────────────────────────────────────────
        // Anonymous file sharing, high abuse rate for malware
        { host: "mega.nz",                                score: -45, exact: false },
        { host: "mega.co.nz",                             score: -45, exact: false },

        // ── MediaFire ─────────────────────────────────────────────────────────
        { host: "mediafire.com",                          score: -40, exact: false },
        { host: "download1.mediafire.com",                score: -40, exact: true  },

        // ── 4shared ───────────────────────────────────────────────────────────
        { host: "4shared.com",                            score: -40, exact: false },

        // ── SendSpace ─────────────────────────────────────────────────────────
        { host: "sendspace.com",                          score: -40, exact: false },

        // ── GoFile ────────────────────────────────────────────────────────────
        { host: "gofile.io",                              score: -45, exact: false },

        // ── Transfer.sh ───────────────────────────────────────────────────────
        { host: "transfer.sh",                            score: -40, exact: false },

        // ── uFile / BayFiles ──────────────────────────────────────────────────
        { host: "ufile.io",                               score: -45, exact: false },
        { host: "bayfiles.com",                           score: -55, exact: false },

        // ── AnonFiles variants ────────────────────────────────────────────────
        // Designed for anonymous uploads, extremely high malware rate
        { host: "anonfiles.com",                          score: -65, exact: false },
        { host: "anonfile.com",                           score: -65, exact: false },
        { host: "anonymousfiles.io",                      score: -65, exact: false },

        // ── Paste sites ───────────────────────────────────────────────────────
        // Unusual to serve executables; often used to host malware stages
        { host: "pastebin.com",                           score: -35, exact: false },
        { host: "paste.ee",                               score: -35, exact: false },
        { host: "hastebin.com",                           score: -35, exact: false },
        { host: "ghostbin.co",                            score: -35, exact: false },
        { host: "controlc.com",                           score: -35, exact: false },
        { host: "rentry.co",                              score: -35, exact: false },

        // ── NexusMods ─────────────────────────────────────────────────────────
        // Moderated but user-uploaded game mods; some risk
        { host: "nexusmods.com",                          score: -15, exact: false },
        { host: "staticdelivery.nexusmods.com",           score: -15, exact: true  },

        // ── Game cheat / hack forums ──────────────────────────────────────────
        { host: "unknowncheats.me",                       score: -70, exact: false },
        { host: "mpgh.net",                               score: -70, exact: false },
        { host: "hackforums.net",                         score: -70, exact: false },
        { host: "elitepvpers.com",                        score: -70, exact: false },
        { host: "ownedcore.com",                          score: -70, exact: false },
        { host: "forums.sythe.org",                       score: -70, exact: true  },
        { host: "cheatengine.org",                        score: -65, exact: false },

        // ── Roblox exploit sites ──────────────────────────────────────────────
        // Targets children; extremely high malware rate
        { host: "v3rmillion.net",                         score: -80, exact: false },
        { host: "wearedevs.net",                          score: -80, exact: false },

        // ── Crack / warez / nulled software ──────────────────────────────────
        { host: "nulled.to",                              score: -75, exact: false },
        { host: "nulled.cc",                              score: -75, exact: false },
        { host: "cracked.io",                             score: -75, exact: false },
        { host: "leakforums.net",                         score: -75, exact: false },
        { host: "getintopc.com",                          score: -55, exact: false },
        { host: "crackedpc.com",                          score: -75, exact: false },

        // ── ROM / emulation sites ─────────────────────────────────────────────
        { host: "emuparadise.me",                         score: -45, exact: false },
        { host: "romsmania.cc",                           score: -45, exact: false },
        { host: "romspure.cc",                            score: -45, exact: false },
        { host: "wowroms.com",                            score: -45, exact: false },

        // ── Bundleware / adware installers ────────────────────────────────────
        { host: "download.cnet.com",                      score: -35, exact: true  },
        { host: "softonic.com",                           score: -35, exact: false },
        { host: "filehippo.com",                          score: -25, exact: false },
    ];

    /**
     * Look up a hostname against the risky hosting sites list.
     *
     * @param {string} hostname  - lowercased hostname from the download URL
     * @returns {{ host: string, score: number, label: string } | null}
     */
    function lookup(hostname) {
        if (!hostname) return null;
        const host = hostname.toLowerCase();

        for (const site of SITES) {
            if (site.exact) {
                if (host === site.host) {
                    return { host: site.host, score: site.score,
                             label: `Download hosted on risky file sharing platform (${site.host})` };
                }
            } else {
                // Suffix match — catches the domain itself and all subdomains
                if (host === site.host || host.endsWith("." + site.host)) {
                    // Show the matched entry host, not the full subdomain
                    return { host: site.host, score: site.score,
                             label: `Download hosted on risky file sharing platform (${host})` };
                }
            }
        }
        return null;
    }

    return { lookup };

})();
