"use strict";

/**
 * DeliveryPatterns.js — v3.5.0 single source of truth for recognised, real-
 * world DELIVERY patterns: the hard anchors that let DeliveryContext.js treat
 * an odd-looking but ordinary delivery route as "explained".
 *
 * Pure tables + matchers, no chrome.* access, no state.
 *
 * Ground rules for every table below (read before adding an entry):
 *   1. Only hosts a VENDOR controls. Never a host where anyone can upload or
 *      publish (raw.githubusercontent.com, objects.githubusercontent.com,
 *      cdn.discordapp.com, media.discordapp.net, drive.usercontent.google.com,
 *      storage.googleapis.com, *.blob.core.windows.net, dropbox, sharepoint,
 *      cloudfront.net / akamaized.net / b-cdn.net and other rent-a-CDN
 *      domains). An attacker can put a file there, so the host proves nothing.
 *   2. Never a keyword: "cdn", "download", "update" in a name are free to
 *      register (cdn-ccleaner-update.top) and must never explain anything.
 *   3. Matching is on whole DNS labels (host === entry or host ends with
 *      "." + entry), so "evilavcdn.net" does not match "avcdn.net".
 *
 * Public interface:
 *   DeliveryPatterns.vendorOf(url)                -> vendor name | null
 *   DeliveryPatterns.mirrorNetworkOf(url)         -> mirror network name | null
 *   DeliveryPatterns.platformDownloadLinkOf(url)  -> platform name | null
 *   DeliveryPatterns.messageOriginOf(url)         -> webmail/chat name | null
 *   DeliveryPatterns.companyOf(hostname)          -> company name | null
 *   DeliveryPatterns.sameCompany(hostA, hostB)    -> boolean (both known, same company)
 *   DeliveryPatterns.isOpenPlatform(domain)        -> boolean (v3.5.2)
 *   DeliveryPatterns.brandOnPlatform(host, platformDomain) -> { keyword } | null (v3.5.2)
 *   DeliveryPatterns.TABLES                       frozen tables (tests, docs)
 */
import { Brands } from "./Brands.js"; // v3.5.2 — brand keywords for brandOnPlatform()

export const DeliveryPatterns = (function () {

    // Vendor-owned download/delivery hosts. A download whose FINAL host is one
    // of these comes from the vendor itself, so route quirks around it — an
    // unrelated referrer page, a link without extension, a short link, a link
    // pasted in a chat — are how vendors normally ship, not evidence.
    const VENDOR_DELIVERY = Object.freeze([
        Object.freeze({ vendor: "Gen Digital (CCleaner, Avast, AVG)", hosts: Object.freeze(["avcdn.net"]) }),
        Object.freeze({ vendor: "Mozilla",   hosts: Object.freeze(["download.mozilla.org", "cdn.mozilla.net"]) }),
        Object.freeze({ vendor: "Microsoft", hosts: Object.freeze([
            "download.microsoft.com", "download.visualstudio.microsoft.com", "download.prss.microsoft.com",
            "delivery.mp.microsoft.com", "officecdn.microsoft.com", "go.microsoft.com", "aka.ms",
        ]) }),
        Object.freeze({ vendor: "Google",    hosts: Object.freeze(["dl.google.com", "edgedl.me.gvt1.com"]) }),
        Object.freeze({ vendor: "Valve (Steam)", hosts: Object.freeze(["steamstatic.com"]) }),
        Object.freeze({ vendor: "Discord (app installers)", hosts: Object.freeze(["dl2.discordapp.net"]) }),
        Object.freeze({ vendor: "Brave",     hosts: Object.freeze(["laptop-updates.brave.com", "brave-browser-downloads.s3.brave.com"]) }),
        Object.freeze({ vendor: "Adobe",     hosts: Object.freeze(["ardownload2.adobe.com", "ardownload3.adobe.com"]) }),
        Object.freeze({ vendor: "JetBrains", hosts: Object.freeze(["download.jetbrains.com", "download-cdn.jetbrains.com"]) }),
        Object.freeze({ vendor: "Opera",     hosts: Object.freeze(["download.opera.com", "get.geo.opera.com"]) }),
        Object.freeze({ vendor: "NVIDIA",    hosts: Object.freeze(["us.download.nvidia.com", "international.download.nvidia.com"]) }),
        Object.freeze({ vendor: "Spotify",   hosts: Object.freeze(["download.scdn.co"]) }),
    ]);

    // Redirectors that hand a download to a volunteer MIRROR network, which
    // may serve plain HTTP. An HTTPS→HTTP downgrade that STARTS here is how the
    // network works; the plain-HTTP risk itself is still scored (ProtocolCheck).
    const MIRROR_NETWORKS = Object.freeze([
        Object.freeze({ network: "VideoLAN mirrors",          hosts: Object.freeze(["get.videolan.org"]) }),
        Object.freeze({ network: "The Document Foundation mirrors", hosts: Object.freeze(["download.documentfoundation.org"]) }),
        Object.freeze({ network: "SourceForge mirrors",       hosts: Object.freeze(["downloads.sourceforge.net"]) }),
    ]);

    // An open platform's OWN extensionless "latest version" link. Explains
    // only the missing extension — the platform's risky-host score still
    // counts, because what is behind the link is still user-uploaded.
    const PLATFORM_DOWNLOAD_LINKS = Object.freeze([
        Object.freeze({ platform: "SourceForge", host: "sourceforge.net", path: /^\/projects\/[^/]+\/files\/(?:.+\/)?download\/?$/ }),
    ]);

    // Pages a phishing/lure link is typically clicked from: webmail and chat.
    // pathPrefix narrows hosts that also serve ordinary pages (discord.com/download
    // is Discord's own download page, discord.com/channels/... is a chat).
    const MESSAGE_ORIGINS = Object.freeze([
        Object.freeze({ name: "Gmail",            host: "mail.google.com" }),
        Object.freeze({ name: "Outlook",          host: "outlook.live.com" }),
        Object.freeze({ name: "Outlook",          host: "outlook.office.com" }),
        Object.freeze({ name: "Outlook",          host: "outlook.office365.com" }),
        Object.freeze({ name: "Outlook Safe Links", host: "safelinks.protection.outlook.com" }),
        Object.freeze({ name: "Yahoo Mail",       host: "mail.yahoo.com" }),
        Object.freeze({ name: "Proton Mail",      host: "mail.proton.me" }),
        Object.freeze({ name: "Discord chat",     host: "discord.com", pathPrefix: "/channels/" }),
        Object.freeze({ name: "WhatsApp Web",     host: "web.whatsapp.com" }),
        Object.freeze({ name: "Telegram Web",     host: "web.telegram.org" }),
        Object.freeze({ name: "Microsoft Teams",  host: "teams.microsoft.com" }),
        Object.freeze({ name: "Microsoft Teams",  host: "teams.live.com" }),
        Object.freeze({ name: "Slack",            host: "app.slack.com" }),
    ]);

    // Registered domains (eTLD+1) that belong to ONE company. Used only to say
    // whether a referring page and a download host are RELATED (protection/
    // FilenameUrlHeuristics.checkReferrerMismatch) — a relation, never trust:
    // user-content domains are listed on purpose (discord.com → its own
    // attachment host cdn.discordapp.com IS related; the risk of what is
    // uploaded there is scored separately, by RiskyHosting). Matched on whole
    // host labels, NOT via the registered domain: the Public Suffix List
    // treats some of these as platform suffixes (githubusercontent.com), so
    // objects.githubusercontent.com would otherwise be its own "site".
    // A user's own site on a platform suffix not listed here (x.github.io)
    // never matches.
    const SAME_COMPANY = Object.freeze([
        Object.freeze({ company: "Discord",   domains: Object.freeze(["discord.com", "discordapp.com", "discordapp.net", "discord.gg"]) }),
        Object.freeze({ company: "GitHub",    domains: Object.freeze(["github.com", "githubusercontent.com", "githubassets.com"]) }),
        Object.freeze({ company: "Google",    domains: Object.freeze(["google.com", "googleusercontent.com", "gstatic.com", "googleapis.com", "gvt1.com", "android.com"]) }),
        Object.freeze({ company: "Microsoft", domains: Object.freeze(["microsoft.com", "live.com", "office.com", "office.net", "windows.com",
                                                                      "windowsupdate.com", "visualstudio.com", "msecnd.net", "aka.ms",
                                                                      "sharepoint.com", "onedrive.com", "1drv.ms", "bing.com", "msn.com"]) }),
        Object.freeze({ company: "Mozilla",   domains: Object.freeze(["mozilla.org", "mozilla.net", "mozilla.com", "firefox.com"]) }),
        Object.freeze({ company: "Gen Digital", domains: Object.freeze(["ccleaner.com", "piriform.com", "avast.com", "avg.com", "avcdn.net", "norton.com"]) }),
        Object.freeze({ company: "Valve",     domains: Object.freeze(["steampowered.com", "steamstatic.com", "steamcommunity.com", "steamusercontent.com"]) }),
        Object.freeze({ company: "Dropbox",   domains: Object.freeze(["dropbox.com", "dropboxusercontent.com"]) }),
        Object.freeze({ company: "Apple",     domains: Object.freeze(["apple.com", "cdn-apple.com", "icloud.com", "mzstatic.com"]) }),
        Object.freeze({ company: "Meta",      domains: Object.freeze(["facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com", "whatsapp.com", "whatsapp.net"]) }),
        Object.freeze({ company: "Telegram",  domains: Object.freeze(["telegram.org", "telegram.me", "t.me"]) }),
        Object.freeze({ company: "MEGA",      domains: Object.freeze(["mega.nz", "mega.io", "mega.co.nz"]) }),
    ]);

    // v3.5.2 (moved from 3P Matrix 4.4.0's data/constants.js — single source for
    // the site AND download checks) — developer-hosting platforms where anyone
    // gets a subdomain (Public Suffix List PRIVATE section) and that sit on the
    // SuspiciousDomains list. Mostly ordinary sites, misused for phishing too.
    // Dynamic-DNS hosts on the same list (duckdns.org, ddns.net, …) are
    // deliberately NOT here: they are not softened anywhere.
    const OPEN_PLATFORMS = Object.freeze([
        "github.io", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
        "onrender.com", "fly.dev", "surge.sh",
    ]);
    // Platforms whose subdomain label is an ACCOUNT name the brand itself
    // registered (microsoft.github.io is Microsoft's GitHub organisation): a
    // label that IS exactly the brand keyword is not impersonation there.
    const ORG_PAGE_PLATFORMS = Object.freeze(["github.io"]);

    function parse(url) {
        if (!url) return null;
        try {
            const u = new URL(url);
            return (u.protocol === "http:" || u.protocol === "https:") ? u : null;
        } catch { return null; }
    }

    function hostMatches(host, entry) {
        return host === entry || host.endsWith("." + entry);
    }

    function vendorOf(url) {
        const u = parse(url);
        if (!u) return null;
        const host = u.hostname.toLowerCase();
        const hit = VENDOR_DELIVERY.find(v => v.hosts.some(h => hostMatches(host, h)));
        return hit ? hit.vendor : null;
    }

    function mirrorNetworkOf(url) {
        const u = parse(url);
        if (!u) return null;
        const host = u.hostname.toLowerCase();
        const hit = MIRROR_NETWORKS.find(m => m.hosts.some(h => hostMatches(host, h)));
        return hit ? hit.network : null;
    }

    function platformDownloadLinkOf(url) {
        const u = parse(url);
        if (!u) return null;
        const host = u.hostname.toLowerCase();
        const hit = PLATFORM_DOWNLOAD_LINKS.find(p => hostMatches(host, p.host) && p.path.test(u.pathname));
        return hit ? hit.platform : null;
    }

    function messageOriginOf(url) {
        const u = parse(url);
        if (!u) return null;
        const host = u.hostname.toLowerCase();
        const hit = MESSAGE_ORIGINS.find(m => hostMatches(host, m.host)
            && (!m.pathPrefix || u.pathname.startsWith(m.pathPrefix)));
        return hit ? hit.name : null;
    }

    function companyOf(hostname) {
        if (!hostname) return null;
        const host = String(hostname).toLowerCase();
        const hit = SAME_COMPANY.find(c => c.domains.some(d => hostMatches(host, d)));
        return hit ? hit.company : null;
    }

    function sameCompany(hostA, hostB) {
        const a = companyOf(hostA);
        return a !== null && a === companyOf(hostB);
    }

    function isOpenPlatform(domain) {
        return !!domain && OPEN_PLATFORMS.includes(String(domain).toLowerCase());
    }

    // A brand name in the subdomain of an open platform (paypal-login.vercel.app)
    // — impersonation. platformDomain = the platform the host is on (a
    // RiskyHosting host or an OPEN_PLATFORMS domain). null when no brand, the
    // host is not under the platform, or it is the brand's own org page.
    function brandOnPlatform(host, platformDomain) {
        if (!host || !platformDomain) return null;
        const h = String(host).toLowerCase();
        const p = String(platformDomain).toLowerCase();
        if (!h.endsWith("." + p)) return null;
        const hit = Brands.matchBrand(h);
        if (!hit) return null;
        const label = h.slice(0, h.length - p.length - 1);
        if (ORG_PAGE_PLATFORMS.includes(p) && label === hit.keyword) return null;
        return { keyword: hit.keyword };
    }

    return {
        vendorOf,
        companyOf,
        sameCompany,
        isOpenPlatform,
        brandOnPlatform,
        mirrorNetworkOf,
        platformDownloadLinkOf,
        messageOriginOf,
        TABLES: Object.freeze({ VENDOR_DELIVERY, MIRROR_NETWORKS, PLATFORM_DOWNLOAD_LINKS, MESSAGE_ORIGINS, SAME_COMPANY,
                                OPEN_PLATFORMS, ORG_PAGE_PLATFORMS }),
    };
})();
