"use strict";

/**
 * DomainAge.js — When the RDAP registration-age lookup CANNOT give a real
 * answer, skip it entirely: no network call, no "unavailable" result, no
 * penalty. v3.3.0 (3P Matrix alignment item 1, full agreement with 3P
 * Matrix: both cases below score neutral, not a risk penalty — unlike a
 * failed/unreachable lookup, which still scores via RdapProtection's own
 * scoreAge(null), see item 2).
 *
 * Two cases, AGE_NA — single source of truth for both:
 *   PLATFORM — the registered domain is a subdomain of a hosting platform
 *              from the Public Suffix List's private section
 *              (PlatformSuffixes.js). The registry only knows the
 *              platform's own age (e.g. "github.io"), which says nothing
 *              about this particular site.
 *   NO_RDAP  — a two-letter country-code TLD with no RDAP service at all
 *              (RdapCctlds.js lists which ccTLDs DO have one). A longer TLD
 *              (every gTLD, or an IDN ccTLD) always has RDAP under ICANN's
 *              contract, so this only ever applies to two-letter ccTLDs.
 *
 * Pure — no network calls, no Chrome APIs. Ported from 3P Matrix's
 * util/domain-age.js.
 */
import { PlatformSuffixes } from "./PlatformSuffixes.js";
import { RdapCctlds } from "./RdapCctlds.js";

export const AGE_NA = Object.freeze({ PLATFORM: "platform", NO_RDAP: "no-rdap" });

const WILDCARD_PREFIX = "*.";
const CCTLD_RE = /^[a-z]{2}$/;

function afterFirstLabel(name) {
    const i = name.indexOf(".");
    return i === -1 ? "" : name.slice(i + 1);
}

/**
 * The hosting platform a registered domain sits on, or "" if none. A PSL
 * wildcard rule ("*.platform.tld") covers every one-label-deeper suffix of
 * that platform; the last two tests below cover a registered domain that
 * IS itself a platform suffix (e.g. the bundled list is older than a
 * platform that has since been added).
 */
function platformOf(registeredDomain) {
    const set = PlatformSuffixes.set;
    const suffix = afterFirstLabel(registeredDomain);
    if (!suffix) return "";
    if (set.has(suffix)) return suffix;
    const parent = afterFirstLabel(suffix);
    if (parent && set.has(WILDCARD_PREFIX + parent)) return parent;
    if (set.has(registeredDomain)) return registeredDomain;
    return set.has(WILDCARD_PREFIX + suffix) ? suffix : "";
}

/**
 * @param {string} registeredDomain - eTLD+1, e.g. "example.co.uk"
 * @returns {{kind: string, text: string}|null} null means "ask RDAP as usual"
 */
export function domainAgeNotApplicable(registeredDomain) {
    const rd = String(registeredDomain || "").toLowerCase();
    if (!rd) return null;

    const platform = platformOf(rd);
    if (platform) {
        return { kind: AGE_NA.PLATFORM, text: `not applicable — site on ${platform}, where anyone can get a subdomain` };
    }

    const tld = rd.slice(rd.lastIndexOf(".") + 1);
    if (CCTLD_RE.test(tld) && !RdapCctlds.set.has(tld)) {
        return { kind: AGE_NA.NO_RDAP, text: `not published — the .${tld} registry has no RDAP service` };
    }

    return null;
}
