"use strict";

/**
 * DnsThreatProtection.js
 * Checks a hostname against a user-chosen DNS-over-HTTPS threat-intel
 * resolver (Quad9, Cloudflare Security, Control D, DNS4EU or CleanBrowsing — see
 * APP.DNS_PROVIDERS, the single source of truth for the providers).
 *
 * v3.3.1: added DNS4EU ("blockpage-ip") and CleanBrowsing ("rpz-soa", which
 * needs the Authority section's SOA records — now parsed); block styles are
 * now compared via the APP.DNS_BLOCK_STYLE enum, never raw strings.
 *
 * v3.0.6: generalized from the old single-provider Quad9Protection.js so
 * the user can pick any two of the three ("first"/"second" DNS check in
 * Options) instead of always querying Quad9 alone. The wire-format codec
 * below (query encoding, response parsing, compression-pointer handling)
 * is unchanged from Quad9Protection.js — see CHANGELOG.md's v3.0.4
 * entry for why it speaks RFC 8484's binary wire format rather than a
 * JSON convenience format.
 *
 * Each provider says "blocked" differently (APP.DNS_PROVIDERS[id].blockStyle):
 *   "nxdomain-no-authority" — Quad9: NXDOMAIN (Status 3) with no Authority
 *                             records → actively blocked by threat-intel.
 *                             NXDOMAIN WITH Authority records → the domain
 *                             genuinely doesn't exist (UNKNOWN, not BLOCKED).
 *   "zero-ip"               — Cloudflare Security / Control D: the domain
 *                             still resolves, but to 0.0.0.0 (A) or :: (AAAA)
 *                             — the resolver's own "sinkhole" answer.
 *   "blockpage-ip"          — DNS4EU: the domain resolves to the provider's
 *                             block-page IP (provider.blockPageIps); 0.0.0.0
 *                             / :: also count as blocked.
 *   "rpz-soa"               — CleanBrowsing: no answer, and the Authority
 *                             section holds a synthetic SOA whose MNAME ends
 *                             in provider.rpzSoaMnameSuffix ("rpz.noc.org").
 *                             A real non-existent name carries the registry's
 *                             SOA instead → UNKNOWN/NXDOMAIN, not BLOCKED.
 *
 * A result that is neither BLOCKED nor ALLOWED carries a `reasonCode` (see
 * UNKNOWN_REASON below) so callers can tell "no threat-intel data for this
 * host" apart from a timeout, an HTTP error, or NXDOMAIN — these are not
 * interchangeable and the UI shows each one differently.
 */
import { APP } from "../util/AppConstants.js";
import { DnsPermissions } from "../util/DnsPermissions.js";

export const DnsThreatProtection = (function () {

    const TIMEOUT_MS = APP.DNS_TIMEOUT_MS; // defined in AppConstants.js
    const BLOCK_STYLE = APP.DNS_BLOCK_STYLE; // enum — defined in AppConstants.js

    // ── DNS wire-format (RFC 1035 / RFC 8484) constants — every magic number
    // for the query/response codec gathered here, single source of truth.
    const DNS = Object.freeze({
        TYPE_A:      1,
        TYPE_CNAME:  5,
        TYPE_SOA:    6,
        TYPE_AAAA:   28,
        CLASS_IN:    1,
        RCODE_NXDOMAIN: 3,
        HEADER_BYTES:   12,
        MAX_LABEL_BYTES: 63,   // RFC 1035 §2.3.4 — a single DNS label can't exceed this
        MAX_NAME_BYTES:  255,  // RFC 1035 §2.3.4 — a full encoded name can't exceed this
        POINTER_FLAG:    0xC0, // top two bits of a length byte mark a compression pointer
        MAX_POINTER_HOPS: 20,  // guard against a malicious/malformed response with a pointer loop
    });

    // ── UNKNOWN reason codes ────────────────────────────────────────────────
    // Single source of truth for *why* a check landed on UNKNOWN instead of
    // BLOCKED/ALLOWED. The UI (WarningPage.js) maps each code to its own
    // display text — never infer the reason from the free-text `reason`/
    // `label` string, which exists for logs/debugging only and may change
    // wording without notice.
    const UNKNOWN_REASON = Object.freeze({
        NO_THREAT_DATA: "NO_THREAT_DATA", // kept for the UI text table's forward-compat (see WarningPage.js); the wire-format protocol has no equivalent of the old JSON endpoint's "no threat data" 400 — a clean domain simply resolves (ALLOWED) — so this is never emitted here any more
        REQUEST_FAILED: "REQUEST_FAILED", // provider returned a non-OK HTTP status, or returned 200 with a body that didn't parse as a valid DNS message
        NXDOMAIN:       "NXDOMAIN",       // Name genuinely doesn't exist (NXDOMAIN + Authority present — Quad9's blockStyle only)
        NO_ANSWER:      "NO_ANSWER",      // OK response but no usable A/AAAA/CNAME records
        TIMEOUT:        "TIMEOUT",        // Request aborted after TIMEOUT_MS with no response
        PERMISSION_MISSING: "PERMISSION_MISSING", // v3.3.1 — optional-permission provider (DNS4EU) selected but its host permission isn't granted; no request is sent
        ERROR:          "ERROR"           // Network failure or other unexpected exception
    });

    // ── DNS query encoding ──────────────────────────────────────────────────
    // Builds a minimal standards-compliant question: one QNAME/A/IN query,
    // recursion desired, no EDNS (not needed over HTTPS — there's no UDP
    // packet-size concern this would exist to solve).
    function encodeHostnameLabels(hostname) {
        const labels = hostname.split(".").filter(Boolean); // filter(Boolean) drops a trailing-dot's empty label
        const bytes = [];
        for (const label of labels) {
            const labelBytes = new TextEncoder().encode(label);
            if (labelBytes.length === 0 || labelBytes.length > DNS.MAX_LABEL_BYTES) return null; // malformed — refuse rather than build a corrupt query
            bytes.push(labelBytes.length, ...labelBytes);
        }
        bytes.push(0); // root label terminator
        return bytes.length <= DNS.MAX_NAME_BYTES ? bytes : null;
    }

    function encodeDnsQuery(hostname) {
        const qname = encodeHostnameLabels(hostname);
        if (!qname) return null;

        const header = [
            0x00, 0x00, // ID — 0 is fine, HTTP request/response pairing makes it redundant
            0x01, 0x00, // flags: RD (recursion desired) set, everything else 0
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];
        const question = [...qname, 0x00, DNS.TYPE_A, 0x00, DNS.CLASS_IN];
        return new Uint8Array([...header, ...question]);
    }

    // base64url (no padding) — the form RFC 8484 requires for the `?dns=` param.
    function toBase64Url(bytes) {
        let binary = "";
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    // ── DNS response decoding ────────────────────────────────────────────────
    // Reads a (possibly compressed, RFC 1035 §4.1.4) name starting at offset;
    // returns { name, nextOffset } where nextOffset is just past the name AS
    // IT APPEARS IN THE MESSAGE (i.e. just past the first pointer byte pair,
    // not wherever a pointer jumped to) — callers use nextOffset to continue
    // reading the record that contained this name.
    function readName(view, startOffset) {
        const labels = [];
        let offset = startOffset;
        let afterFirstPointer = -1;
        let hops = 0;

        for (;;) {
            if (offset >= view.byteLength) throw new RangeError("name runs past end of message");
            const length = view.getUint8(offset);

            if ((length & DNS.POINTER_FLAG) === DNS.POINTER_FLAG) {
                if (++hops > DNS.MAX_POINTER_HOPS) throw new RangeError("too many compression pointer hops");
                if (afterFirstPointer === -1) afterFirstPointer = offset + 2; // first pointer ends the caller-visible region
                const pointerByte2 = view.getUint8(offset + 1);
                offset = ((length & 0x3F) << 8) | pointerByte2;
                continue;
            }
            if (length === 0) { offset += 1; break; } // root label — name ends here
            if (length > DNS.MAX_LABEL_BYTES) throw new RangeError("label exceeds max length");

            const labelStart = offset + 1;
            const labelBytes = new Uint8Array(view.buffer, view.byteOffset + labelStart, length);
            labels.push(new TextDecoder().decode(labelBytes));
            offset = labelStart + length;
        }

        return {
            name: labels.join("."),
            nextOffset: afterFirstPointer !== -1 ? afterFirstPointer : offset,
        };
    }

    /**
     * Parse a raw DNS wire-format response.
     * @returns {{ rcode: number, answerCount: number, authorityCount: number,
     *             answers: string[] }}
     */
    function parseDnsResponse(buffer) {
        const view = new DataView(buffer);
        if (buffer.byteLength < DNS.HEADER_BYTES) throw new RangeError("response shorter than a DNS header");

        const flags          = view.getUint16(2);
        const rcode           = flags & 0x0F;
        const questionCount   = view.getUint16(4);
        const answerCount     = view.getUint16(6);
        const authorityCount  = view.getUint16(8);

        let offset = DNS.HEADER_BYTES;
        for (let i = 0; i < questionCount; i++) {
            offset = readName(view, offset).nextOffset;
            offset += 4; // QTYPE (2) + QCLASS (2)
        }

        const answers = [];
        for (let i = 0; i < answerCount; i++) {
            offset = readName(view, offset).nextOffset;
            const type     = view.getUint16(offset);
            offset += 8; // TYPE (2) + CLASS (2) + TTL (4)
            const rdLength = view.getUint16(offset);
            offset += 2;

            if (type === DNS.TYPE_A && rdLength === 4) {
                const octets = [0, 1, 2, 3].map(j => view.getUint8(offset + j));
                answers.push(octets.join("."));
            } else if (type === DNS.TYPE_AAAA && rdLength === 16) {
                const groups = [];
                for (let j = 0; j < 16; j += 2) groups.push(view.getUint16(offset + j).toString(16));
                answers.push(groups.join(":"));
            } else if (type === DNS.TYPE_CNAME) {
                answers.push(readName(view, offset).name);
            }
            // Any other record type is skipped for our purposes — BLOCKED/
            // ALLOWED only cares whether *some* usable address/alias exists.

            offset += rdLength;
        }

        // Authority section (v3.3.1) — only SOA records are kept, as
        // { owner, mname } (lower-case, no trailing dot); everything else
        // is skipped. Needed by the RPZ_SOA blockStyle only.
        // Guard: the Authority section is supplementary — a truncated or
        // malformed one must not discard the already-parsed answers/rcode,
        // so a read error here just stops collecting (fail open: no RPZ SOA
        // found → never BLOCKED on a section we couldn't read).
        const authoritySoas = [];
        try {
            collectAuthoritySoas(view, offset, authorityCount, authoritySoas);
        } catch {
            // keep whatever was collected before the error
        }

        return { rcode, answerCount, authorityCount, answers, authoritySoas };
    }

    function collectAuthoritySoas(view, startOffset, authorityCount, out) {
        let offset = startOffset;
        for (let i = 0; i < authorityCount; i++) {
            const owner = readName(view, offset);
            offset = owner.nextOffset;
            const type     = view.getUint16(offset);
            offset += 8; // TYPE (2) + CLASS (2) + TTL (4)
            const rdLength = view.getUint16(offset);
            offset += 2;
            if (type === DNS.TYPE_SOA) {
                out.push({
                    owner: normalizeName(owner.name),
                    mname: normalizeName(readName(view, offset).name),
                });
            }
            offset += rdLength;
        }
    }

    // "zero-ip" blockStyle: true when an answer IS the resolver's sinkhole
    // address — 0.0.0.0 for A, :: for AAAA. Works on the string forms
    // parseDnsResponse() already produces (an all-zero AAAA comes out as
    // "0:0:0:0:0:0:0:0", never the ":: "-compressed form, since this codec
    // never compresses on write/read — so "every group is literally 0" is
    // the correct, format-agnostic test for both address families.
    function isSinkholeAddress(answer) {
        if (answer === "0.0.0.0") return true;
        return answer.includes(":") && answer.split(":").every(group => group === "0");
    }

    function normalizeName(name) {
        return String(name).toLowerCase().replace(/\.$/, "");
    }

    // RPZ_SOA blockStyle: true when some Authority SOA's MNAME is, or ends on
    // a label boundary with, provider.rpzSoaMnameSuffix. Guard: no/empty
    // suffix configured → never "blocked" (fail open to UNKNOWN/ALLOWED).
    function hasRpzSoa(provider, parsed) {
        const suffix = typeof provider.rpzSoaMnameSuffix === "string" ? normalizeName(provider.rpzSoaMnameSuffix) : "";
        if (!suffix) return false;
        return parsed.authoritySoas.some(soa => soa.mname === suffix || soa.mname.endsWith("." + suffix));
    }

    // Per-provider list of answers that mean "blocked" in ADDITION to the
    // 0.0.0.0 / :: sinkhole. Only BLOCKPAGE_IP providers have one; guard
    // against a missing/malformed list so a config slip can't throw here.
    function providerBlockPageIps(provider) {
        if (provider.blockStyle !== BLOCK_STYLE.BLOCKPAGE_IP) return [];
        return Array.isArray(provider.blockPageIps) ? provider.blockPageIps : [];
    }

    function isBlockAnswer(provider, answer) {
        return isSinkholeAddress(answer) || providerBlockPageIps(provider).includes(answer);
    }

    /**
     * Query a DNS threat-intel provider (standard wire format) for a hostname.
     * @param {object} provider - one of APP.DNS_PROVIDERS's entries
     * @param {string} hostname
     * @param {AbortSignal} [signal]
     * @returns {Promise<{ status: "BLOCKED"|"ALLOWED"|"UNKNOWN", reasonCode?: string, reason?: string, answers?: string[] }>}
     */
    async function checkHostname(provider, hostname, signal) {
        const query = encodeDnsQuery(hostname);
        if (!query) {
            return {
                status:     "UNKNOWN",
                reasonCode: UNKNOWN_REASON.REQUEST_FAILED,
                reason:     "Hostname could not be encoded as a DNS query"
            };
        }

        const url = `${provider.url}?dns=${toBase64Url(query)}`;
        const response = await fetch(url, {
            headers: { Accept: "application/dns-message" },
            signal
        });

        if (!response.ok) {
            return {
                status:     "UNKNOWN",
                reasonCode: UNKNOWN_REASON.REQUEST_FAILED,
                reason:     `${provider.label} request failed (${response.status})`
            };
        }

        let parsed;
        try {
            parsed = parseDnsResponse(await response.arrayBuffer());
        } catch {
            return {
                status:     "UNKNOWN",
                reasonCode: UNKNOWN_REASON.REQUEST_FAILED,
                reason:     `${provider.label} response could not be parsed as a DNS message`
            };
        }

        if (provider.blockStyle === BLOCK_STYLE.NXDOMAIN_NO_AUTHORITY) {
            // NXDOMAIN — domain either blocked or genuinely non-existent
            if (parsed.rcode === DNS.RCODE_NXDOMAIN) {
                // Authority count 0 → actively blocked by threat-intel
                // Authority count >0 → domain simply doesn't exist
                if (parsed.authorityCount === 0) {
                    return { status: "BLOCKED", reason: `Domain blocked by ${provider.label} threat-intelligence feed` };
                }
                return {
                    status:     "UNKNOWN",
                    reasonCode: UNKNOWN_REASON.NXDOMAIN,
                    reason:     "Domain does not exist (NXDOMAIN)"
                };
            }
        } else if (provider.blockStyle === BLOCK_STYLE.RPZ_SOA) {
            // A policy-zone SOA with no usable answer = blocked; anything
            // else NXDOMAIN-shaped is a genuinely non-existent name.
            if (parsed.answers.length === 0 && hasRpzSoa(provider, parsed)) {
                return { status: "BLOCKED", reason: `Domain blocked by ${provider.label} threat-intelligence feed` };
            }
            if (parsed.rcode === DNS.RCODE_NXDOMAIN) {
                return {
                    status:     "UNKNOWN",
                    reasonCode: UNKNOWN_REASON.NXDOMAIN,
                    reason:     "Domain does not exist (NXDOMAIN)"
                };
            }
        } else {
            // ZERO_IP / BLOCKPAGE_IP blockStyle — domain still resolves, but
            // to a sinkhole or block-page address; NXDOMAIN here just means
            // "doesn't exist".
            if (parsed.answers.some(answer => isBlockAnswer(provider, answer))) {
                return { status: "BLOCKED", reason: `Domain blocked by ${provider.label} threat-intelligence feed` };
            }
            if (parsed.rcode === DNS.RCODE_NXDOMAIN) {
                return {
                    status:     "UNKNOWN",
                    reasonCode: UNKNOWN_REASON.NXDOMAIN,
                    reason:     "Domain does not exist (NXDOMAIN)"
                };
            }
        }

        if (parsed.answers.length === 0) {
            return {
                status:     "UNKNOWN",
                reasonCode: UNKNOWN_REASON.NO_ANSWER,
                reason:     parsed.answerCount === 0 ? "No DNS answer records returned" : "No A/AAAA/CNAME records found"
            };
        }

        return { status: "ALLOWED", answers: parsed.answers };
    }

    /**
     * Public API: check a hostname against one provider, with a hard timeout.
     *
     * @param {string} providerId - a key of APP.DNS_PROVIDERS, or
     *        APP.DNS_NONE / any unrecognised id to skip the check entirely
     *        (the user turned this DNS-check slot off in Options).
     * @param {string} hostname
     *
     * Returns:
     *   { status, score, label, provider, providerLabel, reason?, reasonCode?, answers? }
     *
     *   status "BLOCKED"  → score −100, label "Confirmed malicious"
     *   status "ALLOWED"  → score 0 (neutral; RDAP age will add its own signal)
     *   status "UNKNOWN"  → score 0 (no data, don't penalise); reasonCode is
     *                       always set to one of UNKNOWN_REASON's values so
     *                       the UI can distinguish timeout / HTTP error /
     *                       NXDOMAIN / no-data without parsing free text
     *   status "SKIPPED"  → score 0, this check slot is turned off
     */
    async function check(providerId, hostname) {
        const provider = APP.DNS_PROVIDERS[providerId];
        if (!provider) {
            // APP.DNS_NONE ("none") lands here too — same as any unrecognised
            // id: never run a network request for a disabled/unknown slot.
            return { status: "SKIPPED", score: 0, label: "DNS check disabled", provider: providerId || APP.DNS_NONE, providerLabel: null };
        }

        // Guard (v3.3.1): an optional-permission provider whose permission
        // was declined or later revoked must not be fetched (it would fail
        // anyway) — report it as UNKNOWN, never as safe.
        if (!(await DnsPermissions.has(provider.id))) {
            return {
                status:     "UNKNOWN",
                score:      0,
                label:      `${provider.label}: permission not granted`,
                provider:   provider.id,
                providerLabel: provider.label,
                reasonCode: UNKNOWN_REASON.PERMISSION_MISSING
            };
        }

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort("timeout"), TIMEOUT_MS);

        try {
            const result = await checkHostname(provider, hostname, controller.signal);
            clearTimeout(timer);

            if (result.status === "BLOCKED") {
                return {
                    status:  "BLOCKED",
                    score:   -100,
                    label:   `Confirmed malicious (blocked by ${provider.label})`,
                    provider: provider.id,
                    providerLabel: provider.label,
                    reason:  result.reason
                };
            }

            if (result.status === "ALLOWED") {
                return {
                    status:   "ALLOWED",
                    score:    0,
                    label:    `Resolved (not on ${provider.label} block list)`,
                    provider: provider.id,
                    providerLabel: provider.label,
                    answers:  result.answers
                };
            }

            // UNKNOWN — no usable verdict either way (see UNKNOWN_REASON for why)
            return {
                status:     "UNKNOWN",
                score:      0,
                label:      result.reason || `No ${provider.label} data`,
                provider:   provider.id,
                providerLabel: provider.label,
                reasonCode: result.reasonCode || UNKNOWN_REASON.ERROR
            };

        } catch (err) {
            clearTimeout(timer);
            if (err.name === "AbortError") {
                return {
                    status:     "UNKNOWN",
                    score:      0,
                    label:      `${provider.label} check timed out`,
                    provider:   provider.id,
                    providerLabel: provider.label,
                    reasonCode: UNKNOWN_REASON.TIMEOUT
                };
            }
            return {
                status:     "UNKNOWN",
                score:      0,
                label:      `${provider.label} error: ${err.message}`,
                provider:   provider.id,
                providerLabel: provider.label,
                reasonCode: UNKNOWN_REASON.ERROR
            };
        }
    }

    return { check, UNKNOWN_REASON };
})();
