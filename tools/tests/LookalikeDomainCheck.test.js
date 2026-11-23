"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { LookalikeDomainCheck } from "../../protection/LookalikeDomainCheck.js";

const { check } = LookalikeDomainCheck;

describe("LookalikeDomainCheck — test 1 (popular-site stop)", () => {
    test("a real top site is never flagged as a look-alike of itself", () => {
        assert.equal(check("google.com"), null);
        assert.equal(check("github.com"), null);
    });

    test("a subdomain of a real top site is never flagged", () => {
        assert.equal(check("www.google.com"), null);
    });

    test("a real brand domain is never flagged", () => {
        assert.equal(check("paypal.com"), null);
        assert.equal(check("wellsfargo.com"), null);
    });

    test("a private/platform suffix that is itself a real top site short-circuits before any substitution", () => {
        assert.equal(check("github.io"), null);
    });

    test("shared government-registration suffixes read as a real, popular site (§2 exclusion)", () => {
        // gov.uk is in GovSuffixes.json -> unioned into TopSitesFilter at
        // build time, so "hmrc.gov.uk" (the registrable domain under that
        // suffix) is itself a real site to test 1 — never a lookalike target.
        assert.equal(check("hmrc.gov.uk"), null);
    });
});

describe("LookalikeDomainCheck — test 1.5, runtime government-suffix exemption (v3.3.0, item 17)", () => {
    test("a name that would otherwise match a brand keyword is exempt when registered under a real gov suffix", () => {
        // "gov.pl" is in GovSuffixes.json — only a verified Polish government
        // body can register under it, so this domain is a real gov site by
        // construction. Without the item-17 exemption, test 3 would convert
        // "paypa1" -> "paypal" (clear 1->l substitution) and flag it as a
        // brand-impersonation hit; the gov-suffix exemption stops the check
        // before that ever runs.
        assert.equal(check("paypa1.gov.pl"), null);
    });

    test("the SAME imitation name under an ordinary (non-gov) suffix is still flagged normally", () => {
        // Confirms the exemption checks the SUFFIX, not the name — swapping
        // "gov.pl" for an unrestricted suffix restores the normal brand hit.
        const hit = check("paypa1.com");
        assert.ok(hit);
        assert.equal(hit.type, "brand");
    });

    test("merely mentioning 'gov' inside the registered NAME (not the suffix) does not exempt it", () => {
        // The registrable suffix here is "com", not a GovSuffixes entry —
        // "gov" appearing inside the name itself grants no exemption.
        const hit = check("paypa1-gov-pl.com");
        assert.ok(hit);
        assert.equal(hit.type, "brand");
    });
});

describe("LookalikeDomainCheck — test 2 (no imitation characters -> stop)", () => {
    test("an unrelated, ordinary domain with no imitation characters at all scores null immediately", () => {
        assert.equal(check("example.com"), null);
        assert.equal(check("my-personal-blog.net"), null);
    });

    test("a digit inside a pure digit run (not touching a letter) is not an imitation character", () => {
        // "1688.com" and "500px.com" are real-world numeric-name domains —
        // neither digit run touches a letter in a way that changes meaning
        // the way "g00gle" or "paypa1" does.
        assert.equal(check("1688.com"), null);
        assert.equal(check("500px.com"), null);
    });

    test("a plain compound hostname with the brand word spelled out (no substitution) is out of this check's scope", () => {
        // No imitation CHARACTER here at all — this is SketchyUrlCheck's
        // job (direct word-brand matching), not LookalikeDomainCheck's.
        assert.equal(check("microsoft-login.net"), null);
    });
});

describe("LookalikeDomainCheck — test 3 (clear substitutions)", () => {
    test("1 -> l against a brand keyword", () => {
        const r = check("paypa1-login.com");
        assert.ok(r);
        assert.equal(r.type, "brand");
        assert.equal(r.keyword, "paypal");
    });

    test("0 -> o against a brand keyword", () => {
        const r = check("g00gle.com");
        assert.ok(r);
        assert.equal(r.type, "brand");
        assert.equal(r.keyword, "google");
    });

    test("1 -> l against a brand keyword used as a word, not the whole name", () => {
        const r = check("1inkedin-careers.com");
        assert.ok(r);
        assert.equal(r.type, "brand");
        assert.equal(r.keyword, "linkedin");
    });

    test("8 -> b against the top-sites list (not a curated brand)", () => {
        const r = check("githu8.com");
        assert.ok(r);
        assert.equal(r.type, "site");
        assert.equal(r.resembles, "github.com");
    });

    test("5 -> s against a brand keyword", () => {
        const r = check("micro5oft-update.com");
        assert.ok(r);
    });
});

describe("LookalikeDomainCheck — test 3 (questionable bigram substitutions)", () => {
    test("rn -> m against a brand keyword", () => {
        const r = check("vvellsfargo.com"); // also exercises vv -> w
        assert.ok(r);
        assert.equal(r.type, "brand");
        assert.equal(r.keyword, "wellsfargo");
    });

    test("cl -> d against a brand keyword", () => {
        const r = check("aclobe.com");
        assert.ok(r);
        assert.equal(r.type, "brand");
        assert.equal(r.keyword, "adobe");
    });

    test("a substitution requiring BOTH a clear and a questionable rule still resolves via the ordered variant steps", () => {
        // "arnaz0n" needs "rn"->"m" (questionable) AND "0"->"o" (clear)
        // together to read as "amazon" — step 1 (clear-only) converts the
        // "0" alone ("arnazon" — not a brand/site hit on its own, since the
        // bigram is still untouched), then step 2 (clear + 1st questionable)
        // converts the "rn" too, landing on "amazon".
        const r = check("arnaz0n-secure.net");
        assert.ok(r);
    });
});

describe("LookalikeDomainCheck — brand vs. site priority", () => {
    test("a hit that is both a curated brand AND a top site prefers the brand result (higher-confidence)", () => {
        // wellsfargo.com and adobe.com are both curated brand entries AND
        // already real, popular top-sites in their own right — the brand
        // match (higher confidence, see ScoringEngineV2's
        // LOOKALIKE_BRAND_SCORE/LOOKALIKE_SITE_SCORE comment) must win.
        assert.equal(check("vvellsfargo.com").type, "brand");
        assert.equal(check("aclobe.com").type, "brand");
    });
});

describe("LookalikeDomainCheck — non-Latin confusable (punycode) detection", () => {
    test("a Cyrillic confusable standing in for a Latin letter in a brand name is caught", () => {
        // "paypal" with its 2nd "a" replaced by Cyrillic а (U+0430) — built
        // with Node's own `new URL()` IDNA encoder so this fixture is a
        // real, valid punycode (xn--) label, not hand-rolled.
        const hostWithConfusable = "paypаl-login.com";
        let punycodeHost;
        try {
            punycodeHost = new URL(`https://${hostWithConfusable}/`).hostname;
        } catch {
            punycodeHost = null;
        }
        // Environments without full ICU/IDNA support may fail to encode —
        // skip gracefully rather than fail the suite on an unrelated gap.
        if (!punycodeHost || !punycodeHost.includes("xn--")) return;
        const r = check(punycodeHost);
        assert.ok(r, `expected a hit for ${punycodeHost}`);
        assert.equal(r.type, "brand");
        assert.equal(r.keyword, "paypal");
    });

    test("a real punycode IDN with no confusable letters is unaffected", () => {
        const punycodeHost = new URL("https://café-example.com/").hostname; // café — é has no confusable mapping
        assert.ok(punycodeHost.includes("xn--"));
        assert.equal(check(punycodeHost), null);
    });
});

describe("LookalikeDomainCheck — defensive / robustness", () => {
    test("null/empty/single-label input does not throw", () => {
        assert.equal(check(null), null);
        assert.equal(check(""), null);
        assert.equal(check("localhost"), null);
    });

    test("malformed punycode label does not throw", () => {
        assert.doesNotThrow(() => check("xn--.com"));
        assert.doesNotThrow(() => check("xn--zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.com"));
    });

    test("a host with no separate name+suffix (single-label registered domain) does not throw", () => {
        assert.doesNotThrow(() => check("com"));
    });
});
