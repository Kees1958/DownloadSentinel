"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { SketchyUrlCheck } from "../../protection/SketchyUrlCheck.js";

describe("SketchyUrlCheck — exact brand impersonation", () => {
    test("legitimate brand domain scores 0", () => {
        assert.equal(SketchyUrlCheck.check("https://www.google.com/file.exe").score, 0);
    });

    test("legitimate brand subdomain scores 0", () => {
        assert.equal(SketchyUrlCheck.check("https://accounts.google.com/file.exe").score, 0);
    });

    test("brand keyword on an unrelated host is flagged", () => {
        const r = SketchyUrlCheck.check("https://paypal-login-secure.com/file.exe");
        assert.ok(r.score > 0);
        assert.ok(r.signals.some(s => s.includes("paypal")));
    });

    // v3.2.0 (3P Matrix alignment §2): short/ordinary-word keywords (< 5
    // letters, or an explicitly-listed common word — see Brands.js) are now
    // wholeNameOnly: they only match when the registered domain's WHOLE
    // name is the keyword, never as a word merely appearing inside a
    // longer compound name. "zoom" (4 letters) is one of these — a known,
    // accepted precision/recall trade-off (measured false-alarm rate on a
    // 215,348-site CrUX sample: substring matching on short/common words
    // was the single biggest source of false alarms).
    test("a short wholeNameOnly keyword used as a hyphen-prefix is NOT flagged (known trade-off)", () => {
        assert.equal(SketchyUrlCheck.check("https://zoom-login-secure.com/file.exe").score, 0);
    });

    test("a short wholeNameOnly keyword used as the WHOLE registered name IS flagged", () => {
        const r = SketchyUrlCheck.check("https://zoom.cc/file.exe"); // fake domain, different TLD
        assert.ok(r.score > 0);
        assert.ok(r.signals.some(s => s.includes("zoom")));
    });

    test("unrelated URL with no brand keyword scores 0", () => {
        assert.equal(SketchyUrlCheck.check("https://download.example.com/setup.exe").score, 0);
    });
});

describe("SketchyUrlCheck — fuzzy (typo) brand impersonation", () => {
    // v3.2.0 (3P Matrix alignment §2.3): FUZZY_MIN_BRAND_LENGTH raised 5 -> 7
    // (Brands.js) — "google" (6 letters) is no longer fuzzy-eligible at all,
    // a deliberate trade-off (measured: the remaining 5-6 letter noise
    // disappears once only 7+-letter keywords fuzzy-match). The "fuzzy
    // distance scales with keyword length" describe block below already
    // covers the 7+-letter case this test used to exercise with "google".
    test("a one-letter typo of a 6-letter-or-shorter brand name is NOT fuzzy-flagged (known trade-off)", () => {
        assert.equal(SketchyUrlCheck.check("https://gooogle.com/file.exe").score, 0);
    });

    test("a short (< 5 char) brand keyword is never fuzzy-matched", () => {
        // "bmq" is edit-distance 1 from "bmw", but "bmw" is too short to fuzzy-match
        assert.equal(SketchyUrlCheck.check("https://bmq.com/file.exe").score, 0);
    });

    test("exact match and fuzzy match don't both fire for the same brand", () => {
        // "google" itself — exact match should fire, fuzzy should not add a second hit
        const r = SketchyUrlCheck.check("https://google-secure-login.info/file.exe");
        const googleHits = r.signals.filter(s => s.includes("google"));
        assert.equal(googleHits.length, 1);
    });
});

describe("SketchyUrlCheck — generic-word brand guards (booking.com / monsterenergy)", () => {
    test("a hostname with the bare word 'booking' is not flagged", () => {
        assert.equal(SketchyUrlCheck.check("https://mybookingapp.com/file.exe").score, 0);
    });

    test("booking.com used as a subdomain-prefix trick IS flagged", () => {
        const r = SketchyUrlCheck.check("https://booking.com.evil-login.net/file.exe");
        assert.ok(r.signals.some(s => s.includes("booking.com")));
    });

    test("a hostname with the bare word 'monster' is not flagged", () => {
        assert.equal(SketchyUrlCheck.check("https://monstertrucks.com/file.exe").score, 0);
    });

    test("a fake monsterenergy domain IS flagged", () => {
        const r = SketchyUrlCheck.check("https://monsterenergy-rewards.net/file.exe");
        assert.ok(r.signals.some(s => s.includes("monsterenergy")));
    });
});

describe("SketchyUrlCheck — non-obvious canonical domains verified during the V2.6.1 audit", () => {
    test("Schneider Electric's real domain (se.com) is not flagged", () => {
        assert.equal(SketchyUrlCheck.check("https://se.com/file.exe").score, 0);
    });

    test("a fake schneiderelectric domain IS flagged", () => {
        const r = SketchyUrlCheck.check("https://schneiderelectric-secure.net/file.exe");
        assert.ok(r.signals.some(s => s.includes("schneiderelectric")));
    });
});

describe("SketchyUrlCheck — exceptions (unrelated company sharing a keyword)", () => {
    test("zoominfo.com is not flagged as a Zoom impersonation", () => {
        assert.equal(SketchyUrlCheck.check("https://zoominfo.com/file.exe").score, 0);
    });

    test("a subdomain of zoominfo.com is also not flagged", () => {
        assert.equal(SketchyUrlCheck.check("https://app.zoominfo.com/file.exe").score, 0);
    });

    test("common generic subdomain labels are never fuzzy-matched (app~apple, mail~gmail)", () => {
        // Regression test: "app" was previously edit-distance 2 from "apple",
        // and "mail" is edit-distance 1 from "gmail" — pure coincidence, not
        // typosquatting. See FUZZY_EXCLUDED_LABELS in SketchyUrlCheck.js.
        assert.equal(SketchyUrlCheck.check("https://app.example.com/file.exe").score, 0);
        assert.equal(SketchyUrlCheck.check("https://mail.example.com/file.exe").score, 0);
    });

    test("two real, unrelated brands in the table that are coincidentally near each other are not cross-flagged", () => {
        // Regression test: shopify.com is edit-distance 2 from "spotify", and
        // cisco.com is edit-distance 2 from "costco" — both real, unrelated
        // brand pairs already in BRANDS. See isKnownLegitimateBrandHost().
        assert.equal(SketchyUrlCheck.check("https://shopify.com/file.exe").score, 0);
        assert.equal(SketchyUrlCheck.check("https://spotify.com/file.exe").score, 0);
        assert.equal(SketchyUrlCheck.check("https://cisco.com/file.exe").score, 0);
        assert.equal(SketchyUrlCheck.check("https://costco.com/file.exe").score, 0);
    });

    test("ordinary English words are not fuzzy-matched against short brand keywords", () => {
        // Regression test: "space"/"place" are edit-distance 2 from "slack",
        // and "teach" is edit-distance 2 from "teams" — both 5-letter
        // keywords, where a distance of 2 is 40% of the word. See
        // maxAllowedDistance() and FUZZY_LONG_KEYWORD_LENGTH.
        assert.equal(SketchyUrlCheck.check("https://space.unrelated-example.net/file.exe").score, 0);
        assert.equal(SketchyUrlCheck.check("https://place.unrelated-example.net/file.exe").score, 0);
        assert.equal(SketchyUrlCheck.check("https://teach.unrelated-example.net/file.exe").score, 0);
    });
});

describe("SketchyUrlCheck — fuzzy distance scales with keyword length", () => {
    test("a 7+ letter keyword catches a 2-character typo", () => {
        // "microsft" is edit-distance 1 from "microsoft" (9 letters, long enough for distance 2)
        const r = SketchyUrlCheck.check("https://microsft.com/file.exe");
        assert.ok(r.signals.some(s => s.includes("microsoft")));
    });

    test("known accepted gap: a 2-edit homograph trick on a 6-letter-or-shorter brand is not caught", () => {
        // "arnazon" (the classic "rn"→"m" visual trick) is edit-distance 2
        // from "amazon" (6 letters) — deliberately NOT caught, because
        // loosening the threshold for short keywords reintroduces real false
        // positives (see the slack/teams test above). This test documents
        // the known gap rather than silently leaving it unverified — see
        // maxAllowedDistance() in SketchyUrlCheck.js for the full rationale.
        assert.equal(SketchyUrlCheck.check("https://arnazon.com/file.exe").score, 0);
    });
});

describe("SketchyUrlCheck — blob: URLs (trusted-domain / hostname extraction fix)", () => {
    test("a blob: URL wrapping a brand's real domain is not flagged", () => {
        // Regression test: SketchyUrlCheck used to read url.hostname
        // directly, which is "" for blob: URLs — now routed through
        // UrlUtils.getHostname(), which unwraps blob: URLs correctly.
        assert.equal(SketchyUrlCheck.check("blob:https://google.com/uuid-here").score, 0);
    });

    test("a blob: URL wrapping an unrelated host with a brand keyword is still flagged", () => {
        const r = SketchyUrlCheck.check("blob:https://paypal-login-secure.com/uuid-here");
        assert.ok(r.score > 0);
    });
});
