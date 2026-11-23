"use strict";

// ── FocusRing.js ──────────────────────────────────────────────────────────────
// v3.5.4 (button scheme ported from 3P Matrix 4.4.6, ui/focus-ring.js) — the
// default button has keyboard focus from the start (Enter works) but shows NO
// focus ring, so both buttons look identical. The ring appears once the user
// navigates by keyboard (Tab / arrow keys) and disappears again on the next
// pointer press. CSS: WarningPage.css `.kbd-nav .btn:focus-visible`.
//
// Public interface:
//   FocusRing.init()  — idempotent; attaches the two document listeners once
//
// Guards: init runs once (a second call is a no-op); the two listeners are
// owned by this page for its whole (short) life and removed on `pagehide`,
// so nothing outlives the window. No state besides one class on <html>.
// ─────────────────────────────────────────────────────────────────────────────

// ── Settings (one place) ─────────────────────────────────────────────────────
const KEYBOARD_CLASS = "kbd-nav";
const NAV_KEYS = Object.freeze(["Tab", "ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"]);

let initialized = false;

function onKeyDown(e) {
    if (NAV_KEYS.includes(e.key)) document.documentElement.classList.add(KEYBOARD_CLASS);
}
function onPointerDown() {
    document.documentElement.classList.remove(KEYBOARD_CLASS);
}
function release() {
    document.removeEventListener("keydown", onKeyDown);
    document.removeEventListener("pointerdown", onPointerDown);
    window.removeEventListener("pagehide", release);
    document.documentElement.classList.remove(KEYBOARD_CLASS);
    initialized = false;
}

function init() {
    if (initialized) return;
    initialized = true;
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("pagehide", release);
}

export const FocusRing = Object.freeze({ init });
