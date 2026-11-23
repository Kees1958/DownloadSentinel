"use strict";

/**
 * ScriptExts.js — Single source of truth for script/LOLBin file extensions.
 *
 * Previously duplicated in:
 *   background.js         (SCRIPT_EXTS array)
 *   ScoringEngineV2.js    (isScript parameter, inline Set in check 11)
 *   MimeCheck.js          (inline scriptExts Set in text/plain handler)
 *   WarningPage.js        (SCRIPT_EXTS_CLIENT array)
 *
 * These are interpreted/scripted formats rather than compiled binaries.
 * They are commonly abused as LOLBins (Living Off The Land Binaries) since
 * they execute via a trusted system interpreter (PowerShell, WScript, bash,
 * Python, etc.) rather than running as a standalone executable.
 *
 * To add a new script extension: add it here only. All checks pick it up
 * automatically on the next load.
 *
 * Exposed as:
 *   ScriptExts.set   — Set<string> for O(1) has() lookups
 *   ScriptExts.list  — string[] for includes() / spread usage
 */
export const ScriptExts = (function () {

    const list = [
        // Windows scripting
        "bat", "chm", "cmd", "hta", "jse", "js", "lnk", "msc",
        "ps1", "ps1xml", "ps2", "ps2xml", "psc1", "psc2",
        "vb", "vbe", "vbs", "wsf", "wsh",
        // Unix/Linux shell
        "awk", "bash", "csh", "ksh", "sed", "sh", "tcl", "tcsh", "zsh",
        // Interpreted languages
        "php", "pl", "pm", "py", "pyc", "pyo", "rb",
        // macOS scripting
        "applescript", "command", "scpt", "workflow"
    ];

    const set = new Set(list);

    return { list, set };
})();
