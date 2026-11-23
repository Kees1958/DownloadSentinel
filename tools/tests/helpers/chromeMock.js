"use strict";

/**
 * chromeMock.js — minimal in-memory chrome.storage/chrome.alarms mock for
 * unit tests.
 *
 * Storage.js / Settings.js are the only modules allowed to touch
 * chrome.storage directly (C4 — single storage layer); background.js's own
 * sweep alarm is the only remaining chrome.alarms user (v3.3.0, 3P Matrix
 * alignment item 18, removed util/FilterDataLoader.js, the only other
 * module that used to touch it). This is the one mock the test suite needs
 * for both.
 *
 * Both chrome.storage.local.get/set and chrome.alarms.get/create/clear
 * support the real MV3 dual calling convention — callback OR Promise (no
 * callback passed) — since different callers in this codebase use either
 * form (Storage.js/Settings.js use the callback form; background.js's own
 * alarm wiring uses the Promise form).
 *
 * Resource lifecycle (guard pattern, matches AppConstants.js conventions):
 *   installChromeMock()   — INIT:  attach globalThis.chrome, empty store
 *   resetChromeMock()     — CLEAR: wipe stored data/alarms between tests, keep mock installed
 *   uninstallChromeMock() — RELEASE: remove globalThis.chrome entirely
 *   setGrantedOrigins()   — v3.3.1: preset chrome.permissions grants (request() only "succeeds" for these)
 */

let store = {};
let alarms = new Map();
let alarmListeners = [];
let grantedOrigins = new Set(); // v3.3.1 — chrome.permissions mock state

function installChromeMock() {
    grantedOrigins = new Set();
    store = {};
    alarms = new Map();
    alarmListeners = [];
    globalThis.chrome = {
        storage: {
            local: {
                get(key, callback) {
                    const result = {};
                    if (Object.prototype.hasOwnProperty.call(store, key)) {
                        result[key] = store[key];
                    }
                    if (callback) { queueMicrotask(() => callback(result)); return undefined; }
                    return Promise.resolve(result);
                },
                set(data, callback) {
                    Object.assign(store, data);
                    if (callback) { queueMicrotask(() => callback()); return undefined; }
                    return Promise.resolve();
                }
            }
        },
        alarms: {
            get(name, callback) {
                const alarm = alarms.get(name) || undefined;
                if (callback) { queueMicrotask(() => callback(alarm)); return undefined; }
                return Promise.resolve(alarm);
            },
            create(name, info) {
                alarms.set(name, { name, ...info });
            },
            clear(name, callback) {
                const existed = alarms.delete(name);
                if (callback) { queueMicrotask(() => callback(existed)); return undefined; }
                return Promise.resolve(existed);
            },
            onAlarm: {
                addListener(fn) { alarmListeners.push(fn); },
                removeListener(fn) { alarmListeners = alarmListeners.filter(l => l !== fn); }
            }
        },
        permissions: {
            // Promise form only — the codebase (util/DnsPermissions.js) never uses callbacks here.
            contains({ origins = [] }) { return Promise.resolve(origins.every(o => grantedOrigins.has(o))); },
            request({ origins = [] }) { return Promise.resolve(origins.every(o => grantedOrigins.has(o))); }, // "user declines" unless pre-granted
            remove({ origins = [] }) { origins.forEach(o => grantedOrigins.delete(o)); return Promise.resolve(true); }
        },
        runtime: {
            lastError: undefined
        }
    };
}

function resetChromeMock() {
    grantedOrigins = new Set();
    store = {};
    alarms = new Map();
    alarmListeners = [];
}

function uninstallChromeMock() {
    delete globalThis.chrome;
    grantedOrigins = new Set();
    store = {};
    alarms = new Map();
    alarmListeners = [];
}

// Test helper: simulate the user having granted (or revoked) a host permission.
function setGrantedOrigins(origins) {
    grantedOrigins = new Set(origins);
}

export { installChromeMock, resetChromeMock, uninstallChromeMock, setGrantedOrigins };
