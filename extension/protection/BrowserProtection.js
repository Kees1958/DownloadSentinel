"use strict";

const BrowserProtection = function () {

    let abortControllers = new Map();

    const closeOpenConnections = function (key, reason) {
        if (abortControllers.has(key)) {
            abortControllers.get(key).abort(reason);
            abortControllers.set(key, new AbortController());
        }
    };

    return {

        abandonPendingRequests: function (key, reason) {
            closeOpenConnections(key, reason);
        },

        checkIfUrlIsMalicious: function (key, url, callback) {

            if (!key || !url || !callback) return;

            const startTime = Date.now();
            const urlObject = new URL(url);

            if (!abortControllers.has(key)) {
                abortControllers.set(key, new AbortController());
            }

            const checkUrlWithVirusTotal = async function (settings) {

                // Extension off → do nothing (background.js already guards this,
                // but belt-and-suspenders check here too)
                if (!settings.extensionEnabled) return;

                // No VT check enabled or no API key → skip silently
                if (!settings.virusTotalEnabled) return;
                if (!settings.isVtApiKeySet || !settings.vtApiKey) return;

                if (BrowserProtection.allowedUrls.has(urlObject.href)) {
                    callback(
                        new ProtectionResult(
                            url,
                            ProtectionResult.ResultType.PROBABLY_SAFE,
                            ProtectionResult.ResultOrigin.VIRUSTOTAL,
                            { score: 100, confidence: "Cached", hardRuleApplied: null }
                        ),
                        Date.now() - startTime
                    );
                    return;
                }

                const controller = abortControllers.get(key);
                const signal = controller?.signal;

                let callbackFired = false;
                const timeoutId = setTimeout(() => {
                    if (callbackFired) return;
                    callbackFired = true;
                    controller?.abort("timeout");
                    callback(
                        new ProtectionResult(
                            url,
                            ProtectionResult.ResultType.UNKNOWN,
                            ProtectionResult.ResultOrigin.VIRUSTOTAL
                        ),
                        Date.now() - startTime
                    );
                }, 5000);

                try {
                    // Small delay to let the warning page finish loading before
                    // the result might arrive, reducing the chance of a missed push
                    await new Promise(resolve => setTimeout(resolve, 100));

                    // btoa() only handles Latin1; encode via UTF-8 bytes first
                    // to safely handle IDN domains and non-ASCII URL paths
                    const urlId = btoa(
                        encodeURIComponent(url).replace(/%([0-9A-F]{2})/g,
                            (_, hex) => String.fromCharCode(parseInt(hex, 16)))
                    )
                        .replace(/\+/g, "-")
                        .replace(/\//g, "_")
                        .replace(/=+$/, "");

                    const response = await fetch(
                        `https://www.virustotal.com/api/v3/urls/${urlId}`,
                        {
                            method: "GET",
                            headers: { "x-apikey": settings.vtApiKey },
                            signal
                        }
                    );

                    if (response.status === 404) {
                        clearTimeout(timeoutId);
                        if (callbackFired) return;
                        callbackFired = true;
                        callback(
                            new ProtectionResult(url, ProtectionResult.ResultType.UNKNOWN, ProtectionResult.ResultOrigin.VIRUSTOTAL),
                            Date.now() - startTime
                        );
                        return;
                    }

                    if (!response.ok) {
                        clearTimeout(timeoutId);
                        if (callbackFired) return;
                        callbackFired = true;
                        callback(
                            new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.VIRUSTOTAL),
                            Date.now() - startTime
                        );
                        return;
                    }

                    const data = await response.json();
                    const attributes = data?.data?.attributes || {};
                    const stats = attributes.last_analysis_stats || {};
                    const reputation = attributes.reputation;
                    const totalVotes = attributes.total_votes || {};
                    const firstSubmissionDate = attributes.first_submission_date || null;

                    clearTimeout(timeoutId);
                    if (callbackFired) return;
                    callbackFired = true;

                    const evaluation = ScoringEngine.evaluate({
                        stats,
                        reputation,
                        totalVotes,
                        firstSubmissionDate
                    });

                    const details = {
                        score: evaluation.score,
                        confidence: evaluation.confidence,
                        breakdown: evaluation.breakdown,
                        hardRuleApplied: evaluation.hardRuleApplied
                    };

                    if (evaluation.classification === ProtectionResult.ResultType.PROBABLY_SAFE) {
                        BrowserProtection.allowedUrls.add(urlObject.href);
                    }

                    callback(
                        new ProtectionResult(url, evaluation.classification, ProtectionResult.ResultOrigin.VIRUSTOTAL, details),
                        Date.now() - startTime
                    );

                } catch (error) {
                    clearTimeout(timeoutId);
                    if (error.name === "AbortError") return;
                    if (callbackFired) return;
                    callbackFired = true;
                    callback(new ProtectionResult(url, ProtectionResult.ResultType.FAILED, ProtectionResult.ResultOrigin.VIRUSTOTAL), Date.now() - startTime);
                }
            };

            Settings.get(settings => checkUrlWithVirusTotal(settings));
        }
    };
}();

BrowserProtection.allowedUrls = new Set();
