const BACKEND_URL = "http://127.0.0.1:8000";
const RISKY_DOWNLOAD_EXTENSIONS = [
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".scr",
    ".js",
    ".vbs",
    ".iso",
    ".apk",
    ".zip",
    ".rar",
];
const TRUSTED_DOMAINS = [
    "google.com",
    "microsoft.com",
    "github.com",
    "wikipedia.org",
    "cloudflare.com",
    "apple.com",
    "amazon.com",
    "openai.com",
];
const HARD_BLOCK_SCORE = 68;

function isHttpUrl(url) {
    return (
        typeof url === "string" &&
        (url.startsWith("http://") || url.startsWith("https://"))
    );
}

function parseHost(url) {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch {
        return "";
    }
}

function isTrustedDomain(url) {
    const host = parseHost(url);
    if (!host) return false;
    return TRUSTED_DOMAINS.some(
        (trusted) => host === trusted || host.endsWith(`.${trusted}`),
    );
}

function getStorage(keys) {
    return new Promise((resolve) => {
        chrome.storage.local.get(keys, (items) => resolve(items));
    });
}

function setStorage(items) {
    return new Promise((resolve) => {
        chrome.storage.local.set(items, () => resolve());
    });
}

function messageTab(tabId, payload) {
    return new Promise((resolve) => {
        chrome.tabs.sendMessage(tabId, payload, (response) => {
            if (chrome.runtime.lastError) {
                resolve(null);
                return;
            }
            resolve(response || null);
        });
    });
}

function normalizeThreatType(
    score,
    hasSensitiveInputs,
    suspiciousDownloadLinks,
) {
    if (suspiciousDownloadLinks > 0 || score >= 75) return "Malware / Scam";
    if (hasSensitiveInputs && score >= 55) return "Unsafe Login";
    if (score >= 45) return "Phishing Suspicion";
    return "Likely Safe";
}

function shouldHardBlock(report) {
    if (!report) return false;
    if (report.is_trusted_domain) return false;

    const score = Number(report.risk_score || 0);
    const threat = String(report.threat_type || "").toLowerCase();
    const hasSensitiveInputs = Boolean(report.has_sensitive_inputs);
    const suspiciousDownloads = Number(report.suspicious_download_links || 0);

    if (score >= HARD_BLOCK_SCORE) return true;
    if (suspiciousDownloads > 0 && score >= 55) return true;
    if (hasSensitiveInputs && score >= 60) return true;
    if (threat.includes("malware") || threat.includes("credential theft"))
        return true;
    return false;
}

function localFallbackAnalysis(url, pageScan = {}) {
    const lowerUrl = (url || "").toLowerCase();
    const keywordHits = pageScan.keywordHits || 0;
    const hasSensitiveInputs = Boolean(pageScan.hasSensitiveInputs);
    const hiddenSensitiveInputs = Number(pageScan.hiddenSensitiveInputs || 0);
    const externalFormActions = Number(pageScan.externalFormActions || 0);
    const suspiciousDownloadLinks = pageScan.suspiciousDownloadLinks || 0;
    const urgencyHits = Number(pageScan.urgencyHits || 0);
    const fearHits = Number(pageScan.fearHits || 0);
    const credentialHarvestHits = Number(pageScan.credentialHarvestHits || 0);
    const highlightSelectors = Array.isArray(pageScan.highlightSelectors)
        ? pageScan.highlightSelectors.slice(0, 10)
        : [];
    const reasons = [];
    const featureContributions = [];
    let score = 0;

    if (lowerUrl.startsWith("http://")) {
        score += 25;
        reasons.push(
            "This page is not encrypted (HTTP). Attackers can intercept data.",
        );
        featureContributions.push({
            signal: "http_transport",
            impact: 25,
            detail: "Connection is HTTP.",
            category: "url",
        });
    }

    if (
        lowerUrl.includes("login") ||
        lowerUrl.includes("verify") ||
        lowerUrl.includes("secure")
    ) {
        score += 12;
        reasons.push("The URL uses words often seen in phishing traps.");
        featureContributions.push({
            signal: "phishing_lure_terms",
            impact: 12,
            detail: "URL includes login/verify/secure style wording.",
            category: "url",
        });
    }

    if (keywordHits > 0) {
        const keywordImpact = Math.min(30, keywordHits * 3);
        score += keywordImpact;
        reasons.push(
            "The page uses urgent/security keywords to pressure users.",
        );
        featureContributions.push({
            signal: "keyword_language",
            impact: keywordImpact,
            detail: `Detected ${keywordHits} suspicious keyword hits.`,
            category: "content",
        });
    }

    if (hasSensitiveInputs) {
        score += 15;
        reasons.push("This page asks for sensitive account details.");
        featureContributions.push({
            signal: "sensitive_inputs",
            impact: 15,
            detail: "Credential/email form fields detected.",
            category: "dom",
        });
    }

    if (hiddenSensitiveInputs > 0) {
        const hiddenImpact = Math.min(24, hiddenSensitiveInputs * 8);
        score += hiddenImpact;
        reasons.push("Hidden sensitive fields were found on this page.");
        featureContributions.push({
            signal: "hidden_credential_fields",
            impact: hiddenImpact,
            detail: `Detected ${hiddenSensitiveInputs} hidden sensitive fields.`,
            category: "dom",
        });
    }

    if (externalFormActions > 0) {
        const externalImpact = Math.min(24, externalFormActions * 8);
        score += externalImpact;
        reasons.push("Form actions submit data to an external domain.");
        featureContributions.push({
            signal: "external_form_action",
            impact: externalImpact,
            detail: `Detected ${externalFormActions} external form action(s).`,
            category: "dom",
        });
    }

    if (suspiciousDownloadLinks > 0) {
        score += 25;
        reasons.push("This page includes risky download links.");
        featureContributions.push({
            signal: "suspicious_download_links",
            impact: 25,
            detail: `Detected ${suspiciousDownloadLinks} suspicious download links.`,
            category: "dom",
        });
    }

    const nlpImpact = Math.min(
        35,
        urgencyHits * 5 + fearHits * 6 + credentialHarvestHits * 8,
    );
    if (nlpImpact > 0) {
        score += nlpImpact;
        reasons.push(
            "NLP language cues suggest urgency, fear, or credential-harvesting intent.",
        );
        featureContributions.push({
            signal: "nlp_social_engineering",
            impact: nlpImpact,
            detail: `Urgency ${urgencyHits}, fear ${fearHits}, credential ${credentialHarvestHits}.`,
            category: "nlp",
        });
    }

    score = Math.min(100, score);
    const trusted = isTrustedDomain(url);
    if (trusted) {
        score = Math.max(0, score - 35);
        reasons.unshift("The domain is in RelyX trusted domain list.");
        featureContributions.push({
            signal: "trusted_domain",
            impact: -35,
            detail: "Trusted domain reduced final risk.",
            category: "url",
        });
    }

    const sortedContributions = featureContributions
        .slice()
        .sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact))
        .slice(0, 8);

    return {
        url,
        risk_score: score,
        threat_type: normalizeThreatType(
            score,
            hasSensitiveInputs,
            suspiciousDownloadLinks,
        ),
        reasons: reasons.slice(0, 3),
        explanation:
            reasons.length > 0
                ? `I blocked or warned this page because: ${reasons.slice(0, 3).join(" ")}`
                : "No strong threat signals were detected by local analysis.",
        https: lowerUrl.startsWith("https://"),
        domain_age_days: null,
        keyword_hits: keywordHits,
        has_sensitive_inputs: hasSensitiveInputs,
        hidden_sensitive_inputs: hiddenSensitiveInputs,
        external_form_actions: externalFormActions,
        suspicious_download_links: suspiciousDownloadLinks,
        urgency_hits: urgencyHits,
        fear_hits: fearHits,
        credential_harvest_hits: credentialHarvestHits,
        is_trusted_domain: trusted,
        threat_intel_score: 0,
        xai: {
            model: "layered_rules_nlp_threat_intel",
            feature_contributions: sortedContributions,
            url_features: {
                length: lowerUrl.length,
                entropy: null,
                tld: parseHost(url).split(".").pop() || "",
                subdomain_depth: Math.max(
                    0,
                    parseHost(url).split(".").length - 2,
                ),
                has_punycode: parseHost(url).includes("xn--"),
                has_ip_host: /^\d{1,3}(\.\d{1,3}){3}$/.test(parseHost(url)),
                has_at_symbol: lowerUrl.includes("@"),
                hyphen_count: (parseHost(url).match(/-/g) || []).length,
            },
            nlp: {
                urgency_hits: urgencyHits,
                fear_hits: fearHits,
                credential_harvest_hits: credentialHarvestHits,
            },
            dom: {
                highlight_selectors: highlightSelectors,
                hidden_sensitive_inputs: hiddenSensitiveInputs,
                external_form_actions: externalFormActions,
            },
            threat_intel: {
                virustotal: { queried: false },
                openphish: { queried: false },
            },
        },
        trusted_domains_used: TRUSTED_DOMAINS,
        source: "local-fallback",
    };
}

async function notifyProtection(title, message) {
    console.info("RelyX protection event:", title, message);
}

async function saveReport(tabId, report) {
    const storageState = await getStorage(["tabReports"]);
    const tabReports = storageState.tabReports || {};
    tabReports[String(tabId)] = report;
    await setStorage({ tabReports });
}

function buildBlockedUrl(targetUrl, report) {
    const query = new URLSearchParams({
        target: targetUrl,
        score: String(report.risk_score || 0),
        threat: report.threat_type || "Risk detected",
        reasons: JSON.stringify((report.reasons || []).slice(0, 3)),
        explanation:
            report.explanation || "RelyX blocked this page for your safety.",
    });
    return `${chrome.runtime.getURL("blocked.html")}?${query.toString()}`;
}

async function blockNavigation(tabId, targetUrl, report, mode = "page") {
    const event = {
        type: mode,
        blocked_url: targetUrl,
        risk_score: report.risk_score || 0,
        threat_type: report.threat_type || "Risk detected",
        reasons: (report.reasons || []).slice(0, 3),
        explanation:
            report.explanation || "RelyX blocked this action for your safety.",
        timestamp: new Date().toISOString(),
    };

    await setStorage({ lastProtectionEvent: event });
    await chrome.tabs.update(tabId, {
        url: buildBlockedUrl(targetUrl, report),
    });
    await notifyProtection(
        "RelyX blocked a threat",
        "I saved you from a potentially harmful page.",
    );
}

async function analyzeUrlOnly(url) {
    if (!isHttpUrl(url)) return null;
    let report;

    try {
        const response = await fetch(`${BACKEND_URL}/analyze-url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url,
                trusted_domains: TRUSTED_DOMAINS,
            }),
        });

        if (!response.ok) {
            throw new Error(`Backend error: ${response.status}`);
        }

        report = await response.json();
        report.source = "backend-url";
    } catch {
        report = localFallbackAnalysis(url, {});
    }

    report.is_trusted_domain = Boolean(
        report.is_trusted_domain || isTrustedDomain(url),
    );
    report.timestamp = new Date().toISOString();
    return report;
}

async function analyzePage(tabId, url) {
    if (!isHttpUrl(url)) return null;

    const scanResponse = await messageTab(tabId, { type: "RUN_PAGE_SCAN" });
    const pageScan = (scanResponse && scanResponse.scan) || {
        page_text: "",
        keyword_hits: 0,
        matched_keywords: [],
        has_sensitive_inputs: false,
        hidden_sensitive_inputs: 0,
        external_form_actions: 0,
        suspicious_download_links: 0,
        urgency_hits: 0,
        fear_hits: 0,
        credential_harvest_hits: 0,
        highlight_selectors: [],
    };

    let report;
    try {
        const response = await fetch(`${BACKEND_URL}/analyze-page`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url,
                page_text: pageScan.page_text || "",
                matched_keywords: pageScan.matched_keywords || [],
                keyword_hits: pageScan.keyword_hits || 0,
                has_sensitive_inputs: Boolean(pageScan.has_sensitive_inputs),
                hidden_sensitive_inputs: pageScan.hidden_sensitive_inputs || 0,
                external_form_actions: pageScan.external_form_actions || 0,
                suspicious_download_links:
                    pageScan.suspicious_download_links || 0,
                urgency_hits: pageScan.urgency_hits || 0,
                fear_hits: pageScan.fear_hits || 0,
                credential_harvest_hits: pageScan.credential_harvest_hits || 0,
                highlight_selectors: pageScan.highlight_selectors || [],
                trusted_domains: TRUSTED_DOMAINS,
            }),
        });

        if (!response.ok) {
            throw new Error(`Backend error: ${response.status}`);
        }

        report = await response.json();
        report.source = "backend";
    } catch {
        report = localFallbackAnalysis(url, {
            keywordHits: pageScan.keyword_hits,
            hasSensitiveInputs: pageScan.has_sensitive_inputs,
            hiddenSensitiveInputs: pageScan.hidden_sensitive_inputs,
            externalFormActions: pageScan.external_form_actions,
            suspiciousDownloadLinks: pageScan.suspicious_download_links,
            urgencyHits: pageScan.urgency_hits,
            fearHits: pageScan.fear_hits,
            credentialHarvestHits: pageScan.credential_harvest_hits,
            highlightSelectors: pageScan.highlight_selectors,
        });
    }

    report.timestamp = new Date().toISOString();
    report.is_trusted_domain = Boolean(
        report.is_trusted_domain || isTrustedDomain(url),
    );
    await saveReport(tabId, report);

    if (shouldHardBlock(report)) {
        await blockNavigation(tabId, url, report, "page");
        return report;
    }

    if ((report.risk_score || 0) >= 45) {
        await messageTab(tabId, { type: "SHOW_WARNING", report });
    }

    return report;
}

async function getTabReport(tabId, url) {
    const { tabReports } = await getStorage(["tabReports"]);
    const report =
        tabReports && tabReports[String(tabId)]
            ? tabReports[String(tabId)]
            : null;

    if (report) {
        return report;
    }

    return analyzePage(tabId, url);
}

function localDownloadFallback(downloadItem) {
    const filename = (
        downloadItem.filename ||
        downloadItem.finalUrl ||
        ""
    ).toLowerCase();
    const sourceUrl = (
        downloadItem.url ||
        downloadItem.finalUrl ||
        ""
    ).toLowerCase();
    const referrer = (downloadItem.referrer || "").toLowerCase();

    const reasons = [];
    let riskScore = 0;

    const matchedExt = RISKY_DOWNLOAD_EXTENSIONS.find((ext) =>
        filename.endsWith(ext),
    );
    if (matchedExt) {
        riskScore += 55;
        reasons.push(
            `File type ${matchedExt} is often used to distribute malware.`,
        );
    }

    if (sourceUrl.startsWith("http://")) {
        riskScore += 20;
        reasons.push("The download source is not encrypted (HTTP).");
    }

    if (
        sourceUrl.includes("free") ||
        sourceUrl.includes("crack") ||
        sourceUrl.includes("keygen")
    ) {
        riskScore += 20;
        reasons.push(
            "The source URL includes terms frequently linked to unsafe software.",
        );
    }

    if (
        referrer &&
        (referrer.includes("urgent") || referrer.includes("verify"))
    ) {
        riskScore += 10;
        reasons.push("The referring page uses urgency language.");
    }

    return {
        risk_score: Math.min(100, riskScore),
        threat_type: "Risky Download",
        reasons: reasons.slice(0, 3),
        explanation: reasons.length
            ? `I blocked this file to protect you. ${reasons.slice(0, 3).join(" ")}`
            : "No strong download threat found.",
        should_block: riskScore >= 60,
        source: "local-fallback",
    };
}

async function analyzeDownload(downloadItem) {
    try {
        const response = await fetch(`${BACKEND_URL}/analyze-download`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                filename: downloadItem.filename || "",
                source_url: downloadItem.url || downloadItem.finalUrl || "",
                referrer: downloadItem.referrer || "",
                mime: downloadItem.mime || "",
                total_bytes: downloadItem.totalBytes || 0,
                final_url: downloadItem.finalUrl || "",
                trusted_domains: TRUSTED_DOMAINS,
            }),
        });
        if (!response.ok) throw new Error("backend");
        const result = await response.json();
        result.source = "backend";
        return result;
    } catch {
        return localDownloadFallback(downloadItem);
    }
}

async function cancelUnsafeDownload(downloadItem, report) {
    await new Promise((resolve) =>
        chrome.downloads.cancel(downloadItem.id, () => resolve()),
    );
    const alert = {
        type: "download",
        blocked: true,
        risk_score: report.risk_score,
        threat_type: report.threat_type,
        reasons: (report.reasons || []).slice(0, 3),
        explanation: report.explanation,
        filename: downloadItem.filename || downloadItem.finalUrl,
        source_url: downloadItem.url || downloadItem.finalUrl,
        timestamp: new Date().toISOString(),
    };
    await setStorage({ lastDownloadAlert: alert, lastProtectionEvent: alert });
    await notifyProtection(
        "RelyX blocked a download",
        "I blocked a potentially harmful file before it could run.",
    );
}

chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.set({
        tabReports: {},
        lastDownloadAlert: null,
        lastProtectionEvent: null,
        trustedDomains: TRUSTED_DOMAINS,
    });
});

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0 || !isHttpUrl(details.url)) return;
    const report = await analyzeUrlOnly(details.url);
    if (!report) return;
    await saveReport(details.tabId, report);
    if (shouldHardBlock(report)) {
        await blockNavigation(
            details.tabId,
            details.url,
            report,
            "pre-navigation",
        );
    }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab && isHttpUrl(tab.url)) {
        analyzePage(tabId, tab.url);
    }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && isHttpUrl(tab.url)) {
        analyzePage(tab.id, tab.url);
    }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
    const { tabReports } = await getStorage(["tabReports"]);
    if (!tabReports) return;
    delete tabReports[String(tabId)];
    await setStorage({ tabReports });
});

chrome.downloads.onCreated.addListener(async (downloadItem) => {
    const analysis = await analyzeDownload(downloadItem);
    if (!analysis) return;

    if (analysis.should_block || Number(analysis.risk_score || 0) >= 60) {
        await cancelUnsafeDownload(downloadItem, analysis);
        return;
    }

    const alert = {
        type: "download",
        blocked: false,
        risk_score: analysis.risk_score,
        threat_type: analysis.threat_type,
        reasons: (analysis.reasons || []).slice(0, 3),
        explanation: analysis.explanation,
        filename: downloadItem.filename || downloadItem.finalUrl,
        source_url: downloadItem.url || downloadItem.finalUrl,
        timestamp: new Date().toISOString(),
    };
    await setStorage({ lastDownloadAlert: alert });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "GET_TAB_REPORT") {
        getTabReport(message.tabId, message.url)
            .then(async (report) => {
                const {
                    lastDownloadAlert,
                    lastProtectionEvent,
                    trustedDomains,
                } = await getStorage([
                    "lastDownloadAlert",
                    "lastProtectionEvent",
                    "trustedDomains",
                ]);
                sendResponse({
                    report,
                    lastDownloadAlert: lastDownloadAlert || null,
                    lastProtectionEvent: lastProtectionEvent || null,
                    trustedDomains: trustedDomains || TRUSTED_DOMAINS,
                });
            })
            .catch(() =>
                sendResponse({
                    report: null,
                    lastDownloadAlert: null,
                    lastProtectionEvent: null,
                }),
            );
        return true;
    }

    if (message.type === "TRIGGER_ANALYZE") {
        analyzePage(message.tabId, message.url)
            .then((report) => sendResponse({ report }))
            .catch(() => sendResponse({ report: null }));
        return true;
    }

    if (message.type === "SHOULD_BLOCK_ACTION") {
        const tabId = sender && sender.tab ? sender.tab.id : null;
        if (!tabId) {
            sendResponse({ blocked: false });
            return false;
        }

        getTabReport(tabId, sender.tab.url)
            .then(async (report) => {
                const risk = Number((report && report.risk_score) || 0);
                const actionKind = String(
                    message.action_kind || "",
                ).toLowerCase();
                const targetUrl = String(
                    message.target_url || "",
                ).toLowerCase();
                const riskyExt = RISKY_DOWNLOAD_EXTENSIONS.some((ext) =>
                    targetUrl.includes(ext),
                );
                const shouldBlock =
                    shouldHardBlock(report) ||
                    (actionKind === "form-submit" && risk >= 55) ||
                    (actionKind === "download-click" &&
                        (risk >= 45 || riskyExt));

                if (shouldBlock) {
                    const event = {
                        type: "blocked-action",
                        blocked: true,
                        action_kind: actionKind,
                        target_url: message.target_url || "",
                        risk_score: risk,
                        threat_type: report
                            ? report.threat_type
                            : "Risk detected",
                        reasons: report
                            ? (report.reasons || []).slice(0, 3)
                            : ["Risk level is high for this action."],
                        explanation: report
                            ? report.explanation
                            : "I blocked this action because it could put your data or device at risk.",
                        timestamp: new Date().toISOString(),
                    };
                    await setStorage({ lastProtectionEvent: event });
                    sendResponse({ blocked: true, event });
                    return;
                }

                sendResponse({ blocked: false, report });
            })
            .catch(() => sendResponse({ blocked: false }));
        return true;
    }

    return false;
});
