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
    const suspiciousDownloadLinks = pageScan.suspiciousDownloadLinks || 0;
    const reasons = [];
    let score = 0;

    if (lowerUrl.startsWith("http://")) {
        score += 25;
        reasons.push(
            "This page is not encrypted (HTTP). Attackers can intercept data.",
        );
    }

    if (
        lowerUrl.includes("login") ||
        lowerUrl.includes("verify") ||
        lowerUrl.includes("secure")
    ) {
        score += 12;
        reasons.push("The URL uses words often seen in phishing traps.");
    }

    if (keywordHits > 0) {
        score += Math.min(30, keywordHits * 3);
        reasons.push(
            "The page uses urgent/security keywords to pressure users.",
        );
    }

    if (hasSensitiveInputs) {
        score += 15;
        reasons.push("This page asks for sensitive account details.");
    }

    if (suspiciousDownloadLinks > 0) {
        score += 25;
        reasons.push("This page includes risky download links.");
    }

    score = Math.min(100, score);
    const trusted = isTrustedDomain(url);
    if (trusted) {
        score = Math.max(0, score - 35);
        reasons.unshift("The domain is in SentinelX trusted domain list.");
    }

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
        suspicious_download_links: suspiciousDownloadLinks,
        is_trusted_domain: trusted,
        trusted_domains_used: TRUSTED_DOMAINS,
        source: "local-fallback",
    };
}

async function notifyProtection(title, message) {
    console.info("SentinelX protection event:", title, message);
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
            report.explanation ||
            "SentinelX blocked this page for your safety.",
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
            report.explanation ||
            "SentinelX blocked this action for your safety.",
        timestamp: new Date().toISOString(),
    };

    await setStorage({ lastProtectionEvent: event });
    await chrome.tabs.update(tabId, {
        url: buildBlockedUrl(targetUrl, report),
    });
    await notifyProtection(
        "SentinelX blocked a threat",
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
        suspicious_download_links: 0,
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
                suspicious_download_links:
                    pageScan.suspicious_download_links || 0,
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
            suspiciousDownloadLinks: pageScan.suspicious_download_links,
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
        "SentinelX blocked a download",
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
