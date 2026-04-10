const BACKEND_URL = "http://127.0.0.1:8000";
const CACHE_TTL_MS = 5 * 60 * 1000;
const OVERRIDE_TTL_MS = 5 * 60 * 1000;
const HARD_BLOCK_SCORE = 70;
const FORM_BLOCK_SCORE = 55;
const ACTION_BLOCK_SCORE = 50;
const RISKY_DOWNLOAD_PATTERN =
    /\.(exe|msi|bat|cmd|scr|js|vbs|iso|apk|zip|rar)(\?|$)/i;

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

function normalizeCacheKey(url) {
    try {
        const parsed = new URL(url);
        parsed.hash = "";
        return parsed.toString();
    } catch {
        return String(url || "");
    }
}

function nowIso() {
    return new Date().toISOString();
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

async function callBackend(path, payload) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 9000);
    try {
        const response = await fetch(`${BACKEND_URL}${path}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
            signal: controller.signal,
        });

        if (!response.ok) {
            throw new Error(`backend_${response.status}`);
        }

        return await response.json();
    } finally {
        clearTimeout(timeout);
    }
}

function normalizeThreatType(score, hasSensitiveInputs, riskyDownloads) {
    if (riskyDownloads > 0 && score >= 60) return "Malware or Risky Download";
    if (hasSensitiveInputs && score >= 55) return "Credential Theft Risk";
    if (score >= 45) return "Suspicious Website";
    return "Likely Safe";
}

function localFallbackAnalysis(url, pageScan = {}) {
    const lowerUrl = (url || "").toLowerCase();
    const host = parseHost(url);
    const keywordHits = Number(pageScan.keyword_hits || 0);
    const hasSensitiveInputs = Boolean(pageScan.has_sensitive_inputs);
    const hiddenSensitiveInputs = Number(pageScan.hidden_sensitive_inputs || 0);
    const externalFormActions = Number(pageScan.external_form_actions || 0);
    const suspiciousDownloadLinks = Number(
        pageScan.suspicious_download_links || 0,
    );
    const urgencyHits = Number(pageScan.urgency_hits || 0);
    const fearHits = Number(pageScan.fear_hits || 0);
    const credentialHarvestHits = Number(pageScan.credential_harvest_hits || 0);
    const highlightSelectors = Array.isArray(pageScan.highlight_selectors)
        ? pageScan.highlight_selectors.slice(0, 10)
        : [];

    const signals = [];
    let score = 0;

    if (lowerUrl.startsWith("http://")) {
        score += 18;
        signals.push({
            signal: "missing_https",
            impact: 18,
            detail: "Page uses HTTP instead of HTTPS.",
            category: "transport",
        });
    }

    if (host.includes("xn--")) {
        score += 20;
        signals.push({
            signal: "punycode_domain",
            impact: 20,
            detail: "Punycode domain pattern detected.",
            category: "url",
        });
    }

    if (/\d{1,3}(\.\d{1,3}){3}/.test(host)) {
        score += 24;
        signals.push({
            signal: "ip_host",
            impact: 24,
            detail: "IP address used in host instead of domain.",
            category: "url",
        });
    }

    const lureWords = [
        "login",
        "verify",
        "secure",
        "wallet",
        "update",
        "bonus",
    ];
    const lureHits = lureWords.filter((word) => lowerUrl.includes(word)).length;
    if (lureHits > 0) {
        const impact = Math.min(16, 6 + lureHits * 2);
        score += impact;
        signals.push({
            signal: "lure_terms",
            impact,
            detail: "URL includes words commonly used in phishing lures.",
            category: "url",
        });
    }

    if (keywordHits > 0) {
        const impact = Math.min(24, keywordHits * 2);
        score += impact;
        signals.push({
            signal: "keyword_pressure_language",
            impact,
            detail: `Detected ${keywordHits} suspicious keyword hits.`,
            category: "content",
        });
    }

    if (hasSensitiveInputs) {
        score += 14;
        signals.push({
            signal: "sensitive_form_fields",
            impact: 14,
            detail: "Sensitive email/password fields detected.",
            category: "dom",
        });
    }

    if (hiddenSensitiveInputs > 0) {
        const impact = Math.min(30, hiddenSensitiveInputs * 10);
        score += impact;
        signals.push({
            signal: "hidden_sensitive_fields",
            impact,
            detail: `Detected ${hiddenSensitiveInputs} hidden sensitive inputs.`,
            category: "dom",
        });
    }

    if (externalFormActions > 0) {
        const impact = Math.min(30, externalFormActions * 10);
        score += impact;
        signals.push({
            signal: "external_form_submission",
            impact,
            detail: `Detected ${externalFormActions} forms posting to external domains.`,
            category: "dom",
        });
    }

    if (suspiciousDownloadLinks > 0) {
        const impact = Math.min(32, suspiciousDownloadLinks * 12);
        score += impact;
        signals.push({
            signal: "suspicious_download_links",
            impact,
            detail: `Detected ${suspiciousDownloadLinks} suspicious download links.`,
            category: "dom",
        });
    }

    const nlpImpact = Math.min(
        35,
        urgencyHits * 4 + fearHits * 5 + credentialHarvestHits * 8,
    );
    if (nlpImpact > 0) {
        score += nlpImpact;
        signals.push({
            signal: "social_engineering_language",
            impact: nlpImpact,
            detail: `Urgency ${urgencyHits}, fear ${fearHits}, credential ${credentialHarvestHits}.`,
            category: "nlp",
        });
    }

    if (isTrustedDomain(url)) {
        score = Math.max(0, score - 35);
        signals.push({
            signal: "trusted_domain",
            impact: -35,
            detail: "Trusted domain matched local allowlist.",
            category: "trust",
        });
    }

    score = Math.min(100, Math.max(0, score));
    const sortedSignals = signals
        .slice()
        .sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact));

    return {
        url,
        risk_score: score,
        block_threshold: HARD_BLOCK_SCORE,
        should_block: score >= HARD_BLOCK_SCORE,
        threat_type: normalizeThreatType(
            score,
            hasSensitiveInputs,
            suspiciousDownloadLinks,
        ),
        severity:
            score >= 80
                ? "critical"
                : score >= 60
                  ? "high"
                  : score >= 40
                    ? "medium"
                    : "low",
        confidence_level: "low",
        reasons: sortedSignals.slice(0, 3).map((item) => item.detail),
        explanation:
            "RelyX switched to heuristic fallback because threat-intel APIs were unavailable. Confidence is low.",
        llm_used: false,
        llm_error: "fallback_mode",
        https: lowerUrl.startsWith("https://"),
        domain: host,
        domain_age_days: null,
        is_trusted_domain: isTrustedDomain(url),
        api_flags: {
            google_safe_browsing: false,
            virustotal_malicious: false,
            virustotal_suspicious: false,
            phishtank: false,
        },
        api_checks: {
            google_safe_browsing: {
                queried: false,
                error: "fallback_mode",
            },
            virustotal: { queried: false, error: "fallback_mode" },
            phishtank: { queried: false, error: "fallback_mode" },
            whois: { queried: false, error: "fallback_mode" },
            certificate: { queried: false, error: "fallback_mode" },
        },
        xai: {
            model: "local_fallback_multilayer",
            feature_contributions: sortedSignals.slice(0, 10),
            url_features: {
                length: lowerUrl.length,
                entropy: null,
                tld: host.split(".").pop() || "",
                subdomain_depth: Math.max(0, host.split(".").length - 2),
                has_punycode: host.includes("xn--"),
                has_ip_host: /^\d{1,3}(\.\d{1,3}){3}$/.test(host),
                has_at_symbol: lowerUrl.includes("@"),
                hyphen_count: (host.match(/-/g) || []).length,
                trusted_domain: isTrustedDomain(url),
            },
            threat_intel: {
                google_safe_browsing: {
                    queried: false,
                    matched: false,
                    error: "fallback_mode",
                },
                virustotal: {
                    queried: false,
                    malicious: 0,
                    suspicious: 0,
                    error: "fallback_mode",
                },
                phishtank: {
                    queried: false,
                    matched: false,
                    error: "fallback_mode",
                },
            },
            dom: {
                highlight_selectors: highlightSelectors,
                has_sensitive_inputs: hasSensitiveInputs,
                hidden_sensitive_inputs: hiddenSensitiveInputs,
                external_form_actions: externalFormActions,
            },
            nlp: {
                urgency_hits: urgencyHits,
                fear_hits: fearHits,
                credential_harvest_hits: credentialHarvestHits,
            },
        },
        source: "local-fallback",
        timestamp: nowIso(),
    };
}

function localDownloadFallback(downloadItem) {
    const filename = (downloadItem.filename || "").toLowerCase();
    const sourceUrl = (
        downloadItem.url ||
        downloadItem.finalUrl ||
        ""
    ).toLowerCase();
    const reasons = [];
    let score = 0;

    if (RISKY_DOWNLOAD_PATTERN.test(filename)) {
        score += 55;
        reasons.push("File type is frequently abused to distribute malware.");
    }

    if (sourceUrl.startsWith("http://")) {
        score += 18;
        reasons.push("Download source is not encrypted (HTTP).");
    }

    if (/(crack|keygen|patch|free-download)/i.test(sourceUrl)) {
        score += 16;
        reasons.push("Download URL contains high-risk lure terms.");
    }

    score = Math.min(100, score);

    return {
        risk_score: score,
        block_threshold: HARD_BLOCK_SCORE,
        should_block: score >= 60,
        threat_type:
            score >= 60 ? "Malware or Risky Download" : "Suspicious Website",
        severity:
            score >= 80
                ? "critical"
                : score >= 60
                  ? "high"
                  : score >= 40
                    ? "medium"
                    : "low",
        confidence_level: "low",
        reasons: reasons.slice(0, 3),
        explanation:
            "RelyX used local fallback download checks because threat-intel APIs were unavailable. Confidence is low.",
        llm_used: false,
        llm_error: "fallback_mode",
        source_url: sourceUrl,
        filename: downloadItem.filename || "",
        api_flags: {
            google_safe_browsing: false,
            virustotal_malicious: false,
            virustotal_suspicious: false,
            phishtank: false,
        },
        api_checks: {
            virustotal: { queried: false, error: "fallback_mode" },
        },
        xai: {
            model: "local_fallback_download",
            feature_contributions: reasons.map((reason, idx) => ({
                signal: `fallback_download_signal_${idx + 1}`,
                impact: idx === 0 ? 55 : 16,
                detail: reason,
                category: "download",
            })),
            threat_intel: {},
            url_features: {},
        },
        source: "local-fallback",
        timestamp: nowIso(),
    };
}

function withReportDefaults(report, url) {
    if (!report || typeof report !== "object") {
        return localFallbackAnalysis(url || "", {});
    }

    const normalized = { ...report };
    normalized.url = normalized.url || url || "";
    normalized.timestamp = normalized.timestamp || nowIso();
    normalized.risk_score = Number(normalized.risk_score || 0);
    normalized.block_threshold = Number(
        normalized.block_threshold || HARD_BLOCK_SCORE,
    );
    normalized.threat_type =
        normalized.threat_type ||
        normalizeThreatType(normalized.risk_score, false, 0);
    normalized.reasons = Array.isArray(normalized.reasons)
        ? normalized.reasons.slice(0, 3)
        : [];
    normalized.explanation =
        normalized.explanation ||
        "RelyX detected risk signals and applied active safeguards.";
    normalized.confidence_level = normalized.confidence_level || "low";
    normalized.severity = normalized.severity || "medium";
    normalized.is_trusted_domain = Boolean(
        normalized.is_trusted_domain || isTrustedDomain(normalized.url),
    );
    normalized.xai = normalized.xai || {
        model: "unknown",
        feature_contributions: [],
        url_features: {},
        threat_intel: {},
    };

    if (!normalized.xai.feature_contributions) {
        normalized.xai.feature_contributions = [];
    }

    return normalized;
}

async function cleanupOverrides() {
    const state = await getStorage(["temporaryOverrides"]);
    const overrides = state.temporaryOverrides || {};
    const now = Date.now();
    let changed = false;

    for (const host of Object.keys(overrides)) {
        if (!overrides[host] || Number(overrides[host].expiresAt || 0) <= now) {
            delete overrides[host];
            changed = true;
        }
    }

    if (changed) {
        await setStorage({ temporaryOverrides: overrides });
    }

    return overrides;
}

async function setTemporaryOverride(url) {
    const host = parseHost(url);
    if (!host) return;

    const state = await getStorage(["temporaryOverrides"]);
    const overrides = state.temporaryOverrides || {};
    overrides[host] = {
        expiresAt: Date.now() + OVERRIDE_TTL_MS,
        url,
        grantedAt: nowIso(),
    };

    await setStorage({ temporaryOverrides: overrides });
}

async function isOverrideActive(url) {
    const host = parseHost(url);
    if (!host) return false;
    const overrides = await cleanupOverrides();
    const entry = overrides[host];
    return Boolean(entry && Number(entry.expiresAt || 0) > Date.now());
}

async function shouldHardBlock(report) {
    if (!report) return false;
    if (report.is_trusted_domain) return false;
    if (await isOverrideActive(report.url || "")) return false;
    return (
        Number(report.risk_score || 0) >=
        Number(report.block_threshold || HARD_BLOCK_SCORE)
    );
}

async function saveReport(tabId, report) {
    const state = await getStorage(["tabReports"]);
    const tabReports = state.tabReports || {};
    tabReports[String(tabId)] = report;
    await setStorage({ tabReports });
}

async function getCachedUrlReport(url, forceRefresh = false) {
    if (forceRefresh) return null;
    const key = normalizeCacheKey(url);
    const state = await getStorage(["urlCache"]);
    const urlCache = state.urlCache || {};
    const cached = urlCache[key];
    if (!cached) return null;
    if (Date.now() - Number(cached.cachedAt || 0) > CACHE_TTL_MS) {
        delete urlCache[key];
        await setStorage({ urlCache });
        return null;
    }
    return cached.report || null;
}

async function setCachedUrlReport(url, report) {
    const key = normalizeCacheKey(url);
    const state = await getStorage(["urlCache"]);
    const urlCache = state.urlCache || {};
    urlCache[key] = {
        cachedAt: Date.now(),
        report,
    };

    const keys = Object.keys(urlCache);
    if (keys.length > 200) {
        const sorted = keys
            .map((entry) => ({
                key: entry,
                cachedAt: Number(urlCache[entry].cachedAt || 0),
            }))
            .sort((a, b) => b.cachedAt - a.cachedAt)
            .slice(0, 200);
        const trimmed = {};
        sorted.forEach((entry) => {
            trimmed[entry.key] = urlCache[entry.key];
        });
        await setStorage({ urlCache: trimmed });
        return;
    }

    await setStorage({ urlCache });
}

async function analyzeUrl(url, forceRefresh = false) {
    if (!isHttpUrl(url)) return null;

    const cached = await getCachedUrlReport(url, forceRefresh);
    if (cached) {
        return withReportDefaults(cached, url);
    }

    let report;
    try {
        report = await callBackend("/analyze-url", {
            url,
            trusted_domains: TRUSTED_DOMAINS,
        });
    } catch {
        report = localFallbackAnalysis(url, {});
    }

    const normalized = withReportDefaults(report, url);
    await setCachedUrlReport(url, normalized);
    return normalized;
}

async function requestPageSignals(tabId) {
    const response = await messageTab(tabId, { type: "RUN_PAGE_SCAN" });
    if (!response || !response.scan) {
        return {
            page_text: "",
            matched_keywords: [],
            keyword_hits: 0,
            has_sensitive_inputs: false,
            hidden_sensitive_inputs: 0,
            external_form_actions: 0,
            suspicious_download_links: 0,
            urgency_hits: 0,
            fear_hits: 0,
            credential_harvest_hits: 0,
            highlight_selectors: [],
        };
    }
    return response.scan;
}

async function pushReportToTab(tabId, report) {
    await messageTab(tabId, {
        type: "APPLY_REPORT",
        report,
    });
}

function buildBlockedUrl(targetUrl, report, mode = "page") {
    const query = new URLSearchParams({
        target: targetUrl,
        score: String(report.risk_score || 0),
        threat: report.threat_type || "Threat detected",
        severity: report.severity || "high",
        confidence: report.confidence_level || "low",
        mode,
        reasons: JSON.stringify((report.reasons || []).slice(0, 3)),
        explanation:
            report.explanation ||
            "RelyX blocked this destination because risk is above the protection threshold.",
    });
    return `${chrome.runtime.getURL("blocked.html")}?${query.toString()}`;
}

async function blockNavigation(tabId, targetUrl, report, mode = "page") {
    const event = {
        type: mode,
        blocked_url: targetUrl,
        risk_score: Number(report.risk_score || 0),
        threat_type: report.threat_type || "Threat detected",
        severity: report.severity || "high",
        confidence_level: report.confidence_level || "low",
        reasons: (report.reasons || []).slice(0, 3),
        explanation:
            report.explanation ||
            "RelyX blocked this action because the risk score exceeded the safety threshold.",
        timestamp: nowIso(),
    };

    await setStorage({ lastProtectionEvent: event });
    await chrome.tabs.update(tabId, {
        url: buildBlockedUrl(targetUrl, report, mode),
    });
}

async function analyzePage(tabId, url, forceRefresh = false) {
    if (!isHttpUrl(url)) return null;

    const pageSignals = await requestPageSignals(tabId);
    let report;

    try {
        report = await callBackend("/analyze-page", {
            url,
            ...pageSignals,
            trusted_domains: TRUSTED_DOMAINS,
        });
    } catch {
        report = localFallbackAnalysis(url, pageSignals);
    }

    const normalized = withReportDefaults(report, url);
    await saveReport(tabId, normalized);
    await setCachedUrlReport(url, normalized);
    await pushReportToTab(tabId, normalized);

    if (await shouldHardBlock(normalized)) {
        await blockNavigation(tabId, url, normalized, "page");
    }

    return normalized;
}

async function getTabReport(tabId, url) {
    const state = await getStorage(["tabReports"]);
    const tabReports = state.tabReports || {};
    const stored = tabReports[String(tabId)];
    if (stored) {
        return withReportDefaults(stored, url);
    }
    return analyzePage(tabId, url, false);
}

async function analyzeDownload(downloadItem) {
    try {
        const result = await callBackend("/analyze-download", {
            filename: downloadItem.filename || "",
            source_url: downloadItem.url || downloadItem.finalUrl || "",
            referrer: downloadItem.referrer || "",
            mime: downloadItem.mime || "",
            total_bytes: downloadItem.totalBytes || 0,
            final_url: downloadItem.finalUrl || "",
            trusted_domains: TRUSTED_DOMAINS,
        });
        return withReportDefaults(
            result,
            downloadItem.url || downloadItem.finalUrl || "",
        );
    } catch {
        return localDownloadFallback(downloadItem);
    }
}

async function cancelUnsafeDownload(downloadItem, report) {
    await new Promise((resolve) => {
        chrome.downloads.cancel(downloadItem.id, () => resolve());
    });

    const alert = {
        type: "download",
        blocked: true,
        risk_score: Number(report.risk_score || 0),
        threat_type: report.threat_type,
        severity: report.severity,
        confidence_level: report.confidence_level,
        reasons: (report.reasons || []).slice(0, 3),
        explanation: report.explanation,
        filename: downloadItem.filename || downloadItem.finalUrl,
        source_url: downloadItem.url || downloadItem.finalUrl,
        timestamp: nowIso(),
    };

    await setStorage({
        lastDownloadAlert: alert,
        lastProtectionEvent: alert,
    });
}

async function handlePotentialNavigationBlock(tabId, url, mode) {
    if (!isHttpUrl(url)) return;
    const report = await analyzeUrl(url, false);
    if (!report) return;
    await saveReport(tabId, report);

    if (await shouldHardBlock(report)) {
        await blockNavigation(tabId, url, report, mode);
    }
}

chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.set({
        tabReports: {},
        urlCache: {},
        temporaryOverrides: {},
        lastDownloadAlert: null,
        lastProtectionEvent: null,
        trustedDomains: TRUSTED_DOMAINS,
    });
});

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0 || !isHttpUrl(details.url)) return;
    await handlePotentialNavigationBlock(
        details.tabId,
        details.url,
        "pre-navigation",
    );
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab && isHttpUrl(tab.url || "")) {
        analyzePage(tabId, tab.url, true);
    }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && isHttpUrl(tab.url || "")) {
        analyzePage(tab.id, tab.url, false);
    }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
    const state = await getStorage(["tabReports"]);
    const tabReports = state.tabReports || {};
    if (tabReports[String(tabId)]) {
        delete tabReports[String(tabId)];
        await setStorage({ tabReports });
    }
});

chrome.downloads.onCreated.addListener(async (downloadItem) => {
    const report = await analyzeDownload(downloadItem);
    if (!report) return;

    if (Number(report.risk_score || 0) >= 60 || report.should_block) {
        await cancelUnsafeDownload(downloadItem, report);
        return;
    }

    const alert = {
        type: "download",
        blocked: false,
        risk_score: Number(report.risk_score || 0),
        threat_type: report.threat_type,
        severity: report.severity,
        confidence_level: report.confidence_level,
        reasons: (report.reasons || []).slice(0, 3),
        explanation: report.explanation,
        filename: downloadItem.filename || downloadItem.finalUrl,
        source_url: downloadItem.url || downloadItem.finalUrl,
        timestamp: nowIso(),
    };
    await setStorage({ lastDownloadAlert: alert });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "GET_TAB_REPORT") {
        getTabReport(message.tabId, message.url)
            .then(async (report) => {
                const state = await getStorage([
                    "lastDownloadAlert",
                    "lastProtectionEvent",
                    "trustedDomains",
                ]);
                sendResponse({
                    report,
                    lastDownloadAlert: state.lastDownloadAlert || null,
                    lastProtectionEvent: state.lastProtectionEvent || null,
                    trustedDomains: state.trustedDomains || TRUSTED_DOMAINS,
                });
            })
            .catch(() => {
                sendResponse({
                    report: null,
                    lastDownloadAlert: null,
                    lastProtectionEvent: null,
                    trustedDomains: TRUSTED_DOMAINS,
                });
            });
        return true;
    }

    if (message.type === "TRIGGER_ANALYZE") {
        analyzePage(message.tabId, message.url, true)
            .then(async (report) => {
                const state = await getStorage([
                    "lastDownloadAlert",
                    "lastProtectionEvent",
                ]);
                sendResponse({
                    report,
                    lastDownloadAlert: state.lastDownloadAlert || null,
                    lastProtectionEvent: state.lastProtectionEvent || null,
                });
            })
            .catch(() => sendResponse({ report: null }));
        return true;
    }

    if (message.type === "SHOULD_BLOCK_ACTION") {
        const tabId = sender && sender.tab ? sender.tab.id : null;
        const tabUrl = sender && sender.tab ? sender.tab.url || "" : "";
        if (!tabId) {
            sendResponse({ blocked: false });
            return false;
        }

        getTabReport(tabId, tabUrl)
            .then(async (report) => {
                const risk = Number((report && report.risk_score) || 0);
                const actionKind = String(
                    (message && message.action_kind) || "",
                ).toLowerCase();
                const targetUrl = String(
                    (message && message.target_url) || "",
                ).toLowerCase();
                const riskyClick =
                    actionKind === "download-click" &&
                    RISKY_DOWNLOAD_PATTERN.test(targetUrl);

                const hardBlock = await shouldHardBlock(report);
                const blockForm =
                    actionKind === "form-submit" &&
                    (risk >= FORM_BLOCK_SCORE || hardBlock);
                const blockAction =
                    hardBlock ||
                    blockForm ||
                    (actionKind === "download-click" &&
                        (risk >= ACTION_BLOCK_SCORE || riskyClick));

                if (blockAction) {
                    const event = {
                        type: "blocked-action",
                        blocked: true,
                        action_kind: actionKind,
                        target_url: targetUrl,
                        risk_score: risk,
                        threat_type: report.threat_type,
                        severity: report.severity,
                        confidence_level: report.confidence_level,
                        reasons: (report.reasons || []).slice(0, 3),
                        explanation: blockForm
                            ? "Sensitive data blocked on unsafe page"
                            : report.explanation,
                        timestamp: nowIso(),
                    };
                    await setStorage({ lastProtectionEvent: event });
                    await messageTab(tabId, {
                        type: "SHOW_ACTION_BLOCK",
                        event,
                    });
                    sendResponse({ blocked: true, event, report });
                    return;
                }

                sendResponse({ blocked: false, report });
            })
            .catch(() => sendResponse({ blocked: false }));

        return true;
    }

    if (message.type === "REQUEST_OVERRIDE") {
        const targetUrl = String((message && message.target_url) || "");
        if (!isHttpUrl(targetUrl)) {
            sendResponse({ ok: false, error: "invalid_target_url" });
            return false;
        }

        const explicit = Boolean(message && message.explicit === true);
        if (!explicit) {
            sendResponse({ ok: false, error: "explicit_consent_required" });
            return false;
        }

        const acknowledgedDisclaimer = Boolean(
            message && message.acknowledged_disclaimer === true,
        );
        if (!acknowledgedDisclaimer) {
            sendResponse({ ok: false, error: "disclaimer_ack_required" });
            return false;
        }

        setTemporaryOverride(targetUrl)
            .then(async () => {
                const tabId =
                    (message && Number(message.tab_id || 0)) ||
                    (sender && sender.tab ? sender.tab.id : null);

                if (tabId) {
                    await chrome.tabs.update(tabId, { url: targetUrl });
                } else {
                    const tabs = await chrome.tabs.query({
                        active: true,
                        currentWindow: true,
                    });
                    if (tabs[0] && tabs[0].id) {
                        await chrome.tabs.update(tabs[0].id, {
                            url: targetUrl,
                        });
                    }
                }

                sendResponse({ ok: true });
            })
            .catch(() => sendResponse({ ok: false, error: "override_failed" }));
        return true;
    }

    if (message.type === "GET_POLICY") {
        const tabId = sender && sender.tab ? sender.tab.id : null;
        const tabUrl = sender && sender.tab ? sender.tab.url || "" : "";
        if (!tabId || !isHttpUrl(tabUrl)) {
            sendResponse({ report: null });
            return false;
        }

        getTabReport(tabId, tabUrl)
            .then((report) => sendResponse({ report }))
            .catch(() => sendResponse({ report: null }));
        return true;
    }

    return false;
});
