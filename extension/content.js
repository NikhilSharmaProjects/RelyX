const SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "password",
    "urgent",
    "free",
    "download",
    "bank",
    "wallet",
    "security alert",
    "reset",
    "confirm",
    "otp",
    "seed phrase",
];

const RISKY_DOWNLOAD_PATTERN =
    /\.(exe|msi|bat|cmd|scr|js|vbs|iso|apk|zip|rar)(\?|$)/i;

const URGENCY_PHRASES = [
    "act now",
    "urgent",
    "limited time",
    "expires today",
    "verify now",
    "immediately",
    "confirm now",
];

const FEAR_PHRASES = [
    "account suspended",
    "security breach",
    "unauthorized access",
    "legal action",
    "you will lose access",
    "device infected",
];

const CREDENTIAL_HARVEST_PHRASES = [
    "confirm your password",
    "enter your password",
    "seed phrase",
    "wallet recovery",
    "one-time password",
    "otp",
    "cvv",
];

const HARD_BLOCK_SCORE = 70;
const WARNING_SCORE = 45;

let currentReport = null;
let styleInjected = false;

function runtimeMessage(payload) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage(payload, (response) => {
            if (chrome.runtime.lastError) {
                resolve(null);
                return;
            }
            resolve(response || null);
        });
    });
}

function countOccurrences(text, word) {
    const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(`\\b${escaped}\\b`, "gi");
    const matches = text.match(regex);
    return matches ? matches.length : 0;
}

function findSensitiveInputs() {
    const inputSelectors = [
        "input[type='password']",
        "input[type='email']",
        "input[name*='password' i]",
        "input[name*='email' i]",
        "input[id*='password' i]",
        "input[id*='email' i]",
    ];
    return document.querySelectorAll(inputSelectors.join(","));
}

function isElementHidden(element) {
    if (!element) return false;
    const style = window.getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return (
        element.hidden ||
        style.display === "none" ||
        style.visibility === "hidden" ||
        Number(style.opacity || 1) === 0 ||
        rect.width === 0 ||
        rect.height === 0
    );
}

function buildSelector(element) {
    if (!element || !element.tagName) return "";
    const tag = element.tagName.toLowerCase();
    if (element.id) return `#${element.id}`;
    if (element.name) return `${tag}[name='${element.name}']`;
    if (element.type) return `${tag}[type='${element.type}']`;
    return tag;
}

function findHiddenSensitiveInputs() {
    return Array.from(findSensitiveInputs()).filter((input) =>
        isElementHidden(input),
    );
}

function findExternalFormActions() {
    const forms = Array.from(document.querySelectorAll("form[action]"));
    const host = window.location.hostname.toLowerCase();
    return forms.filter((form) => {
        const action = (form.getAttribute("action") || "").trim();
        if (!action) return false;
        try {
            const actionUrl = new URL(action, window.location.href);
            return actionUrl.hostname.toLowerCase() !== host;
        } catch {
            return false;
        }
    });
}

function countPhraseHits(text, phrases) {
    const lower = (text || "").toLowerCase();
    return phrases.reduce(
        (sum, phrase) => sum + countOccurrences(lower, phrase),
        0,
    );
}

function uniqueSelectors(selectors) {
    const clean = selectors.filter(Boolean);
    return Array.from(new Set(clean)).slice(0, 10);
}

function findSuspiciousDownloadLinks() {
    const links = Array.from(document.querySelectorAll("a[href]"));
    return links.filter((link) => RISKY_DOWNLOAD_PATTERN.test(link.href));
}

function collectPageSignals() {
    const pageText = (
        document.body && document.body.innerText ? document.body.innerText : ""
    ).toLowerCase();

    const matchedKeywords = [];
    let keywordHits = 0;

    for (const keyword of SUSPICIOUS_KEYWORDS) {
        const hits = countOccurrences(pageText, keyword.toLowerCase());
        if (hits > 0) {
            matchedKeywords.push(keyword);
            keywordHits += hits;
        }
    }

    const sensitiveInputs = findSensitiveInputs();
    const hiddenSensitiveInputs = findHiddenSensitiveInputs();
    const externalFormActions = findExternalFormActions();
    const suspiciousDownloadLinks = findSuspiciousDownloadLinks();
    const urgencyHits = countPhraseHits(pageText, URGENCY_PHRASES);
    const fearHits = countPhraseHits(pageText, FEAR_PHRASES);
    const credentialHarvestHits = countPhraseHits(
        pageText,
        CREDENTIAL_HARVEST_PHRASES,
    );

    const highlightSelectors = uniqueSelectors([
        ...Array.from(hiddenSensitiveInputs).map((item) => buildSelector(item)),
        ...Array.from(externalFormActions).map((item) => buildSelector(item)),
        ...Array.from(suspiciousDownloadLinks)
            .slice(0, 4)
            .map((item) => buildSelector(item)),
    ]);

    return {
        page_text: pageText.slice(0, 12000),
        matched_keywords: matchedKeywords,
        keyword_hits: keywordHits,
        has_sensitive_inputs: sensitiveInputs.length > 0,
        hidden_sensitive_inputs: hiddenSensitiveInputs.length,
        external_form_actions: externalFormActions.length,
        suspicious_download_links: suspiciousDownloadLinks.length,
        urgency_hits: urgencyHits,
        fear_hits: fearHits,
        credential_harvest_hits: credentialHarvestHits,
        highlight_selectors: highlightSelectors,
    };
}

function injectStyles() {
    if (styleInjected) return;
    styleInjected = true;

    const style = document.createElement("style");
    style.id = "RelyX-style";
    style.textContent = `
        @keyframes relyxPulse {
            0% { transform: scale(0.98); box-shadow: 0 0 0 0 rgba(255, 82, 82, 0.55); }
            70% { transform: scale(1); box-shadow: 0 0 0 28px rgba(255, 82, 82, 0); }
            100% { transform: scale(0.98); box-shadow: 0 0 0 0 rgba(255, 82, 82, 0); }
        }

        @keyframes relyxSlide {
            from { transform: translateY(16px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        html.relyx-interaction-locked body > *:not(#RelyX-threat-overlay):not(#RelyX-risk-badge) {
            pointer-events: none !important;
            user-select: none !important;
            filter: blur(1px) saturate(0.7);
        }

        #RelyX-risk-badge {
            position: fixed;
            top: 12px;
            right: 12px;
            z-index: 2147483645;
            display: flex;
            align-items: center;
            gap: 10px;
            background: rgba(7, 12, 24, 0.86);
            border: 1px solid rgba(141, 255, 245, 0.35);
            color: #ebfeff;
            border-radius: 999px;
            padding: 8px 12px;
            font-family: "Segoe UI", Tahoma, sans-serif;
            backdrop-filter: blur(10px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
            transition: all 220ms ease;
            cursor: default;
        }

        #RelyX-risk-badge .relyx-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #2dd4bf;
            box-shadow: 0 0 0 0 rgba(45, 212, 191, 0.8);
        }

        #RelyX-risk-badge.high .relyx-dot {
            background: #ff5c7d;
            animation: relyxPulse 1.8s infinite;
        }

        #RelyX-risk-badge .relyx-score {
            font-weight: 800;
            font-size: 13px;
            letter-spacing: 0.2px;
        }

        #RelyX-risk-badge .relyx-meta {
            font-size: 11px;
            color: #b5cedf;
        }

        #RelyX-threat-overlay {
            position: fixed;
            inset: 0;
            z-index: 2147483647;
            display: grid;
            place-items: center;
            padding: 20px;
            background:
                radial-gradient(circle at 12% 15%, rgba(255, 117, 117, 0.28), transparent 35%),
                radial-gradient(circle at 78% 78%, rgba(255, 90, 96, 0.28), transparent 40%),
                linear-gradient(150deg, rgba(45, 6, 8, 0.96), rgba(25, 6, 9, 0.94));
            animation: relyxSlide 180ms ease;
        }

        #RelyX-threat-overlay .relyx-card {
            width: min(760px, 96vw);
            border-radius: 18px;
            border: 1px solid rgba(255, 134, 134, 0.45);
            background: rgba(25, 8, 14, 0.75);
            backdrop-filter: blur(9px);
            box-shadow: 0 30px 80px rgba(0, 0, 0, 0.5);
            color: #fff8fb;
            font-family: "Segoe UI", Tahoma, sans-serif;
            padding: 22px;
        }

        #RelyX-threat-overlay .relyx-badge {
            display: inline-block;
            padding: 7px 12px;
            border-radius: 999px;
            font-size: 11px;
            letter-spacing: 1px;
            text-transform: uppercase;
            font-weight: 700;
            color: #ffdce2;
            border: 1px solid rgba(255, 130, 130, 0.5);
            background: rgba(255, 102, 102, 0.16);
        }

        #RelyX-threat-overlay h2 {
            margin: 12px 0 8px;
            font-size: clamp(24px, 4vw, 36px);
            line-height: 1.15;
        }

        #RelyX-threat-overlay .relyx-summary {
            margin: 0;
            color: #ffe6ea;
            line-height: 1.45;
            font-size: 15px;
        }

        #RelyX-threat-overlay .relyx-meta-grid {
            margin-top: 14px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 10px;
        }

        #RelyX-threat-overlay .relyx-meta-item {
            border: 1px solid rgba(255, 182, 182, 0.25);
            border-radius: 12px;
            padding: 10px;
            background: rgba(56, 16, 20, 0.55);
        }

        #RelyX-threat-overlay .relyx-meta-item span {
            display: block;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: #ffc8d1;
        }

        #RelyX-threat-overlay .relyx-meta-item strong {
            margin-top: 4px;
            display: block;
            font-size: 15px;
        }

        #RelyX-threat-overlay .relyx-reasons {
            margin: 14px 0 0;
            padding-left: 18px;
        }

        #RelyX-threat-overlay .relyx-reasons li {
            margin-bottom: 8px;
            color: #ffe3e8;
        }

        #RelyX-threat-overlay .relyx-actions {
            margin-top: 16px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        #RelyX-threat-overlay button {
            border: 0;
            border-radius: 10px;
            padding: 11px 14px;
            font-weight: 700;
            cursor: pointer;
        }

        #RelyX-threat-overlay .relyx-leave {
            background: linear-gradient(90deg, #ff6b7d, #ff455f);
            color: #2d040b;
        }

        #RelyX-threat-overlay .relyx-override {
            background: #0e2735;
            color: #9fe7ff;
            border: 1px solid rgba(153, 229, 255, 0.35);
        }

        #RelyX-warning-banner {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 2147483646;
            padding: 11px 14px;
            color: #fff;
            font-family: "Segoe UI", Tahoma, sans-serif;
            font-size: 13px;
            background: linear-gradient(90deg, #b45309, #dc2626);
            box-shadow: 0 4px 18px rgba(0, 0, 0, 0.35);
            animation: relyxSlide 150ms ease;
        }
    `;
    document.documentElement.appendChild(style);
}

function severityLabel(report) {
    return String((report && report.severity) || "medium").toUpperCase();
}

function ensureRiskBadge() {
    injectStyles();
    let badge = document.getElementById("RelyX-risk-badge");
    if (!badge) {
        badge = document.createElement("div");
        badge.id = "RelyX-risk-badge";
        badge.innerHTML = `
            <span class="relyx-dot"></span>
            <div>
                <div class="relyx-score">RelyX Risk --</div>
                <div class="relyx-meta">Monitoring...</div>
            </div>
        `;
        document.documentElement.appendChild(badge);
    }
    return badge;
}

function updateRiskBadge(report) {
    const badge = ensureRiskBadge();
    const score = Number((report && report.risk_score) || 0);
    const severity = severityLabel(report);
    const confidence = String((report && report.confidence_level) || "low");

    const scoreEl = badge.querySelector(".relyx-score");
    const metaEl = badge.querySelector(".relyx-meta");
    if (scoreEl) {
        scoreEl.textContent = `RelyX Risk ${score}/100`;
    }
    if (metaEl) {
        metaEl.textContent = `${severity} • confidence ${confidence}`;
    }

    badge.classList.toggle("high", score >= HARD_BLOCK_SCORE);
}

function removeWarningBanner() {
    const existing = document.getElementById("RelyX-warning-banner");
    if (existing) existing.remove();
}

function showWarningBanner(report) {
    removeWarningBanner();
    if (!report || Number(report.risk_score || 0) < WARNING_SCORE) {
        return;
    }

    const banner = document.createElement("div");
    banner.id = "RelyX-warning-banner";
    const reasons = (report.reasons || []).slice(0, 2).join(" ");
    banner.textContent = `RelyX warning: Risk ${report.risk_score}/100 (${report.threat_type}). ${reasons}`;
    document.documentElement.appendChild(banner);
}

function unlockInteraction() {
    document.documentElement.classList.remove("relyx-interaction-locked");
}

function lockInteraction() {
    document.documentElement.classList.add("relyx-interaction-locked");
}

function removeThreatOverlay() {
    const existing = document.getElementById("RelyX-threat-overlay");
    if (existing) existing.remove();
    unlockInteraction();
}

function safeNavigateAway() {
    if (document.referrer && document.referrer.startsWith("http")) {
        window.history.back();
        return;
    }
    window.location.href = "about:blank";
}

async function requestOverride(targetUrl) {
    const response = await runtimeMessage({
        type: "REQUEST_OVERRIDE",
        target_url: targetUrl,
        explicit: true,
    });

    return Boolean(response && response.ok);
}

function renderOverlayContent(report, mode = "hard") {
    const riskScore = Number((report && report.risk_score) || 0);
    const threatType = (report && report.threat_type) || "Threat detected";
    const confidence = (report && report.confidence_level) || "low";
    const severity = severityLabel(report);
    const explanation =
        (report && report.explanation) ||
        "RelyX blocked this page because it exceeded the security threshold.";
    const reasons = Array.isArray(report && report.reasons)
        ? report.reasons.slice(0, 3)
        : ["High-risk security signals were detected."];

    const overlay = document.createElement("div");
    overlay.id = "RelyX-threat-overlay";

    const title =
        mode === "action"
            ? "Sensitive data blocked on unsafe page"
            : "RelyX actively blocked this threat";

    overlay.innerHTML = `
        <section class="relyx-card">
            <span class="relyx-badge">RelyX Active Shield</span>
            <h2>${title}</h2>
            <p class="relyx-summary">${explanation}</p>
            <div class="relyx-meta-grid">
                <div class="relyx-meta-item">
                    <span>Risk Score</span>
                    <strong>${riskScore}/100</strong>
                </div>
                <div class="relyx-meta-item">
                    <span>Threat Type</span>
                    <strong>${threatType}</strong>
                </div>
                <div class="relyx-meta-item">
                    <span>Severity</span>
                    <strong>${severity}</strong>
                </div>
                <div class="relyx-meta-item">
                    <span>Confidence</span>
                    <strong>${String(confidence).toUpperCase()}</strong>
                </div>
            </div>
            <ul class="relyx-reasons">
                ${reasons.map((reason) => `<li>${reason}</li>`).join("")}
            </ul>
            <div class="relyx-actions">
                <button type="button" class="relyx-leave">Leave Unsafe Page</button>
                <button type="button" class="relyx-override">Explicit Override (5 min)</button>
            </div>
        </section>
    `;

    const leaveButton = overlay.querySelector(".relyx-leave");
    const overrideButton = overlay.querySelector(".relyx-override");

    if (leaveButton) {
        leaveButton.addEventListener("click", () => {
            safeNavigateAway();
        });
    }

    if (overrideButton) {
        overrideButton.addEventListener("click", async () => {
            overrideButton.disabled = true;
            overrideButton.textContent = "Applying override...";
            const ok = await requestOverride(window.location.href);
            if (!ok) {
                overrideButton.disabled = false;
                overrideButton.textContent = "Override Failed - Retry";
            }
        });
    }

    return overlay;
}

function showThreatOverlay(report, mode = "hard") {
    removeThreatOverlay();
    lockInteraction();
    const overlay = renderOverlayContent(report, mode);
    document.documentElement.appendChild(overlay);
}

function highlightTriggeredElements(report) {
    const selectors =
        (report &&
        report.xai &&
        report.xai.dom &&
        Array.isArray(report.xai.dom.highlight_selectors)
            ? report.xai.dom.highlight_selectors
            : []) || [];

    selectors.slice(0, 8).forEach((selector) => {
        try {
            const element = document.querySelector(selector);
            if (!element) return;
            element.style.outline = "2px solid #ffbe4a";
            element.style.boxShadow = "0 0 0 3px rgba(255, 190, 74, 0.32)";
        } catch {
            // Ignore invalid selectors from dynamic pages.
        }
    });
}

function applyReport(report) {
    if (!report) return;
    currentReport = report;

    updateRiskBadge(report);
    showWarningBanner(report);
    highlightTriggeredElements(report);

    if (Number(report.risk_score || 0) >= HARD_BLOCK_SCORE) {
        showThreatOverlay(report, "hard");
    } else {
        removeThreatOverlay();
    }
}

function getClickTargetInfo(event) {
    const anchor =
        event.target && event.target.closest
            ? event.target.closest("a[href]")
            : null;
    if (!anchor) return null;
    const href = anchor.href || "";
    if (!href) return null;

    const actionKind = RISKY_DOWNLOAD_PATTERN.test(href)
        ? "download-click"
        : "link-click";

    return {
        href,
        actionKind,
        text: (anchor.innerText || anchor.textContent || "")
            .trim()
            .slice(0, 120),
    };
}

async function guardClick(event) {
    const info = getClickTargetInfo(event);
    if (!info) return;

    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();

    const response = await runtimeMessage({
        type: "SHOULD_BLOCK_ACTION",
        action_kind: info.actionKind,
        target_url: info.href,
        label: info.text,
    });

    if (response && response.blocked) {
        showThreatOverlay(response.event || currentReport || {}, "action");
        return;
    }

    window.location.assign(info.href);
}

async function guardFormSubmit(event) {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;

    const hasSensitiveInput =
        form.querySelector("input[type='password'],input[type='email']") !==
        null;
    if (!hasSensitiveInput) return;

    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();

    const response = await runtimeMessage({
        type: "SHOULD_BLOCK_ACTION",
        action_kind: "form-submit",
        target_url: window.location.href,
        label: "sensitive-form-submit",
    });

    if (response && response.blocked) {
        showThreatOverlay(
            {
                ...(response.report || currentReport || {}),
                explanation: "Sensitive data blocked on unsafe page",
            },
            "action",
        );
        return;
    }

    form.submit();
}

async function bootstrapPolicy() {
    ensureRiskBadge();
    const response = await runtimeMessage({ type: "GET_POLICY" });
    if (response && response.report) {
        applyReport(response.report);
    }
}

document.addEventListener(
    "click",
    (event) => {
        guardClick(event);
    },
    true,
);

document.addEventListener(
    "submit",
    (event) => {
        guardFormSubmit(event);
    },
    true,
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "RUN_PAGE_SCAN") {
        sendResponse({ scan: collectPageSignals() });
        return true;
    }

    if (message.type === "APPLY_REPORT" && message.report) {
        applyReport(message.report);
    }

    if (message.type === "SHOW_ACTION_BLOCK" && message.event) {
        showThreatOverlay(message.event, "action");
    }

    return false;
});

bootstrapPolicy();
