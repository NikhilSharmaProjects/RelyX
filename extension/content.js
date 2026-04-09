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
];
const RISKY_DOWNLOAD_PATTERN =
    /\.(exe|msi|bat|cmd|scr|js|vbs|iso|apk|zip|rar)(\?|$)/i;

function countOccurrences(text, word) {
    const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(`\\b${escaped}\\b`, "gi");
    const matches = text.match(regex);
    return matches ? matches.length : 0;
}

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
    const suspiciousDownloadLinks = findSuspiciousDownloadLinks();

    return {
        page_text: pageText.slice(0, 12000),
        matched_keywords: matchedKeywords,
        keyword_hits: keywordHits,
        has_sensitive_inputs: sensitiveInputs.length > 0,
        suspicious_download_links: suspiciousDownloadLinks.length,
    };
}

function removeExistingWarning() {
    const existingBanner = document.getElementById("sentinelx-warning-banner");
    if (existingBanner) {
        existingBanner.remove();
    }
}

function markSensitiveInputs() {
    const inputs = findSensitiveInputs();
    inputs.forEach((input) => {
        input.style.outline = "2px solid #ff4d4f";
        input.style.backgroundColor = "#fff5f5";
    });

    const firstForm = document.querySelector("form");
    if (firstForm && !document.getElementById("sentinelx-form-warning")) {
        const formWarning = document.createElement("div");
        formWarning.id = "sentinelx-form-warning";
        formWarning.textContent =
            "SentinelX blocked sensitive actions on this page to protect your data.";
        formWarning.style.background = "#fff1f0";
        formWarning.style.border = "1px solid #ffccc7";
        formWarning.style.color = "#a8071a";
        formWarning.style.padding = "10px 12px";
        formWarning.style.marginBottom = "12px";
        formWarning.style.borderRadius = "8px";
        firstForm.insertAdjacentElement("beforebegin", formWarning);
    }
}

function showWarningBanner(report) {
    removeExistingWarning();

    const banner = document.createElement("div");
    banner.id = "sentinelx-warning-banner";
    banner.style.position = "fixed";
    banner.style.top = "0";
    banner.style.left = "0";
    banner.style.right = "0";
    banner.style.zIndex = "2147483647";
    banner.style.padding = "12px 16px";
    banner.style.fontFamily = "Segoe UI, Tahoma, sans-serif";
    banner.style.fontSize = "14px";
    banner.style.lineHeight = "1.35";
    banner.style.color = "#fff";
    banner.style.background = "linear-gradient(90deg, #9f1239, #b91c1c)";
    banner.style.boxShadow = "0 4px 16px rgba(0,0,0,0.35)";

    const reasons = (report.reasons || [])
        .slice(0, 3)
        .map((r) => `• ${r}`)
        .join(" ");
    banner.textContent = `SentinelX Protection: Risk ${report.risk_score}/100 (${report.threat_type}). ${reasons}`;

    document.body.appendChild(banner);
    if (document.body) {
        document.body.style.paddingTop = `${banner.offsetHeight + 6}px`;
    }

    if (report.has_sensitive_inputs && report.risk_score >= 45) {
        markSensitiveInputs();
    }
}

function ensureActionBlockOverlay(event) {
    const existing = document.getElementById("sentinelx-action-block-overlay");
    if (existing) {
        existing.remove();
    }

    const overlay = document.createElement("div");
    overlay.id = "sentinelx-action-block-overlay";
    overlay.style.position = "fixed";
    overlay.style.inset = "0";
    overlay.style.background = "rgba(8, 10, 18, 0.82)";
    overlay.style.zIndex = "2147483647";
    overlay.style.display = "grid";
    overlay.style.placeItems = "center";
    overlay.style.padding = "16px";

    const card = document.createElement("div");
    card.style.maxWidth = "560px";
    card.style.width = "100%";
    card.style.background = "#111827";
    card.style.border = "1px solid #ef4444";
    card.style.borderRadius = "14px";
    card.style.padding = "18px";
    card.style.color = "#f9fafb";
    card.style.fontFamily = "Segoe UI, Tahoma, sans-serif";

    const heading = document.createElement("h2");
    heading.textContent = "SentinelX protected you";
    heading.style.margin = "0 0 10px";
    heading.style.fontSize = "22px";

    const summary = document.createElement("p");
    summary.style.margin = "0 0 8px";
    summary.textContent =
        event && event.explanation
            ? event.explanation
            : "I blocked this action because it can expose your data or device to harm.";

    const bullets = document.createElement("ul");
    bullets.style.margin = "8px 0 0";
    bullets.style.paddingLeft = "18px";
    const reasons = (
        event && event.reasons
            ? event.reasons
            : ["Risk signals were too high for safe browsing."]
    ).slice(0, 3);
    reasons.forEach((reason) => {
        const li = document.createElement("li");
        li.textContent = reason;
        li.style.marginBottom = "6px";
        bullets.appendChild(li);
    });

    const closeBtn = document.createElement("button");
    closeBtn.textContent = "Understood";
    closeBtn.style.marginTop = "14px";
    closeBtn.style.padding = "10px 14px";
    closeBtn.style.border = "0";
    closeBtn.style.borderRadius = "8px";
    closeBtn.style.fontWeight = "700";
    closeBtn.style.cursor = "pointer";
    closeBtn.style.background = "#22d3ee";
    closeBtn.style.color = "#022c22";
    closeBtn.addEventListener("click", () => overlay.remove());

    card.appendChild(heading);
    card.appendChild(summary);
    card.appendChild(bullets);
    card.appendChild(closeBtn);
    overlay.appendChild(card);
    document.documentElement.appendChild(overlay);
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
    const targetInfo = getClickTargetInfo(event);
    if (!targetInfo) return;

    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();

    const response = await runtimeMessage({
        type: "SHOULD_BLOCK_ACTION",
        action_kind: targetInfo.actionKind,
        target_url: targetInfo.href,
        label: targetInfo.text,
    });

    if (response && response.blocked) {
        ensureActionBlockOverlay(response.event || null);
        return;
    }

    window.location.assign(targetInfo.href);
}

async function guardFormSubmit(event) {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    const hasSensitive =
        form.querySelector("input[type='password'],input[type='email']") !==
        null;
    if (!hasSensitive) return;

    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();

    const response = await runtimeMessage({
        type: "SHOULD_BLOCK_ACTION",
        action_kind: "form-submit",
        target_url: location.href,
        label: "sensitive-form-submit",
    });

    if (response && response.blocked) {
        ensureActionBlockOverlay(response.event || null);
        return;
    }

    form.submit();
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

    if (message.type === "SHOW_WARNING" && message.report) {
        showWarningBanner(message.report);
    }

    if (message.type === "SHOW_ACTION_BLOCK" && message.event) {
        ensureActionBlockOverlay(message.event);
    }

    return false;
});
