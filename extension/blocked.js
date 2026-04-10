function getParam(name) {
    const params = new URLSearchParams(window.location.search);
    return params.get(name) || "";
}

function safeDecode(value) {
    try {
        return decodeURIComponent(value);
    } catch {
        return value;
    }
}

function parseReasons() {
    const encoded = getParam("reasons");
    if (!encoded) return [];
    try {
        const parsed = JSON.parse(safeDecode(encoded));
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

function setText(id, text) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = text;
    }
}

function renderReasons(list) {
    const ul = document.getElementById("reasons");
    if (!ul) return;
    ul.innerHTML = "";
    (list || []).slice(0, 3).forEach((reason) => {
        const li = document.createElement("li");
        li.textContent = reason;
        ul.appendChild(li);
    });
}

async function requestOverride(targetUrl, acknowledgedDisclaimer) {
    const tabIdFromQuery = Number(getParam("tab_id") || 0);
    let tabId =
        Number.isFinite(tabIdFromQuery) && tabIdFromQuery > 0
            ? tabIdFromQuery
            : null;

    if (!tabId) {
        const [tab] = await chrome.tabs.query({
            active: true,
            currentWindow: true,
        });
        tabId = tab && tab.id ? tab.id : null;
    }

    const response = await chrome.runtime.sendMessage({
        type: "REQUEST_OVERRIDE",
        target_url: targetUrl,
        tab_id: tabId,
        explicit: true,
        acknowledged_disclaimer: Boolean(acknowledgedDisclaimer),
    });
    return Boolean(response && response.ok);
}

function fallbackLeave() {
    if (window.history.length > 1) {
        window.history.back();
        return;
    }
    window.location.href = "about:blank";
}

const target = getParam("target") || "Unknown";
const score = Number(getParam("score") || 0);
const threat = getParam("threat") || "Threat detected";
const severity = (getParam("severity") || "high").toUpperCase();
const confidence = (getParam("confidence") || "low").toUpperCase();
const explanation =
    safeDecode(getParam("explanation")) ||
    "RelyX blocked this destination before you could interact with a high-risk page.";

setText("targetUrl", target);
setText("riskScore", `${score}/100`);
setText("threatType", threat);
setText("severity", severity);
setText("confidence", confidence);
setText("plainText", explanation);
renderReasons(parseReasons());

document.getElementById("leaveBtn")?.addEventListener("click", () => {
    fallbackLeave();
});

document.getElementById("newTabBtn")?.addEventListener("click", () => {
    chrome.tabs.create({ url: "chrome://newtab" });
});

function setupSuspiciousSiteContinue() {
    document
        .getElementById("overrideBtn")
        ?.addEventListener("click", async (event) => {
            const button = event.currentTarget;
            if (!(button instanceof HTMLButtonElement)) return;

            const acknowledgment = document.getElementById("responsibilityAck");
            const hint = document.getElementById("overrideHint");
            const isChecked =
                acknowledgment instanceof HTMLInputElement
                    ? acknowledgment.checked
                    : false;

            if (!isChecked) {
                if (hint) {
                    hint.textContent =
                        "Please confirm that RelyX is not responsible before continuing.";
                }
                return;
            }

            const userConfirmed = window.confirm(
                "You are about to continue to a blocked site. RelyX is not responsible for further actions or consequences. Continue?",
            );
            if (!userConfirmed) {
                return;
            }

            button.disabled = true;
            button.textContent = "Applying override...";

            const ok = await requestOverride(target, true);
            if (!ok) {
                button.disabled = false;
                button.textContent = "Override Failed - Retry";
                if (hint) {
                    hint.textContent =
                        "Override failed. Please try again in a moment.";
                }
            }
        });
}

setupSuspiciousSiteContinue();
