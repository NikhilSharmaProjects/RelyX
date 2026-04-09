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
        const decoded = safeDecode(encoded);
        const parsed = JSON.parse(decoded);
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
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

const threat = getParam("threat") || "Risk detected";
const score = Number(getParam("score") || 0);
const target = getParam("target") || "Unknown";
const explanation =
    safeDecode(getParam("explanation")) ||
    "SentinelX blocked a dangerous page before it could harm you.";

setText("threatType", threat);
setText("riskScore", `${score}/100`);
setText("targetUrl", target);
setText("plainText", explanation);
renderReasons(parseReasons());

document.getElementById("backBtn")?.addEventListener("click", () => {
    window.history.back();
});

document.getElementById("homeBtn")?.addEventListener("click", () => {
    chrome.tabs.create({ url: "chrome://newtab" });
});
