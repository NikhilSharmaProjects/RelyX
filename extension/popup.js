const riskScoreEl = document.getElementById("riskScore");
const riskDialEl = document.getElementById("riskDial");
const threatTypeEl = document.getElementById("threatType");
const aiStatusEl = document.getElementById("aiStatus");
const explanationEl = document.getElementById("explanation");
const reasonsEl = document.getElementById("reasons");
const xaiSummaryEl = document.getElementById("xaiSummary");
const xaiBarsEl = document.getElementById("xaiBars");
const intelSummaryEl = document.getElementById("intelSummary");
const analyzeBtn = document.getElementById("analyzeBtn");
const downloadAlertEl = document.getElementById("downloadAlert");
const downloadTextEl = document.getElementById("downloadText");
const protectionCardEl = document.getElementById("protectionCard");
const protectionTextEl = document.getElementById("protectionText");

function queryActiveTab() {
    return new Promise((resolve) => {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) =>
            resolve(tabs[0] || null),
        );
    });
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

function getScoreColor(score) {
    if (score >= 70) return "#fb7185";
    if (score >= 45) return "#f59e0b";
    return "#34d399";
}

function signalLabel(raw) {
    if (!raw) return "unknown_signal";
    return String(raw)
        .split("_")
        .map((token) => token.charAt(0).toUpperCase() + token.slice(1))
        .join(" ");
}

function setDial(score) {
    if (!riskDialEl) return;
    const clamped = Math.max(0, Math.min(100, Number(score || 0)));
    riskDialEl.style.setProperty("--dial-angle", `${(clamped / 100) * 360}deg`);
}

function animateScore(targetScore) {
    const target = Math.max(0, Math.min(100, Number(targetScore || 0)));
    const start = Number(riskScoreEl.dataset.score || 0);
    const durationMs = 420;
    const startTs = performance.now();

    function frame(now) {
        const progress = Math.min(1, (now - startTs) / durationMs);
        const value = Math.round(start + (target - start) * progress);
        riskScoreEl.dataset.score = String(value);
        riskScoreEl.textContent = String(value);
        setDial(value);
        if (progress < 1) {
            requestAnimationFrame(frame);
        }
    }

    requestAnimationFrame(frame);
}

function renderReasons(reasons) {
    reasonsEl.innerHTML = "";
    (reasons || []).slice(0, 3).forEach((reason) => {
        const li = document.createElement("li");
        li.textContent = reason;
        reasonsEl.appendChild(li);
    });
}

function renderDownloadAlert(alert) {
    if (!alert) {
        downloadAlertEl.classList.add("hidden");
        return;
    }

    downloadAlertEl.classList.remove("hidden");
    downloadTextEl.textContent = `${alert.filename || "A file"} scored ${alert.risk_score}/100. ${alert.reasons.join(" ")}`;
}

function renderXai(report) {
    const xai = report && report.xai ? report.xai : null;
    xaiBarsEl.innerHTML = "";

    if (!xai) {
        xaiSummaryEl.textContent =
            "Layered defense signals will appear after analysis.";
        intelSummaryEl.textContent = "";
        return;
    }

    const features = Array.isArray(xai.feature_contributions)
        ? xai.feature_contributions.slice(0, 6)
        : [];
    const topFeature = features[0] || null;

    xaiSummaryEl.textContent = topFeature
        ? `${signalLabel(topFeature.signal)}: ${topFeature.detail}`
        : "No strong feature contributions were returned.";

    features.forEach((feature) => {
        const impact = Number(feature.impact || 0);
        const width = Math.max(10, Math.min(100, Math.abs(impact) * 2.4));

        const row = document.createElement("div");
        row.className = "xai-row";

        const label = document.createElement("div");
        label.className = "xai-label";
        label.innerHTML = `<span>${signalLabel(feature.signal)}</span><span>${impact >= 0 ? "+" : ""}${impact}</span>`;

        const track = document.createElement("div");
        track.className = "xai-track";

        const bar = document.createElement("div");
        bar.className = `xai-bar ${impact >= 0 ? "positive" : "negative"}`;
        bar.style.width = `${width}%`;

        track.appendChild(bar);
        row.appendChild(label);
        row.appendChild(track);
        xaiBarsEl.appendChild(row);
    });

    const threatIntel = xai.threat_intel || {};
    const vt = threatIntel.virustotal || {};
    const op = threatIntel.openphish || {};
    const vtLine = vt.queried
        ? `VirusTotal: malicious ${vt.malicious || 0}, suspicious ${vt.suspicious || 0}.`
        : "VirusTotal: not configured.";
    const opLine = op.queried
        ? `OpenPhish: ${op.matched ? "matched known phishing feed" : "no feed match"}.`
        : "OpenPhish: disabled.";
    intelSummaryEl.textContent = `${vtLine} ${opLine}`;
}

function renderProtectionEvent(event) {
    if (!event) {
        protectionCardEl.classList.add("hidden");
        return;
    }

    protectionCardEl.classList.remove("hidden");
    const scoreText =
        typeof event.risk_score === "number"
            ? `${event.risk_score}/100`
            : "unknown";
    protectionTextEl.textContent = `I blocked a ${event.threat_type || "risky action"} (risk ${scoreText}) to keep you safe. ${event.explanation || ""}`;
}

function renderReport(report) {
    if (!report) {
        riskScoreEl.textContent = "--";
        riskScoreEl.dataset.score = "0";
        setDial(0);
        threatTypeEl.textContent = "No data available";
        aiStatusEl.textContent = "AI status: unavailable";
        explanationEl.textContent =
            "Unable to analyze this tab. Open an HTTP/HTTPS page and try again.";
        renderReasons([]);
        renderXai(null);
        return;
    }

    const score = Number(report.risk_score || 0);
    animateScore(score);
    riskScoreEl.style.color = getScoreColor(score);
    threatTypeEl.textContent = report.threat_type || "Unknown";
    const aiUsed = Boolean(report.llm_used);
    aiStatusEl.textContent = aiUsed
        ? "AI status: generated by LLM"
        : `AI status: fallback (${report.llm_error || "unknown"})`;
    aiStatusEl.style.color = aiUsed ? "#34d399" : "#f59e0b";
    const trustedLine = report.is_trusted_domain
        ? "This site matches RelyX trusted-domain checks."
        : "This site is not in RelyX trusted-domain list.";
    explanationEl.textContent = `${report.explanation || "No explanation provided."} ${trustedLine}`;
    renderReasons(report.reasons || []);
    renderXai(report);
}

async function analyzeCurrentTab(triggerAnalyze = false) {
    const activeTab = await queryActiveTab();
    if (!activeTab || !activeTab.id || !activeTab.url) {
        renderReport(null);
        renderProtectionEvent(null);
        return;
    }

    const messageType = triggerAnalyze ? "TRIGGER_ANALYZE" : "GET_TAB_REPORT";
    const result = await runtimeMessage({
        type: messageType,
        tabId: activeTab.id,
        url: activeTab.url,
    });

    renderReport(result ? result.report : null);
    renderProtectionEvent(result ? result.lastProtectionEvent : null);

    if (!triggerAnalyze) {
        renderDownloadAlert(result ? result.lastDownloadAlert : null);
    } else {
        chrome.storage.local.get(["lastDownloadAlert"], (items) => {
            renderDownloadAlert(items.lastDownloadAlert || null);
        });
        chrome.storage.local.get(["lastProtectionEvent"], (items) => {
            renderProtectionEvent(items.lastProtectionEvent || null);
        });
    }
}

analyzeBtn.addEventListener("click", () => analyzeCurrentTab(true));
analyzeCurrentTab(false);
