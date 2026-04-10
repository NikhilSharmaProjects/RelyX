const riskScoreEl = document.getElementById("riskScore");
const riskDialEl = document.getElementById("riskDial");
const threatTypeEl = document.getElementById("threatType");
const severityTagEl = document.getElementById("severityTag");
const confidenceLineEl = document.getElementById("confidenceLine");
const liveStateEl = document.getElementById("liveState");
const aiStatusEl = document.getElementById("aiStatus");
const explanationEl = document.getElementById("explanation");
const reasonsEl = document.getElementById("reasons");
const intelGridEl = document.getElementById("intelGrid");
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
    if (score >= 70) return "#ff7a93";
    if (score >= 45) return "#f7a829";
    return "#42dfb2";
}

function setDial(score) {
    if (!riskDialEl) return;
    const clamped = Math.max(0, Math.min(100, Number(score || 0)));
    riskDialEl.style.setProperty("--dial-angle", `${(clamped / 100) * 360}deg`);
    riskDialEl.classList.toggle("high", clamped >= 70);
}

function animateScore(targetScore) {
    const target = Math.max(0, Math.min(100, Number(targetScore || 0)));
    const start = Number(riskScoreEl.dataset.score || 0);
    const durationMs = 460;
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

function setSeverityTag(severity, score) {
    const normalized = String(severity || "low").toLowerCase();
    severityTagEl.textContent = normalized.toUpperCase();
    severityTagEl.classList.remove("low", "medium", "high", "critical");
    severityTagEl.classList.add(normalized);

    if (score >= 70) {
        liveStateEl.textContent = "Shield: Blocking";
        liveStateEl.style.borderColor = "rgba(255, 107, 134, 0.55)";
        liveStateEl.style.background = "rgba(255, 107, 134, 0.2)";
        liveStateEl.style.color = "#ffd4de";
    } else {
        liveStateEl.textContent = "Shield: Monitoring";
        liveStateEl.style.borderColor = "rgba(49, 214, 165, 0.45)";
        liveStateEl.style.background = "rgba(49, 214, 165, 0.2)";
        liveStateEl.style.color = "#b7ffe7";
    }
}

function renderReasons(reasons) {
    reasonsEl.innerHTML = "";
    (reasons || []).slice(0, 3).forEach((reason) => {
        const li = document.createElement("li");
        li.textContent = reason;
        reasonsEl.appendChild(li);
    });
}

function renderIntelItem(label, statusText, className) {
    const item = document.createElement("div");
    item.className = `intel-item ${className}`;
    item.innerHTML = `<span class="label">${label}</span><span class="status">${statusText}</span>`;
    return item;
}

function renderThreatIntel(report) {
    intelGridEl.innerHTML = "";
    const checks = (report && report.api_checks) || {};
    const gsb = checks.google_safe_browsing || {};
    const vt = checks.virustotal || {};
    const phishtank = checks.phishtank || {};
    const whois = checks.whois || {};
    const cert = checks.certificate || {};

    const gsbStatus = gsb.queried
        ? gsb.matched
            ? "Flagged"
            : "No match"
        : "Unavailable";
    intelGridEl.appendChild(
        renderIntelItem(
            "Google Safe Browsing",
            gsbStatus,
            gsb.matched ? "bad" : gsb.queried ? "good" : "warn",
        ),
    );

    const vtStatus = vt.queried
        ? `Mal ${vt.malicious || 0} / Susp ${vt.suspicious || 0}`
        : "Unavailable";
    const vtClass = vt.queried
        ? Number(vt.malicious || 0) > 0 || Number(vt.suspicious || 0) > 0
            ? "bad"
            : "good"
        : "warn";
    intelGridEl.appendChild(renderIntelItem("VirusTotal", vtStatus, vtClass));

    const ptStatus = phishtank.queried
        ? phishtank.matched
            ? "Phish match"
            : "No match"
        : "Unavailable";
    intelGridEl.appendChild(
        renderIntelItem(
            "PhishTank",
            ptStatus,
            phishtank.matched ? "bad" : phishtank.queried ? "good" : "warn",
        ),
    );

    const whoisStatus = whois.queried
        ? whois.source
            ? `Checked (${whois.source})`
            : "Checked"
        : "Unavailable";
    intelGridEl.appendChild(
        renderIntelItem(
            "WHOIS Age",
            whoisStatus,
            whois.queried ? "good" : "warn",
        ),
    );

    const certStatus = cert.queried
        ? cert.valid === false
            ? "Invalid"
            : typeof cert.days_left === "number"
              ? `${cert.days_left} days left`
              : "Valid"
        : "Unavailable";
    const certClass =
        cert.valid === false ? "bad" : cert.queried ? "good" : "warn";
    intelGridEl.appendChild(
        renderIntelItem("TLS Certificate", certStatus, certClass),
    );
}

function renderDownloadAlert(alert) {
    if (!alert) {
        downloadAlertEl.classList.add("hidden");
        return;
    }

    downloadAlertEl.classList.remove("hidden");
    downloadTextEl.textContent = `${alert.filename || "A file"} scored ${alert.risk_score}/100 (${alert.severity || "unknown"}). ${(
        alert.reasons || []
    )
        .slice(0, 2)
        .join(" ")}`;
}

function renderProtectionEvent(event) {
    if (!event) {
        protectionCardEl.classList.add("hidden");
        return;
    }

    protectionCardEl.classList.remove("hidden");
    protectionTextEl.textContent = `RelyX blocked ${
        event.action_kind ? `${event.action_kind} action` : "a high-risk page"
    } (${event.risk_score || "--"}/100). ${event.explanation || "Threat stopped."}`;
}

function renderReport(report) {
    if (!report) {
        riskScoreEl.textContent = "--";
        riskScoreEl.dataset.score = "0";
        setDial(0);
        threatTypeEl.textContent = "No data available";
        confidenceLineEl.textContent = "Confidence: --";
        aiStatusEl.textContent = "AI status: unavailable";
        explanationEl.textContent =
            "Unable to analyze this tab. Open an HTTP/HTTPS page and try again.";
        renderReasons([]);
        renderThreatIntel(null);
        setSeverityTag("low", 0);
        return;
    }

    const score = Number(report.risk_score || 0);
    animateScore(score);
    riskScoreEl.style.color = getScoreColor(score);

    threatTypeEl.textContent = report.threat_type || "Unknown";
    confidenceLineEl.textContent = `Confidence: ${String(
        report.confidence_level || "low",
    ).toUpperCase()}`;
    setSeverityTag(report.severity || "low", score);

    const aiUsed = Boolean(report.llm_used);
    aiStatusEl.textContent = aiUsed
        ? `AI source: ${String(report.llm_provider || "ai").toUpperCase()} ${String(
              report.llm_model || "structured explanation",
          )}`
        : "AI status: unavailable";
    aiStatusEl.style.color = aiUsed ? "#8af8d5" : "#ffdca3";

    explanationEl.textContent =
        report.explanation ||
        "RelyX analyzed this page and generated a security decision.";

    renderReasons(report.reasons || []);
    renderThreatIntel(report);
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
    renderDownloadAlert(result ? result.lastDownloadAlert : null);
}

analyzeBtn.addEventListener("click", () => analyzeCurrentTab(true));
analyzeCurrentTab(false);
