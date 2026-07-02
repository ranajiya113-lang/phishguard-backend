// =======================
// ELEMENTS
// =======================

const urlScanner = document.getElementById("urlScanner");
const resultContainer = document.getElementById("resultContainer");
const urlInput = document.getElementById("urlInput");
const statusText = document.getElementById("statusText");
const scannedText = document.getElementById("scannedText");
const scoreValue = document.getElementById("scoreValue");
const riskList = document.getElementById("riskList");
const positiveList = document.getElementById("positiveList");
const statusIcon = document.querySelector(".status-icon i");
const summaryCard = document.querySelector(".summary-card");
const scoreCircle = document.querySelector(".score-circle");

// =======================
// BACKEND URL
// =======================

const BACKEND_URL = "http://127.0.0.1:8000";

// =======================
// URL SCAN
// =======================

document.getElementById("urlScanBtn").addEventListener("click", async () => {
    const urlText = urlInput.value.trim();
    if (!urlText) {
        alert("Please enter a URL before scanning");
        return;
    }
    showLoading();
    try {
        const response = await fetch(`${BACKEND_URL}/detect`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: urlText })
        });
        if (!response.ok) throw new Error(`Server error: ${response.status}`);
        const data = await response.json();
        showResult(data, urlText, "url");
    } catch (err) {
        showError(err.message);
    }
});

// =======================
// SHOW RESULT
// =======================

function showResult(data, text, type) {
    resultContainer.style.display = "block";

    const score = data.risk_score || 0;
    const riskLevel = data.risk_level || "safe";
    const flags = data.details?.heuristics?.flags || [];
    const mlScore = data.details?.ml_model?.score || 0;

    scoreValue.innerText = Math.round(score * 10);

    if (riskLevel === "dangerous") {
        statusText.innerText = "⚠️ Phishing Detected!";
    } else if (riskLevel === "suspicious") {
        statusText.innerText = "🔍 Suspicious URL";
    } else {
        statusText.innerText = "✅ Looks Safe";
    }

    scannedText.innerText = type === "email" ? "Email content analyzed" : text;
    applyRiskStyling(riskLevel === "dangerous", riskLevel === "suspicious");

    // Risk Factors
    riskList.innerHTML = "";
    flags.forEach(flag => { riskList.innerHTML += `<li>⚠️ ${flag}</li>`; });
    const urlLower = text.toLowerCase();
    if (!urlLower.startsWith("https")) riskList.innerHTML += `<li>⚠️ Not using HTTPS</li>`;
    if (urlLower.includes("@"))        riskList.innerHTML += `<li>⚠️ Contains @ symbol in URL</li>`;
    if (!riskList.innerHTML)           riskList.innerHTML  = "<li>✅ No risk factors detected</li>";

    // Positive Signals
    positiveList.innerHTML = "";
    if (urlLower.startsWith("https"))                              positiveList.innerHTML += `<li>✅ Uses HTTPS encryption</li>`;
    if (!data.details?.heuristics?.features?.is_shortened)         positiveList.innerHTML += `<li>✅ No URL shortener detected</li>`;
    if (!data.details?.heuristics?.features?.has_ip_address)       positiveList.innerHTML += `<li>✅ No IP address used as domain</li>`;
    if (mlScore < 0.3)                                             positiveList.innerHTML += `<li>✅ ML model: low phishing probability</li>`;
    if (riskLevel === "safe")                                      positiveList.innerHTML += `<li>✅ Trusted URL structure</li>`;

    // Threat Intel
    const intel = data.details?.threat_intel;
    if (intel?.available) {
        if (intel.flagged_by_virustotal)
            riskList.innerHTML += `<li>🔴 Flagged by VirusTotal</li>`;
        else if (intel.virustotal && !intel.virustotal.error)
            positiveList.innerHTML += `<li>✅ Clean on VirusTotal (${intel.virustotal.detection_ratio})</li>`;

        if (intel.flagged_by_google)
            riskList.innerHTML += `<li>🔴 Flagged by Google Safe Browsing</li>`;
        else if (intel.google_safe_browsing && !intel.google_safe_browsing.error)
            positiveList.innerHTML += `<li>✅ Clean on Google Safe Browsing</li>`;
    }
}

// =======================
// APPLY COLOR STYLING
// =======================

function applyRiskStyling(isDangerous, isSuspicious) {
    summaryCard.style.borderColor = "";
    statusIcon.className = "";
    scoreCircle.style.borderColor = "";

    if (isDangerous) {
        summaryCard.style.borderColor = "#ef4444";
        scoreCircle.style.borderColor = "#ef4444";
        statusIcon.className = "fa-solid fa-triangle-exclamation";
        statusIcon.parentElement.style.background = "#ef4444";
    } else if (isSuspicious) {
        summaryCard.style.borderColor = "#f59e0b";
        scoreCircle.style.borderColor = "#f59e0b";
        statusIcon.className = "fa-solid fa-circle-exclamation";
        statusIcon.parentElement.style.background = "#f59e0b";
    } else {
        summaryCard.style.borderColor = "#22c55e";
        scoreCircle.style.borderColor = "#22c55e";
        statusIcon.className = "fa-solid fa-check";
        statusIcon.parentElement.style.background = "linear-gradient(135deg, #22c55e, #16a34a)";
    }
}

// =======================
// SHOW ERROR
// =======================

function showError(message) {
    resultContainer.style.display = "block";
    statusText.innerText = "❌ Connection Error";
    scannedText.innerText = "Could not reach the backend server";
    scoreValue.innerText = "-";
    riskList.innerHTML = `<li>⚠️ ${message}</li><li>⚠️ Make sure the backend is running on port 8000</li>`;
    positiveList.innerHTML = "<li>Run: python -m uvicorn app.main:app --port 8000</li>";
    summaryCard.style.borderColor = "#ef4444";
}

// =======================
// LOADING STATE
// =======================

function showLoading() {
    resultContainer.style.display = "block";
    statusText.innerText = "Scanning...";
    scannedText.innerText = "Please wait...";
    scoreValue.innerText = "-";
    riskList.innerHTML = "<li>⏳ Analyzing URL with AI...</li>";
    positiveList.innerHTML = "<li>⏳ Checking threat databases...</li>";
    summaryCard.style.borderColor = "#06b6d4";
    statusIcon.className = "fa-solid fa-spinner fa-spin";
    statusIcon.parentElement.style.background = "#06b6d4";
}

// =======================
// PAGE LOAD RESET
// =======================

window.addEventListener("load", () => {
    urlInput.value = "";
    resultContainer.style.display = "none";
    statusText.innerText = "";
    scannedText.innerText = "";
    scoreValue.innerText = "0";
    riskList.innerHTML = "";
    positiveList.innerHTML = "";
});