class PhishingDetector {
  constructor() {
    // Auto-detect API URL based on environment
    if (
      window.location.hostname === "localhost" ||
      window.location.hostname === "127.0.0.1"
    ) {
      this.apiUrl = "http://localhost:3000/api/analyze";
    } else {
      this.apiUrl = "/api/analyze"; // Use relative URL for production
    }
    this.initializeEventListeners();
  }

  initializeEventListeners() {
    const analyzeBtn = document.getElementById("analyzeBtn");
    const urlInput = document.getElementById("urlInput");
    if (!analyzeBtn || !urlInput) {
      console.error("Required DOM elements missing: analyzeBtn or urlInput");
      return;
    }

    analyzeBtn.addEventListener("click", () => this.analyzeUrl());
    urlInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter") {
        this.analyzeUrl();
      }
    });
  }

  async analyzeUrl() {
    const urlInput = document.getElementById("urlInput");
    if (!urlInput) return;
    let url = urlInput.value.trim();

    // Auto-prepend https:// if protocol is missing
    if (url && !/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(url)) {
      url = "https://" + url;
    }

    // remove any existing error messages
    document.querySelectorAll(".error-message").forEach((el) => el.remove());

    if (!url) {
      this.showError("Please enter a URL to analyze");
      return;
    }

    if (!this.isValidUrl(url)) {
      this.showError("Please enter a valid URL");
      return;
    }

    this.showLoading();
    this.hideResult();

    try {
      // try POST first
      let response = await fetch(this.apiUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
        mode: "cors",
      });

      if (response.status === 405) {
        console.warn("POST not allowed, retrying with GET");
        // try GET with url as query param
        const getUrl = `${this.apiUrl}?url=${encodeURIComponent(url)}`;
        response = await fetch(getUrl, { method: "GET", mode: "cors" });
      }

      const text = await response.text();
      if (!response.ok)
        throw new Error(
          `API ${response.status}: ${text || response.statusText}`
        );
      const result = JSON.parse(text);
      // ...use result as before...
      // ensure minimal fields exist
      result.url = result.url || url;
      result.isPhishing = !!result.isPhishing;
      result.confidence = Number.isFinite(result.confidence)
        ? result.confidence
        : 0;
      result.features = Array.isArray(result.features) ? result.features : [];
      result.recommendations = Array.isArray(result.recommendations)
        ? result.recommendations
        : [];

      this.displayResult(result);
    } catch (error) {
      console.error("Error analyzing URL:", error);
      this.showError(
        error.message || "Failed to analyze URL. Please try again."
      );
    } finally {
      this.hideLoading();
    }
  }

  isValidUrl(string) {
    try {
      // require protocol to avoid ambiguous inputs
      const u = new URL(string);
      return u.protocol === "http:" || u.protocol === "https:";
    } catch (_) {
      return false;
    }
  }

  showLoading() {
    const loading = document.getElementById("loadingSection");
    if (loading) loading.classList.remove("hidden");
    const btn = document.getElementById("analyzeBtn");
    if (btn) btn.disabled = true;
  }

  hideLoading() {
    const loading = document.getElementById("loadingSection");
    if (loading) loading.classList.add("hidden");
    const btn = document.getElementById("analyzeBtn");
    if (btn) btn.disabled = false;
  }

  showResult() {
    const el = document.getElementById("resultSection");
    if (el) el.classList.remove("hidden");
  }

  hideResult() {
    const el = document.getElementById("resultSection");
    if (el) el.classList.add("hidden");
  }

  displayResult(result) {
    // guard checks for elements
    const analyzedUrlEl = document.getElementById("analyzedUrl");
    if (analyzedUrlEl) analyzedUrlEl.textContent = result.url || "";

    const statusIndicator = document.getElementById("statusIndicator");
    const statusIcon = document.getElementById("statusIcon");
    const statusText = document.getElementById("statusText");

    if (statusIndicator) statusIndicator.className = "status-indicator";
    const confidence = Number(result.confidence) || 0;

    if (result.isPhishing) {
      if (statusIndicator) statusIndicator.classList.add("dangerous");
      if (statusIcon) statusIcon.className = "fas fa-exclamation-triangle";
      if (statusText) statusText.textContent = "DANGEROUS - Phishing Detected";
    } else if (confidence > 70) {
      if (statusIndicator) statusIndicator.classList.add("safe");
      if (statusIcon) statusIcon.className = "fas fa-check-circle";
      if (statusText) statusText.textContent = "SAFE - No Threats Detected";
    } else {
      if (statusIndicator) statusIndicator.classList.add("suspicious");
      if (statusIcon) statusIcon.className = "fas fa-question-circle";
      if (statusText) statusText.textContent = "SUSPICIOUS - Exercise Caution";
    }

    const scoreFill = document.getElementById("scoreFill");
    const scoreValue = document.getElementById("scoreValue");
    if (scoreFill) scoreFill.style.width = `${confidence}%`;
    if (scoreValue) scoreValue.textContent = `${confidence}%`;

    // Show analysis source if available
    if (result.analysisSource) {
      const sourceInfo = document.createElement("div");
      sourceInfo.className = "analysis-source";
      sourceInfo.style.cssText = `
        background: #e3f2fd;
        color: #1976d2;
        padding: 8px 12px;
        border-radius: 6px;
        margin: 10px 0;
        font-size: 0.9rem;
        border-left: 3px solid #2196f3;
      `;
      sourceInfo.innerHTML = `<i class="fas fa-database"></i> Analysis Source: ${result.analysisSource}`;

      const resultDetails = document.querySelector(".result-details");
      if (resultDetails) {
        resultDetails.insertBefore(sourceInfo, resultDetails.firstChild);
      }
    }

    this.updateFeatures(result.features || []);
    this.updateRecommendations(result.recommendations || []);

    this.showResult();
  }

  updateFeatures(features) {
    const featuresList = document.getElementById("featuresList");
    if (!featuresList) return;
    featuresList.innerHTML = "";
    if (!features.length) {
      featuresList.innerHTML =
        '<div class="feature-item">No feature details</div>';
      return;
    }

    features.forEach((feature) => {
      const featureItem = document.createElement("div");
      featureItem.className = "feature-item";

      const icon =
        feature.risk === "high"
          ? "fas fa-exclamation-triangle"
          : feature.risk === "medium"
          ? "fas fa-exclamation-circle"
          : "fas fa-check-circle";

      featureItem.innerHTML = `
                <i class="${icon}"></i>
                <span><strong>${feature.name || "Feature"}:</strong> ${
        feature.description || ""
      }</span>
            `;

      featuresList.appendChild(featureItem);
    });
  }

  updateRecommendations(recommendations) {
    const recommendationsList = document.getElementById("recommendationsList");
    if (!recommendationsList) return;
    recommendationsList.innerHTML = "";
    if (!recommendations.length) {
      recommendationsList.innerHTML =
        '<div class="recommendation-item">No recommendations</div>';
      return;
    }

    recommendations.forEach((recommendation) => {
      const recommendationItem = document.createElement("div");
      recommendationItem.className = "recommendation-item";
      recommendationItem.innerHTML = `
                <i class="fas fa-lightbulb"></i>
                <span>${recommendation}</span>
            `;
      recommendationsList.appendChild(recommendationItem);
    });
  }

  showError(message) {
    // prevent duplicate errors
    document.querySelectorAll(".error-message").forEach((el) => el.remove());

    const errorDiv = document.createElement("div");
    errorDiv.className = "error-message";
    errorDiv.style.cssText = `
            background: #f8d7da;
            color: #721c24;
            padding: 12px;
            border-radius: 8px;
            margin: 12px 0;
            border-left: 4px solid #dc3545;
        `;
    errorDiv.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${message}`;

    const inputSection =
      document.querySelector(".input-section") || document.body;
    inputSection.appendChild(errorDiv);

    setTimeout(() => {
      if (errorDiv.parentNode) errorDiv.parentNode.removeChild(errorDiv);
    }, 5000);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  new PhishingDetector();

  // example placeholders
  const urlInput = document.getElementById("urlInput");
  if (!urlInput) return;
  const examples = [
    "https://www.google.com",
    "https://www.github.com",
    "https://suspicious-site.com/login",
    "https://paypal-security-alert.com",
  ];
  let exampleIndex = 0;
  setInterval(() => {
    urlInput.placeholder = `Enter URL to analyze (e.g., ${examples[exampleIndex]})`;
    exampleIndex = (exampleIndex + 1) % examples.length;
  }, 3000);
});

// Remove or comment out any code like:
// window.location.href = "login.html";
// document.getElementById('loginBtn').addEventListener(...);

// Modify analyzeUrl to include Authorization header when present
async function analyzeUrl(url) {
  const payload = { url };
  const token = localStorage.getItem("phg_token");
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = "Bearer " + token;
  const res = await fetch("/api/analyze", {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });
  return res.json();
}
