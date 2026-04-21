import { analyzeContent } from "/shared/detectionEngine.js";

function bindResult(prefix) {
  return {
    card: document.getElementById(`${prefix}Card`),
    score: document.getElementById(`${prefix}Score`),
    dial: document.getElementById(`${prefix}Dial`),
    classification: document.getElementById(`${prefix}Classification`),
    summary: document.getElementById(`${prefix}Summary`),
    meta: document.getElementById(`${prefix}Meta`),
    reasons: document.getElementById(`${prefix}Reasons`),
    highlights: document.getElementById(`${prefix}Highlights`),
    recommendations: document.getElementById(`${prefix}Recommendations`),
  };
}

const results = {
  messageLocal: bindResult("messageLocal"),
  messageServer: bindResult("messageServer"),
  screenLocal: bindResult("screenLocal"),
  screenServer: bindResult("screenServer"),
};

const messageInput = document.getElementById("messageInput");
const sourceSelect = document.getElementById("sourceSelect");
const processConsent = document.getElementById("processConsent");
const storeLogConsent = document.getElementById("storeLogConsent");
const snippetConsent = document.getElementById("snippetConsent");
const serverAnalyzeButton = document.getElementById("serverAnalyzeButton");
const messageStatus = document.getElementById("messageStatus");

const screenInput = document.getElementById("screenInput");
const screenConsent = document.getElementById("screenConsent");
const captureScreenButton = document.getElementById("captureScreenButton");
const screenServerAnalyzeButton = document.getElementById("screenServerAnalyzeButton");
const screenStatus = document.getElementById("screenStatus");

function debounce(callback, delay = 180) {
  let timeoutId = null;
  return (...args) => {
    window.clearTimeout(timeoutId);
    timeoutId = window.setTimeout(() => callback(...args), delay);
  };
}

function renderList(element, items, formatter, emptyText) {
  element.innerHTML = "";

  if (!items || items.length === 0) {
    if (!emptyText) {
      return;
    }

    const item = document.createElement("li");
    item.textContent = emptyText;
    element.appendChild(item);
    return;
  }

  items.forEach((entry) => {
    const item = document.createElement("li");
    item.textContent = formatter(entry);
    element.appendChild(item);
  });
}

function applyTone(card, classification) {
  card.classList.remove("safe", "suspicious", "scam");

  if (classification === "SAFE") {
    card.classList.add("safe");
  } else if (classification === "SUSPICIOUS") {
    card.classList.add("suspicious");
  } else if (classification === "SCAM") {
    card.classList.add("scam");
  }
}

function renderEmpty(target, title, summary, meta) {
  target.score.textContent = "0";
  target.dial.style.setProperty("--angle", "0deg");
  target.classification.textContent = title;
  target.summary.textContent = summary;
  target.meta.textContent = meta;
  applyTone(target.card, "");
  renderList(target.reasons, [], (entry) => entry, "No signals yet.");
  renderList(target.highlights, [], (entry) => entry, "No highlights yet.");
  renderList(target.recommendations, [], (entry) => entry, "No recommendations yet.");
}

function renderAnalysis(target, analysis, originLabel) {
  const angle = `${Math.round((analysis.riskScore / 100) * 360)}deg`;
  target.score.textContent = String(analysis.riskScore);
  target.dial.style.setProperty("--angle", angle);
  target.classification.textContent = analysis.classification;
  target.summary.textContent = analysis.summary;
  target.meta.textContent = `${originLabel} • ML ${analysis.factors.machineLearning.riskScore}/100 • ${analysis.stats.wordCount} words`;
  applyTone(target.card, analysis.classification);

  renderList(target.reasons, analysis.explanation, (entry) => entry, "No explanation available.");
  renderList(
    target.highlights,
    analysis.highlights,
    (entry) => `${entry.type}: ${entry.label}`,
    "No highlighted patterns.",
  );
  renderList(
    target.recommendations,
    analysis.recommendations,
    (entry) => entry,
    "No recommendations available.",
  );
}

function syncConsentControls() {
  snippetConsent.disabled = !storeLogConsent.checked;
  if (!storeLogConsent.checked) {
    snippetConsent.checked = false;
  }
}

function analyzeMessageLocally() {
  if (!processConsent.checked) {
    renderEmpty(
      results.messageLocal,
      "Awaiting Consent",
      "AI Shield will not inspect content until you explicitly consent to analysis.",
      "On-device only",
    );
    messageStatus.textContent = "Turn on consent to start local real-time analysis.";
    return;
  }

  const content = messageInput.value.trim();
  if (!content) {
    renderEmpty(
      results.messageLocal,
      "Ready",
      "Paste a message to start local scam analysis.",
      "On-device only",
    );
    messageStatus.textContent = "Paste suspicious content to inspect it locally.";
    return;
  }

  const analysis = analyzeContent({
    content,
    source: sourceSelect.value,
  });

  renderAnalysis(results.messageLocal, analysis, "Browser local analysis");
  messageStatus.textContent = "Local protection is active. Nothing has been sent to the server.";
}

function analyzeScreenLocally() {
  if (!screenConsent.checked) {
    renderEmpty(
      results.screenLocal,
      "Awaiting Consent",
      "Screen analysis stays disabled until you allow screen-text inspection.",
      "Manual paste or browser OCR",
    );
    screenStatus.textContent = "Screen analysis stays disabled until you grant screen-scan consent.";
    return;
  }

  const content = screenInput.value.trim();
  if (!content) {
    renderEmpty(
      results.screenLocal,
      "Ready",
      "Paste visible screen text or capture it locally to inspect it.",
      "Manual paste or browser OCR",
    );
    screenStatus.textContent = "Visible screen text remains local unless you explicitly send it.";
    return;
  }

  const analysis = analyzeContent({
    content,
    source: "screen",
  });

  renderAnalysis(results.screenLocal, analysis, "Browser local screen analysis");
  screenStatus.textContent = "Local screen protection is active. No visible text has been transmitted.";
}

async function sendForVerification(endpoint, body, statusElement, targetResult, button, successLabel) {
  button.disabled = true;
  statusElement.textContent = "Protected verification is running…";

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Verification failed.");
    }

    renderAnalysis(targetResult, payload.analysis, successLabel);
    if (payload.logReceipt?.id) {
      statusElement.textContent = `Verified. Minimal encrypted log stored as ${payload.logReceipt.id}.`;
      return;
    }

    statusElement.textContent = "Verified. No content was stored because logging consent was not enabled.";
  } catch (error) {
    statusElement.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function verifyMessageWithApi() {
  if (!processConsent.checked) {
    messageStatus.textContent = "Consent is required before server-side message analysis.";
    return;
  }

  const content = messageInput.value.trim();
  if (!content) {
    messageStatus.textContent = "Paste a message before requesting protected API verification.";
    return;
  }

  await sendForVerification(
    "/api/analyze",
    {
      content,
      source: sourceSelect.value,
      consent: {
        process: true,
        storeLog: storeLogConsent.checked,
        persistContentSnippet: snippetConsent.checked,
      },
      metadata: {
        sessionId: crypto.randomUUID(),
      },
    },
    messageStatus,
    results.messageServer,
    serverAnalyzeButton,
    "Protected API verification",
  );
}

async function verifyScreenWithApi() {
  if (!screenConsent.checked) {
    screenStatus.textContent = "Screen-scan consent is required before protected verification.";
    return;
  }

  const visibleText = screenInput.value.trim();
  if (!visibleText) {
    screenStatus.textContent = "Paste or capture visible screen text before verification.";
    return;
  }

  await sendForVerification(
    "/api/analyze/screen",
    {
      visibleText,
      source: "screen",
      consent: {
        process: true,
        screenScan: true,
        storeLog: storeLogConsent.checked,
        persistContentSnippet: snippetConsent.checked,
      },
      metadata: {
        sessionId: crypto.randomUUID(),
      },
    },
    screenStatus,
    results.screenServer,
    screenServerAnalyzeButton,
    "Protected API screen verification",
  );
}

async function captureScreenTextLocally() {
  if (!screenConsent.checked) {
    screenStatus.textContent = "Enable screen-scan consent before attempting local capture.";
    return;
  }

  if (!navigator.mediaDevices?.getDisplayMedia) {
    screenStatus.textContent = "Screen capture is not supported in this browser. Paste visible text manually instead.";
    return;
  }

  if (typeof window.TextDetector !== "function") {
    screenStatus.textContent = "Browser OCR is not available here. Paste visible screen text manually for local analysis.";
    return;
  }

  captureScreenButton.disabled = true;
  screenStatus.textContent = "Waiting for screen permission…";

  let stream;
  try {
    stream = await navigator.mediaDevices.getDisplayMedia({
      video: true,
      audio: false,
    });

    const video = document.createElement("video");
    video.srcObject = stream;
    video.muted = true;
    await video.play();

    await new Promise((resolve) => {
      window.setTimeout(resolve, 250);
    });

    const canvas = document.createElement("canvas");
    canvas.width = video.videoWidth || 1280;
    canvas.height = video.videoHeight || 720;
    const context = canvas.getContext("2d");
    context.drawImage(video, 0, 0, canvas.width, canvas.height);

    const bitmap = await createImageBitmap(canvas);
    const detector = new window.TextDetector();
    const blocks = await detector.detect(bitmap);
    const extracted = blocks.map((block) => block.rawValue).filter(Boolean).join("\n");

    if (!extracted.trim()) {
      screenStatus.textContent = "No readable text was detected. Paste visible text manually if needed.";
      return;
    }

    screenInput.value = extracted;
    analyzeScreenLocally();
    screenStatus.textContent = `Captured ${blocks.length} text blocks locally. Review before sending anything to the API.`;
  } catch (error) {
    screenStatus.textContent = `Screen capture failed: ${error.message}`;
  } finally {
    stream?.getTracks().forEach((track) => track.stop());
    captureScreenButton.disabled = false;
  }
}

const debouncedMessageAnalysis = debounce(analyzeMessageLocally, 180);
const debouncedScreenAnalysis = debounce(analyzeScreenLocally, 180);

messageInput.addEventListener("input", debouncedMessageAnalysis);
sourceSelect.addEventListener("change", analyzeMessageLocally);
processConsent.addEventListener("change", analyzeMessageLocally);
storeLogConsent.addEventListener("change", syncConsentControls);
serverAnalyzeButton.addEventListener("click", verifyMessageWithApi);

screenInput.addEventListener("input", debouncedScreenAnalysis);
screenConsent.addEventListener("change", analyzeScreenLocally);
captureScreenButton.addEventListener("click", captureScreenTextLocally);
screenServerAnalyzeButton.addEventListener("click", verifyScreenWithApi);

syncConsentControls();
renderEmpty(
  results.messageLocal,
  "Awaiting Consent",
  "AI Shield will analyze in-browser once message-analysis consent is enabled.",
  "On-device only",
);
renderEmpty(
  results.messageServer,
  "Not Verified",
  "Server verification will stay idle until you explicitly submit this content.",
  "No data transmitted yet",
);
renderEmpty(
  results.screenLocal,
  "Awaiting Consent",
  "Visible text stays on-device unless you explicitly send it to the API.",
  "Manual paste or browser OCR",
);
renderEmpty(
  results.screenServer,
  "Not Verified",
  "Server-side screen verification is available only when screen consent is active.",
  "Consent-gated",
);