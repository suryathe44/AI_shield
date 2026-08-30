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
const feedbackForm = document.getElementById("feedbackForm");
const feedbackCategory = document.getElementById("feedbackCategory");
const feedbackComment = document.getElementById("feedbackComment");
const feedbackCharacterCount = document.getElementById("feedbackCharacterCount");
const feedbackSubmitButton = document.getElementById("feedbackSubmitButton");
const feedbackStatus = document.getElementById("feedbackStatus");

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
  target.card.classList.add("is-empty");
  renderList(target.reasons, [], (entry) => entry, "No detected reasons yet.");
  renderList(target.highlights, [], (entry) => entry, "No suspicious patterns yet.");
  renderList(target.recommendations, [], (entry) => entry, "Recommendations will appear with a verdict.");
}

function renderAnalysis(target, analysis, originLabel) {
  const angle = `${Math.round((analysis.riskScore / 100) * 360)}deg`;
  target.score.textContent = String(analysis.riskScore);
  target.dial.style.setProperty("--angle", angle);
  target.classification.textContent = analysis.classification;
  target.summary.textContent = analysis.summary;
  const reputation = analysis.factors.internetReputation;
  const internetStatus = reputation
    ? reputation.checked
      ? ` | Internet URL check: ${reputation.matches.length ? "THREAT FOUND" : "no known threat"}`
      : reputation.unavailable
        ? " | Internet URL check unavailable"
        : reputation.configured
          ? " | No URL to check"
          : " | Internet URL check not configured"
    : "";
  target.meta.textContent = `${originLabel} | ML ${analysis.factors.machineLearning.riskScore}/100 | Confidence ${analysis.confidence?.level ?? "N/A"} | ${analysis.stats.wordCount} words${internetStatus}`;
  target.card.classList.remove("is-empty");
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
      "Ready when you are",
      "Allow analysis and paste a message to see a local risk assessment.",
      "Runs in this browser",
    );
    messageStatus.textContent = "Allow analysis, then paste a message for a local check.";
    return;
  }

  const content = messageInput.value.trim();
  if (!content) {
    renderEmpty(
      results.messageLocal,
      "Ready",
      "Paste a message to start local scam analysis.",
      "Runs in this browser",
    );
    messageStatus.textContent = "Paste suspicious content to inspect it locally.";
    return;
  }

  const analysis = analyzeContent({
    content,
    source: sourceSelect.value,
  });

  renderAnalysis(results.messageLocal, analysis, "Browser local analysis");
  messageStatus.textContent = "Local verdict updated. Use API verification only if you want a server-confirmed result.";
}

function analyzeScreenLocally() {
  if (!screenConsent.checked) {
    renderEmpty(
      results.screenLocal,
      "Ready when you are",
      "Allow analysis and add visible text to see a browser-local verdict.",
      "Pasted text runs in this browser",
    );
    screenStatus.textContent = "Allow screen analysis, then paste text or choose a screen to capture.";
    return;
  }

  const content = screenInput.value.trim();
  if (!content) {
    renderEmpty(
      results.screenLocal,
      "Ready",
      "Paste visible screen text or capture the full screen to inspect it.",
      "Pasted text runs in this browser",
    );
    screenStatus.textContent = "Add visible text to generate a local verdict.";
    return;
  }

  const analysis = analyzeContent({
    content,
    source: "screen",
  });

  renderAnalysis(results.screenLocal, analysis, "Browser local screen analysis");
  screenStatus.textContent = "Local verdict updated. API verification remains optional.";
}

async function sendForVerification(endpoint, body, statusElement, targetResult, button, successLabel) {
  button.disabled = true;
  statusElement.textContent = "Protected verification is running...";

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

async function captureScreenFrame() {
  const stream = await navigator.mediaDevices.getDisplayMedia({
    video: {
      cursor: "always",
    },
    audio: false,
  });

  try {
    const video = document.createElement("video");
    video.srcObject = stream;
    video.muted = true;
    await video.play();

    await new Promise((resolve) => {
      window.setTimeout(resolve, 250);
    });

    const sourceWidth = video.videoWidth || 1280;
    const sourceHeight = video.videoHeight || 720;
    const scale = Math.min(1, 1800 / Math.max(sourceWidth, sourceHeight));
    const canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(sourceWidth * scale));
    canvas.height = Math.max(1, Math.round(sourceHeight * scale));

    const context = canvas.getContext("2d");
    context.drawImage(video, 0, 0, canvas.width, canvas.height);

    return { canvas };
  } finally {
    stream.getTracks().forEach((track) => track.stop());
  }
}

async function runLocalServiceScreenOcr(canvas) {
  const response = await fetch("/api/analyze/screen/capture", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      imageDataUrl: canvas.toDataURL("image/jpeg", 0.92),
      consent: {
        process: true,
        screenScan: true,
        storeLog: storeLogConsent.checked,
        persistContentSnippet: snippetConsent.checked,
      },
      metadata: {
        sessionId: crypto.randomUUID(),
      },
    }),
  });

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "Local service screen OCR failed.");
  }

  return payload;
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

  captureScreenButton.disabled = true;
  screenStatus.textContent = "Waiting for screen permission...";

  try {
    const { canvas } = await captureScreenFrame();

    if (typeof window.TextDetector === "function") {
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
      return;
    }

    screenStatus.textContent = "Browser OCR is unavailable. Sending this capture to the locally hosted AI Shield service for Windows OCR.";
    const payload = await runLocalServiceScreenOcr(canvas);
    screenInput.value = payload.extractedText ?? "";
    renderAnalysis(results.screenLocal, payload.analysis, "Locally hosted Windows OCR");
    screenStatus.textContent = `Captured the selected screen and analyzed ${payload.ocr.lineCount} text lines with the local AI Shield service.`;
  } catch (error) {
    screenStatus.textContent = `Screen capture failed: ${error.message}`;
  } finally {
    captureScreenButton.disabled = false;
  }
}

async function submitFeedback(event) {
  event.preventDefault();
  const ratingInput = feedbackForm.querySelector('input[name="feedbackRating"]:checked');
  if (!ratingInput) {
    feedbackStatus.textContent = "Select a rating from 1 to 5.";
    feedbackForm.querySelector('input[name="feedbackRating"]').focus();
    return;
  }

  feedbackSubmitButton.disabled = true;
  feedbackStatus.textContent = "Submitting feedback...";

  try {
    const response = await fetch("/api/feedback", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        rating: Number(ratingInput.value),
        category: feedbackCategory.value,
        comment: feedbackComment.value,
      }),
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || "Feedback could not be submitted.");
    }

    feedbackForm.reset();
    feedbackCharacterCount.textContent = "0 / 500";
    feedbackStatus.textContent = `Thank you for helping improve AI Shield. Feedback reference: ${payload.feedbackId}`;
    window.setTimeout(() => {
      feedbackSubmitButton.disabled = false;
    }, 1500);
  } catch (error) {
    feedbackStatus.textContent = error.message;
    feedbackSubmitButton.disabled = false;
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
feedbackComment.addEventListener("input", () => {
  feedbackCharacterCount.textContent = `${feedbackComment.value.length} / 500`;
});
feedbackForm.addEventListener("submit", submitFeedback);

syncConsentControls();
renderEmpty(
  results.messageLocal,
  "Ready when you are",
  "Allow analysis and paste a message to see a local risk assessment.",
  "Runs in this browser",
);
renderEmpty(
  results.messageServer,
  "Not Verified",
  "Use API verification when you want a server-confirmed result.",
  "Starts only from the verification button",
);
renderEmpty(
  results.screenLocal,
  "Ready when you are",
  "Allow analysis and add visible text to see a browser-local verdict.",
  "Pasted text runs in this browser",
);
renderEmpty(
  results.screenServer,
  "Not Verified",
  "Send the extracted or pasted text when you want an API-confirmed result.",
  "Starts only from the verification button",
);
