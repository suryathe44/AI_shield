import { analyzeContent } from "../../shared/detectionEngine.js";
import { sanitizeContent } from "../../shared/textUtils.js";
import { readJsonBody, sendJson } from "../utils/http.js";

function normalizeConsent(rawConsent = {}) {
  return {
    process: rawConsent.process === true,
    storeLog: rawConsent.storeLog === true,
    screenScan: rawConsent.screenScan === true,
    persistContentSnippet: rawConsent.persistContentSnippet === true,
  };
}

function normalizeSource(source, fallback) {
  return typeof source === "string" && source.trim() ? source.trim().toLowerCase() : fallback;
}

function validateConsent(consent, requiresScreenConsent) {
  if (!consent.process) {
    return {
      ok: false,
      message: "User consent is required before content can be analyzed.",
    };
  }

  if (requiresScreenConsent && !consent.screenScan) {
    return {
      ok: false,
      message: "Explicit screen-scan consent is required for screen analysis.",
    };
  }

  return { ok: true };
}

async function appendAnalysisLog(context, body, consent, analysis, content, source) {
  if (!consent.storeLog) {
    return null;
  }

  return context.logger.appendLog({
    analysis,
    content,
    source,
    consent,
    actorHint: body.metadata?.userId ?? context.ip,
    metadata: body.metadata ?? {},
  });
}

async function runTextAnalysis(req, res, context, options) {
  const body = await readJsonBody(req, context.config.maxBodyBytes);
  const consent = normalizeConsent(body.consent);
  const consentState = validateConsent(consent, options.requiresScreenConsent);

  if (!consentState.ok) {
    sendJson(res, 400, {
      error: consentState.message,
    });
    return true;
  }

  const { content, wasTruncated } = sanitizeContent(body[options.bodyField]);
  if (!content) {
    sendJson(res, 400, {
      error: "A non-empty message or visible screen text is required.",
    });
    return true;
  }

  const analysis = analyzeContent({
    content,
    source: normalizeSource(body.source, options.source),
  });
  const logReceipt = await appendAnalysisLog(context, body, consent, analysis, content, options.source);

  sendJson(res, 200, {
    analysis,
    privacy: {
      processed: true,
      stored: Boolean(logReceipt),
      wasTruncated,
      thirdPartySharing: false,
      localAnalysisAvailable: true,
      storage: context.logger.getStorageMetadata(),
    },
    logReceipt,
  });

  return true;
}

async function runScreenCaptureAnalysis(req, res, context) {
  const body = await readJsonBody(req, context.config.maxImageBodyBytes);
  const consent = normalizeConsent(body.consent);
  const consentState = validateConsent(consent, true);

  if (!consentState.ok) {
    sendJson(res, 400, {
      error: consentState.message,
    });
    return true;
  }

  if (typeof body.imageDataUrl !== "string" || !body.imageDataUrl.startsWith("data:image/")) {
    sendJson(res, 400, {
      error: "A base64 PNG or JPEG screen capture is required.",
    });
    return true;
  }

  const ocrResult = await context.ocrService.extractTextFromDataUrl(body.imageDataUrl);
  const { content, wasTruncated } = sanitizeContent(ocrResult.text);

  if (!content) {
    sendJson(res, 422, {
      error: "No readable text was detected in the captured screen.",
      ocr: {
        engine: ocrResult.engine,
        lineCount: 0,
      },
    });
    return true;
  }

  const analysis = analyzeContent({
    content,
    source: "screen_capture",
  });
  const logReceipt = await appendAnalysisLog(context, body, consent, analysis, content, "screen_capture");

  sendJson(res, 200, {
    analysis,
    extractedText: content,
    ocr: {
      engine: ocrResult.engine,
      lineCount: ocrResult.lineCount,
      localOnly: true,
    },
    privacy: {
      processed: true,
      stored: Boolean(logReceipt),
      wasTruncated,
      thirdPartySharing: false,
      localAnalysisAvailable: true,
      storage: context.logger.getStorageMetadata(),
    },
    logReceipt,
  });

  return true;
}

export async function handleAnalyzeRoutes(req, res, url, context) {
  if (req.method === "POST" && url.pathname === "/api/analyze") {
    return runTextAnalysis(req, res, context, {
      source: "message",
      bodyField: "content",
      requiresScreenConsent: false,
    });
  }

  if (req.method === "POST" && url.pathname === "/api/analyze/screen") {
    return runTextAnalysis(req, res, context, {
      source: "screen",
      bodyField: "visibleText",
      requiresScreenConsent: true,
    });
  }

  if (req.method === "POST" && url.pathname === "/api/analyze/screen/capture") {
    return runScreenCaptureAnalysis(req, res, context);
  }

  return false;
}
