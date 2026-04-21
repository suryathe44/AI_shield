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

async function runAnalysis(req, res, context, options) {
  const body = await readJsonBody(req, context.config.maxBodyBytes);
  const consent = normalizeConsent(body.consent);

  if (!consent.process) {
    sendJson(res, 400, {
      error: "User consent is required before content can be analyzed.",
    });
    return true;
  }

  if (options.requiresScreenConsent && !consent.screenScan) {
    sendJson(res, 400, {
      error: "Explicit screen-scan consent is required for screen analysis.",
    });
    return true;
  }

  const targetField = options.bodyField;
  const { content, wasTruncated } = sanitizeContent(body[targetField]);

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

  let logReceipt = null;
  if (consent.storeLog) {
    logReceipt = await context.logger.appendLog({
      analysis,
      content,
      source: options.source,
      consent,
      actorHint: body.metadata?.userId ?? context.ip,
      metadata: body.metadata ?? {},
    });
  }

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

export async function handleAnalyzeRoutes(req, res, url, context) {
  if (req.method === "POST" && url.pathname === "/api/analyze") {
    return runAnalysis(req, res, context, {
      source: "message",
      bodyField: "content",
      requiresScreenConsent: false,
    });
  }

  if (req.method === "POST" && url.pathname === "/api/analyze/screen") {
    return runAnalysis(req, res, context, {
      source: "screen",
      bodyField: "visibleText",
      requiresScreenConsent: true,
    });
  }

  return false;
}