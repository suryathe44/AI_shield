import http from "node:http";
import { loadConfig } from "./config/env.js";
import { AdminAuthService } from "./services/adminAuthService.js";
import { createRateLimiter } from "./middleware/rateLimiter.js";
import { handleAdminRoutes } from "./routes/adminRoutes.js";
import { handleAnalyzeRoutes } from "./routes/analyzeRoutes.js";
import { SecureLogger } from "./services/secureLogger.js";
import { WindowsOcrService } from "./services/windowsOcr.js";
import {
  getClientIp,
  sendJson,
  serveStaticAsset,
  setRateLimitHeaders,
  setSecurityHeaders,
} from "./utils/http.js";

export function createAiShieldApp(overrides = {}) {
  const config = loadConfig(overrides);
  const logger = overrides.logger ?? new SecureLogger({
    logFilePath: config.logFilePath,
    masterKey: config.masterKey,
  });
  const adminAuthService = overrides.adminAuthService ?? new AdminAuthService(config);
  const ocrService = overrides.ocrService ?? new WindowsOcrService();
  const rateLimiter = overrides.rateLimiter ?? createRateLimiter({
    windowMs: config.rateLimitWindowMs,
    analyzeLimit: config.analyzePerMinute,
    adminLimit: config.adminPerMinute,
    adminAuthLimit: config.adminAuthPerMinute,
  });

  const context = {
    config,
    logger,
    adminAuthService,
    ocrService,
    rateLimiter,
  };

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? `${config.host}:${config.port}`}`);
      setSecurityHeaders(req, res, config);

      if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/health") {
        sendJson(res, 200, {
          service: "AI Shield",
          status: "ok",
          timestamp: new Date().toISOString(),
          privacyMode: "consent-first",
        });
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/features") {
        sendJson(res, 200, {
          name: "AI Shield",
          localAnalysisAvailable: true,
          secureLogging: true,
          screenTextAnalysis: true,
          screenCaptureOcrFallback: true,
          adminPortal: true,
          storage: logger.getStorageMetadata(),
        });
        return;
      }

      const ip = getClientIp(req);
      const routeContext = { ...context, ip };

      if (url.pathname.startsWith("/api/admin/")) {
        const bucket = url.pathname === "/api/admin/auth/login" ? "admin-auth" : "admin";
        const rateState = rateLimiter.consume({ ip, bucket });
        setRateLimitHeaders(res, rateState);
        if (!rateState.allowed) {
          sendJson(res, 429, {
            error: bucket === "admin-auth"
              ? "Too many admin login attempts. Please retry later."
              : "Admin rate limit exceeded. Please retry later.",
          });
          return;
        }

        if (await handleAdminRoutes(req, res, url, routeContext)) {
          return;
        }
      }

      if (url.pathname.startsWith("/api/")) {
        const rateState = rateLimiter.consume({ ip, bucket: "analyze" });
        setRateLimitHeaders(res, rateState);
        if (!rateState.allowed) {
          sendJson(res, 429, {
            error: "Analysis rate limit exceeded. Please retry shortly.",
          });
          return;
        }

        if (await handleAnalyzeRoutes(req, res, url, routeContext)) {
          return;
        }

        sendJson(res, 404, {
          error: "API route not found.",
        });
        return;
      }

      if ((req.method === "GET" || req.method === "HEAD") && (await serveStaticAsset(url.pathname, req, res))) {
        return;
      }

      sendJson(res, 404, {
        error: "Route not found.",
      });
    } catch (error) {
      console.error("AI Shield request error", error);
      sendJson(res, error.statusCode ?? 500, {
        error: error.statusCode ? error.message : "Internal server error.",
      });
    }
  });

  return {
    server,
    config,
    logger,
    adminAuthService,
    ocrService,
  };
}
