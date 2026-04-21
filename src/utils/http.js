import { readFile } from "node:fs/promises";
import path from "node:path";

const PUBLIC_DIR = path.resolve(process.cwd(), "public");
const SHARED_DIR = path.resolve(process.cwd(), "shared");

const MIME_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml; charset=utf-8",
};

export function sendJson(res, statusCode, payload) {
  if (!res.headersSent) {
    res.writeHead(statusCode, {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    });
  }

  res.end(JSON.stringify(payload));
}

export function setSecurityHeaders(req, res, config) {
  const origin = req.headers.origin;

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
  );
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Device-Fingerprint");

  if (origin && config.allowedOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
}

export function setRateLimitHeaders(res, rateState) {
  res.setHeader("X-RateLimit-Limit", String(rateState.limit));
  res.setHeader("X-RateLimit-Remaining", String(rateState.remaining));
  res.setHeader("X-RateLimit-Reset", String(rateState.resetAt));
}

export async function readJsonBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalBytes = 0;
    let aborted = false;

    req.on("data", (chunk) => {
      if (aborted) {
        return;
      }

      totalBytes += chunk.length;
      if (totalBytes > maxBytes) {
        aborted = true;
        const error = new Error("Payload too large");
        error.statusCode = 413;
        reject(error);
        return;
      }

      chunks.push(chunk);
    });

    req.on("end", () => {
      if (aborted) {
        return;
      }

      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw ? JSON.parse(raw) : {});
      } catch (error) {
        const parseError = new Error("Invalid JSON payload");
        parseError.statusCode = 400;
        reject(parseError);
      }
    });

    req.on("error", reject);
  });
}

export function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length > 0) {
    return forwarded.split(",")[0].trim();
  }

  return req.socket.remoteAddress ?? "unknown";
}

export async function serveStaticAsset(pathname, req, res) {
  const isShared = pathname.startsWith("/shared/");
  const baseDir = isShared ? SHARED_DIR : PUBLIC_DIR;
  const relativePath = isShared
    ? pathname.slice("/shared/".length)
    : pathname === "/"
      ? "index.html"
      : pathname.slice(1);

  if (!relativePath) {
    return false;
  }

  const absolutePath = path.resolve(baseDir, relativePath);
  if (!absolutePath.startsWith(baseDir)) {
    return false;
  }

  try {
    const file = await readFile(absolutePath);
    const extension = path.extname(absolutePath);
    const contentType = MIME_TYPES[extension] ?? "application/octet-stream";

    res.writeHead(200, {
      "Content-Type": contentType,
      "Cache-Control": extension === ".html" ? "no-store" : "public, max-age=300",
    });

    if (req.method === "HEAD") {
      res.end();
      return true;
    }

    res.end(file);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") {
      return false;
    }

    throw error;
  }
}
