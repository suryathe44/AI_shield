import path from "node:path";

function parseNumber(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseMinutes(value, fallbackMinutes) {
  return parseNumber(value, fallbackMinutes) * 60_000;
}

function parseBoolean(value, fallback = false) {
  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value !== "string") {
    return fallback;
  }

  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }

  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }

  return fallback;
}

function normalizeString(value, fallback = "") {
  if (typeof value !== "string") {
    return fallback;
  }

  return value.trim();
}

function normalizeAllowedOrigins(value) {
  if (value instanceof Set) {
    return value;
  }

  if (Array.isArray(value)) {
    return new Set(value.filter(Boolean));
  }

  return new Set(
    String(value ?? "http://127.0.0.1:3000,http://localhost:3000")
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean),
  );
}

function normalizeStringList(value, fallback = []) {
  if (Array.isArray(value)) {
    return value.map((entry) => String(entry).trim()).filter(Boolean);
  }

  if (value instanceof Set) {
    return Array.from(value).map((entry) => String(entry).trim()).filter(Boolean);
  }

  if (typeof value !== "string") {
    return fallback;
  }

  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function loadConfig(overrides = {}) {
  const defaults = {
    port: parseNumber(process.env.PORT, 10000),
   host: process.env.HOST ?? "0.0.0.0",
    allowedOrigins: normalizeAllowedOrigins(process.env.AI_SHIELD_ALLOWED_ORIGINS),
    masterKey: process.env.AI_SHIELD_MASTER_KEY ?? "",
    adminUsername: normalizeString(process.env.AI_SHIELD_ADMIN_USERNAME, "admin"),
    adminPasswordHash: normalizeString(process.env.AI_SHIELD_ADMIN_PASSWORD_HASH),
    adminOtpSecret: normalizeString(process.env.AI_SHIELD_ADMIN_OTP_SECRET),
    adminIpWhitelist: normalizeStringList(process.env.AI_SHIELD_ADMIN_IP_WHITELIST, []),
    adminFailedLoginLimit: parseNumber(process.env.AI_SHIELD_ADMIN_FAILED_LOGIN_LIMIT, 3),
    adminSessionTtlMs: parseMinutes(process.env.AI_SHIELD_ADMIN_SESSION_TTL_MIN, 30),
    adminIdleTimeoutMs: parseMinutes(process.env.AI_SHIELD_ADMIN_IDLE_TIMEOUT_MIN, 15),
    authDebug: parseBoolean(process.env.AI_SHIELD_AUTH_DEBUG, false),
    logFilePath: path.resolve(process.cwd(), process.env.AI_SHIELD_LOG_FILE ?? "./data/secure-logs.enc"),
    maxBodyBytes: 32_000,
    maxImageBodyBytes: parseNumber(process.env.AI_SHIELD_MAX_IMAGE_BODY_BYTES, 8_000_000),
    rateLimitWindowMs: 60_000,
    analyzePerMinute: parseNumber(process.env.AI_SHIELD_RATE_LIMIT_ANALYZE_PER_MIN, 60),
    adminPerMinute: parseNumber(process.env.AI_SHIELD_RATE_LIMIT_ADMIN_PER_MIN, 20),
    adminAuthPerMinute: parseNumber(process.env.AI_SHIELD_RATE_LIMIT_ADMIN_AUTH_PER_MIN, 10),
  };

  const merged = { ...defaults, ...overrides };
  merged.allowedOrigins = normalizeAllowedOrigins(merged.allowedOrigins);
  merged.adminIpWhitelist = normalizeStringList(merged.adminIpWhitelist, ["127.0.0.1", "::1"]);
  merged.adminUsername = normalizeString(merged.adminUsername, "admin");
  merged.adminPasswordHash = normalizeString(merged.adminPasswordHash);
  merged.adminOtpSecret = normalizeString(merged.adminOtpSecret);
  merged.authDebug = parseBoolean(merged.authDebug, false);
  merged.logFilePath = path.resolve(process.cwd(), merged.logFilePath);

  return merged;
}
