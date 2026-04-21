import { sendJson } from "../utils/http.js";

export function extractBearerToken(req) {
  const authorization = req.headers.authorization;
  if (typeof authorization !== "string") {
    return "";
  }

  const match = /^Bearer\s+(.+)$/i.exec(authorization.trim());
  return match ? match[1].trim() : "";
}

export function requireAdminSession(req, res, context) {
  try {
    const session = context.adminAuthService.authenticate({
      token: extractBearerToken(req),
      ipAddress: context.ip,
      fingerprint: req.headers["x-device-fingerprint"],
    });

    req.adminSession = session;
    return session;
  } catch (error) {
    sendJson(res, error.statusCode ?? 401, {
      error: error.message,
      code: error.code ?? "admin_auth_failed",
    });
    return null;
  }
}
