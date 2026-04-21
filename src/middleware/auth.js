import { timingSafeEqual } from "node:crypto";
import { sendJson } from "../utils/http.js";

export function authorizeAdmin(req, res, config) {
  const expected = config.adminApiKey;
  const provided = req.headers["x-admin-api-key"];

  if (!expected) {
    sendJson(res, 503, {
      error: "Admin API access is disabled until AI_SHIELD_ADMIN_API_KEY is configured.",
    });
    return false;
  }

  if (typeof provided !== "string") {
    sendJson(res, 401, {
      error: "Missing X-Admin-API-Key header.",
    });
    return false;
  }

  const providedBuffer = Buffer.from(provided);
  const expectedBuffer = Buffer.from(expected);
  const isValid =
    providedBuffer.length === expectedBuffer.length &&
    timingSafeEqual(providedBuffer, expectedBuffer);

  if (!isValid) {
    sendJson(res, 403, {
      error: "Invalid admin API key.",
    });
    return false;
  }

  return true;
}