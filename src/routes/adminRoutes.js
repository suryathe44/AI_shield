import { authorizeAdmin } from "../middleware/auth.js";
import { sendJson } from "../utils/http.js";

export async function handleAdminRoutes(req, res, url, context) {
  if (!url.pathname.startsWith("/api/admin/logs")) {
    return false;
  }

  if (!authorizeAdmin(req, res, context.config)) {
    return true;
  }

  if (req.method === "GET" && url.pathname === "/api/admin/logs") {
    const logs = await context.logger.readAllLogs();
    sendJson(res, 200, {
      logs,
      count: logs.length,
    });
    return true;
  }

  if (req.method === "DELETE" && url.pathname === "/api/admin/logs") {
    const deletedCount = await context.logger.deleteAll();
    sendJson(res, 200, {
      deletedCount,
      message: "All stored logs have been deleted.",
    });
    return true;
  }

  if (req.method === "DELETE" && url.pathname.startsWith("/api/admin/logs/")) {
    const id = decodeURIComponent(url.pathname.slice("/api/admin/logs/".length));
    const deleted = await context.logger.deleteLog(id);

    if (!deleted) {
      sendJson(res, 404, {
        error: "Log entry not found.",
      });
      return true;
    }

    sendJson(res, 200, {
      deleted: true,
      id,
    });
    return true;
  }

  sendJson(res, 405, {
    error: "Method not allowed.",
  });
  return true;
}