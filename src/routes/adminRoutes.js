import { extractBearerToken, requireAdminSession } from "../middleware/auth.js";
import { readJsonBody, sendJson } from "../utils/http.js";

async function handleLogin(req, res, context) {
  const body = await readJsonBody(req, context.config.maxBodyBytes);

  try {
    const result = context.adminAuthService.login({
      username: body.username,
      password: body.password,
      otp: body.otp,
      ipAddress: context.ip,
      fingerprint: req.headers["x-device-fingerprint"],
    });

    sendJson(res, 200, {
      message: "Admin login successful.",
      token: result.token,
      session: context.adminAuthService.getSessionView(result.session),
      security: {
        ip: context.ip,
        whitelistEnforced: context.config.adminIpWhitelist.length > 0,
        twoFactorRequired: true,
        deviceBound: true,
      },
    });
  } catch (error) {
    sendJson(res, error.statusCode ?? 401, {
      error: error.message,
      code: error.code ?? "admin_login_failed",
    });
  }

  return true;
}

async function handleSession(req, res, context) {
  const session = requireAdminSession(req, res, context);
  if (!session) {
    return true;
  }

  sendJson(res, 200, {
    session: context.adminAuthService.getSessionView(session),
    blockedIpCount: context.adminAuthService.listBlockedIps().length,
  });
  return true;
}

async function handleLogout(req, res, context) {
  const session = requireAdminSession(req, res, context);
  if (!session) {
    return true;
  }

  context.adminAuthService.logout(extractBearerToken(req));
  sendJson(res, 200, {
    message: "Admin session closed.",
  });
  return true;
}

async function handleBlockedIps(req, res, context) {
  const blockedIps = context.adminAuthService.listBlockedIps();
  sendJson(res, 200, {
    blockedIps,
    count: blockedIps.length,
  });
  return true;
}

async function handleUnlockIp(req, res, context) {
  const body = await readJsonBody(req, context.config.maxBodyBytes);
  const ip = String(body.ip ?? "").trim();

  if (!ip) {
    sendJson(res, 400, {
      error: "A blocked IP is required.",
      code: "admin_unlock_ip_required",
    });
    return true;
  }

  const unlocked = context.adminAuthService.unlockIp(ip);
  if (!unlocked) {
    sendJson(res, 404, {
      error: "Blocked IP not found.",
      code: "admin_unlock_target_not_found",
    });
    return true;
  }

  sendJson(res, 200, {
    message: "Blocked IP unlocked.",
    ip,
  });
  return true;
}

async function handleProtectedAdminRoutes(req, res, url, context) {
  const session = requireAdminSession(req, res, context);
  if (!session) {
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
        code: "admin_log_not_found",
      });
      return true;
    }

    sendJson(res, 200, {
      deleted: true,
      id,
    });
    return true;
  }

  if (req.method === "GET" && url.pathname === "/api/admin/security/blocked") {
    return handleBlockedIps(req, res, context);
  }

  if (req.method === "POST" && url.pathname === "/api/admin/security/unlock-ip") {
    return handleUnlockIp(req, res, context);
  }

  sendJson(res, 405, {
    error: "Method not allowed.",
    code: "admin_method_not_allowed",
  });
  return true;
}

export async function handleAdminRoutes(req, res, url, context) {
  if (!url.pathname.startsWith("/api/admin/")) {
    return false;
  }

  if (req.method === "POST" && url.pathname === "/api/admin/auth/login") {
    return handleLogin(req, res, context);
  }

  if (req.method === "GET" && url.pathname === "/api/admin/auth/session") {
    return handleSession(req, res, context);
  }

  if (req.method === "POST" && url.pathname === "/api/admin/auth/logout") {
    return handleLogout(req, res, context);
  }

  return handleProtectedAdminRoutes(req, res, url, context);
}
