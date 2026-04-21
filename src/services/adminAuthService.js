import { randomUUID } from "node:crypto";
import {
  createFingerprintHash,
  createIpHash,
  createSignedToken,
  isIpAllowed,
  normalizeIp,
  safeTextEqual,
  verifyPasswordHash,
  verifySignedToken,
  verifyTotpCode,
} from "../utils/adminSecurity.js";

function makeError(message, statusCode, code) {
  const error = new Error(message);
  error.statusCode = statusCode;
  error.code = code;
  return error;
}

export class AdminAuthService {
  constructor(config, options = {}) {
    this.config = config;
    this.now = options.now ?? (() => Date.now());
    this.failedAttemptsByIp = new Map();
    this.sessions = new Map();
    this.tokenSecret = Buffer.from(`${config.masterKey ?? ""}:admin-session`, "utf8");
  }

  debug(event, details = {}) {
    if (!this.config.authDebug) {
      return;
    }

    console.info(
      `[AI Shield][admin-auth] ${event}`,
      JSON.stringify({
        ...details,
        timestamp: new Date(this.now()).toISOString(),
      }),
    );
  }

  ensureConfigured() {
    const missing = [];

    if (!this.config.masterKey) {
      missing.push("AI_SHIELD_MASTER_KEY");
    }
    if (!this.config.adminUsername) {
      missing.push("AI_SHIELD_ADMIN_USERNAME");
    }
    if (!this.config.adminPasswordHash) {
      missing.push("AI_SHIELD_ADMIN_PASSWORD_HASH");
    }
    if (!this.config.adminOtpSecret) {
      missing.push("AI_SHIELD_ADMIN_OTP_SECRET");
    }

    if (missing.length > 0) {
      this.debug("config-missing", { missing });
      throw makeError(
        `Admin authentication is not configured. Missing: ${missing.join(", ")}.`,
        503,
        "admin_auth_not_configured",
      );
    }
  }

  assertIpAllowed(ipAddress) {
    const normalizedIp = normalizeIp(ipAddress);
    if (!isIpAllowed(normalizedIp, this.config.adminIpWhitelist)) {
      this.debug("ip-not-whitelisted", { ip: normalizedIp });
      throw makeError(
        "This IP is not allowed for admin access.",
        403,
        "admin_ip_not_whitelisted",
      );
    }

    return normalizedIp;
  }

  assertFingerprintPresent(fingerprint) {
    const normalizedFingerprint = String(fingerprint ?? "").trim();
    if (!normalizedFingerprint) {
      this.debug("missing-device-fingerprint");
      throw makeError(
        "A device fingerprint is required for admin authentication.",
        400,
        "admin_device_fingerprint_required",
      );
    }

    return normalizedFingerprint;
  }

  getBlockedRecord(ipAddress) {
    const normalizedIp = normalizeIp(ipAddress);
    const record = this.failedAttemptsByIp.get(normalizedIp);

    if (!record || !record.blockedAt) {
      return null;
    }

    return {
      ip: normalizedIp,
      attempts: record.attempts,
      blockedAt: record.blockedAt,
      lastFailedAt: record.lastFailedAt,
    };
  }

  assertNotBlocked(ipAddress) {
    const record = this.getBlockedRecord(ipAddress);
    if (!record) {
      return;
    }

    this.debug("ip-blocked", { ip: record.ip, attempts: record.attempts, blockedAt: record.blockedAt });
    throw makeError(
      "This IP has been blocked after repeated failed login attempts. An authenticated admin must unlock it.",
      423,
      "admin_ip_blocked",
    );
  }

  recordFailedAttempt(ipAddress) {
    const normalizedIp = normalizeIp(ipAddress);
    const nowIso = new Date(this.now()).toISOString();
    const existing = this.failedAttemptsByIp.get(normalizedIp) ?? {
      ip: normalizedIp,
      attempts: 0,
      blockedAt: null,
      lastFailedAt: null,
    };

    existing.attempts += 1;
    existing.lastFailedAt = nowIso;

    if (existing.attempts >= this.config.adminFailedLoginLimit) {
      existing.blockedAt = nowIso;
    }

    this.failedAttemptsByIp.set(normalizedIp, existing);
    this.debug("failed-login-attempt", {
      ip: normalizedIp,
      attempts: existing.attempts,
      blocked: Boolean(existing.blockedAt),
    });
    return {
      blocked: Boolean(existing.blockedAt),
      attempts: existing.attempts,
      blockedAt: existing.blockedAt,
    };
  }

  clearFailedAttempts(ipAddress) {
    this.debug("failed-attempts-cleared", { ip: normalizeIp(ipAddress) });
    this.failedAttemptsByIp.delete(normalizeIp(ipAddress));
  }

  createSession({ username, ipAddress, fingerprint }) {
    const now = this.now();
    const sessionId = randomUUID();
    const expiresAt = now + this.config.adminSessionTtlMs;
    const session = {
      id: sessionId,
      username,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(expiresAt).toISOString(),
      lastSeenAt: new Date(now).toISOString(),
      fingerprintHash: createFingerprintHash(fingerprint, this.tokenSecret),
      ipHash: createIpHash(ipAddress, this.tokenSecret),
      revokedAt: null,
    };

    this.sessions.set(sessionId, session);
    this.debug("session-created", { sessionId, username, ip: normalizeIp(ipAddress) });

    const payload = {
      iss: "ai-shield-admin",
      sub: username,
      sid: sessionId,
      role: "admin",
      iat: Math.floor(now / 1000),
      exp: Math.floor(expiresAt / 1000),
    };

    return {
      token: createSignedToken(payload, this.tokenSecret),
      session,
    };
  }

  login({ username, password, otp, ipAddress, fingerprint }) {
    this.ensureConfigured();
    const normalizedIp = this.assertIpAllowed(ipAddress);
    this.assertNotBlocked(normalizedIp);
    const normalizedFingerprint = this.assertFingerprintPresent(fingerprint);

    const normalizedUsername = String(username ?? "").trim();
    const isValidUser = normalizedUsername && safeTextEqual(normalizedUsername, this.config.adminUsername);
    const isValidPassword = password && verifyPasswordHash(password, this.config.adminPasswordHash);
    const isValidOtp = otp && verifyTotpCode(this.config.adminOtpSecret, otp);

    if (!(isValidUser && isValidPassword && isValidOtp)) {
      this.debug("login-rejected", {
        ip: normalizedIp,
        hasUsername: Boolean(normalizedUsername),
        userMatch: Boolean(isValidUser),
        passwordMatch: Boolean(isValidPassword),
        otpMatch: Boolean(isValidOtp),
      });
      const failure = this.recordFailedAttempt(normalizedIp);
      if (failure.blocked) {
        throw makeError(
          "This IP has been blocked after 3 failed login attempts. An authenticated admin must unlock it.",
          423,
          "admin_ip_blocked",
        );
      }

      throw makeError(
        "Invalid username, password, or one-time code.",
        401,
        "admin_invalid_credentials",
      );
    }

    this.clearFailedAttempts(normalizedIp);
    this.debug("login-accepted", {
      ip: normalizedIp,
      username: this.config.adminUsername,
    });
    const { token, session } = this.createSession({
      username: this.config.adminUsername,
      ipAddress: normalizedIp,
      fingerprint: normalizedFingerprint,
    });

    return {
      token,
      session,
    };
  }

  authenticate({ token, ipAddress, fingerprint }) {
    this.ensureConfigured();
    const normalizedIp = this.assertIpAllowed(ipAddress);
    this.assertNotBlocked(normalizedIp);
    const normalizedFingerprint = this.assertFingerprintPresent(fingerprint);

    if (!token) {
      this.debug("missing-bearer-token", { ip: normalizedIp });
      throw makeError(
        "Missing bearer token.",
        401,
        "admin_bearer_token_required",
      );
    }

    let verifiedToken;
    try {
      verifiedToken = verifySignedToken(token, this.tokenSecret);
    } catch {
      this.debug("invalid-token-signature", { ip: normalizedIp });
      throw makeError(
        "Invalid admin session token.",
        401,
        "admin_invalid_token",
      );
    }

    const payload = verifiedToken.payload;
    if (payload.role !== "admin" || payload.iss !== "ai-shield-admin") {
      throw makeError(
        "This token cannot access the admin API.",
        403,
        "admin_wrong_token_scope",
      );
    }

    const session = this.sessions.get(payload.sid);
    if (!session || session.revokedAt) {
      this.debug("session-not-active", { sessionId: payload.sid, ip: normalizedIp });
      throw makeError(
        "This admin session is no longer active.",
        401,
        "admin_session_not_active",
      );
    }

    const now = this.now();
    if (payload.exp * 1000 <= now || Date.parse(session.expiresAt) <= now) {
      this.sessions.delete(payload.sid);
      this.debug("session-expired", { sessionId: payload.sid, ip: normalizedIp });
      throw makeError(
        "This admin session has expired.",
        401,
        "admin_session_expired",
      );
    }

    if (Date.parse(session.lastSeenAt) + this.config.adminIdleTimeoutMs <= now) {
      this.sessions.delete(payload.sid);
      this.debug("session-idle-timeout", { sessionId: payload.sid, ip: normalizedIp });
      throw makeError(
        "This admin session expired due to inactivity.",
        401,
        "admin_session_idle_timeout",
      );
    }

    const currentFingerprintHash = createFingerprintHash(normalizedFingerprint, this.tokenSecret);
    if (currentFingerprintHash !== session.fingerprintHash) {
      this.debug("device-mismatch", { sessionId: payload.sid, ip: normalizedIp });
      throw makeError(
        "This device fingerprint does not match the active admin session.",
        403,
        "admin_device_mismatch",
      );
    }

    const currentIpHash = createIpHash(normalizedIp, this.tokenSecret);
    if (currentIpHash !== session.ipHash) {
      this.debug("session-ip-mismatch", { sessionId: payload.sid, ip: normalizedIp });
      throw makeError(
        "This IP does not match the active admin session.",
        403,
        "admin_ip_mismatch",
      );
    }

    session.lastSeenAt = new Date(now).toISOString();
    this.sessions.set(session.id, session);
    this.debug("session-validated", { sessionId: session.id, ip: normalizedIp });
    return session;
  }

  logout(token) {
    if (!token) {
      return false;
    }

    try {
      const payload = verifySignedToken(token, this.tokenSecret).payload;
      const session = this.sessions.get(payload.sid);
      if (!session) {
        return false;
      }

      session.revokedAt = new Date(this.now()).toISOString();
      this.sessions.set(session.id, session);
      this.sessions.delete(session.id);
      this.debug("session-logout", { sessionId: session.id });
      return true;
    } catch {
      return false;
    }
  }

  listBlockedIps() {
    return Array.from(this.failedAttemptsByIp.values())
      .filter((record) => record.blockedAt)
      .map((record) => ({
        ip: record.ip,
        attempts: record.attempts,
        blockedAt: record.blockedAt,
        lastFailedAt: record.lastFailedAt,
      }))
      .sort((left, right) => Date.parse(right.blockedAt) - Date.parse(left.blockedAt));
  }

  unlockIp(ipAddress) {
    const normalizedIp = normalizeIp(ipAddress);
    const unlocked = this.failedAttemptsByIp.delete(normalizedIp);
    this.debug("ip-unlock", { ip: normalizedIp, unlocked });
    return unlocked;
  }

  getSessionView(session) {
    return {
      username: session.username,
      createdAt: session.createdAt,
      expiresAt: session.expiresAt,
      lastSeenAt: session.lastSeenAt,
      idleTimeoutMs: this.config.adminIdleTimeoutMs,
      sessionTtlMs: this.config.adminSessionTtlMs,
    };
  }
}
