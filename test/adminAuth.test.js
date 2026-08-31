import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { createHmac } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { createAiShieldApp } from "../src/app.js";
import { AdminAuthService } from "../src/services/adminAuthService.js";
import {
  createPasswordHash,
  generateBase32Secret,
  generateTotpCode,
  verifySignedToken,
} from "../src/utils/adminSecurity.js";

function signTokenParts(header, payload, secret) {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest("base64url");
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function buildAdminConfig(tempDir, overrides = {}) {
  const otpSecret = overrides.adminOtpSecret ?? generateBase32Secret();
  return {
    host: "127.0.0.1",
    port: 0,
    masterKey: "test-master-key",
    adminUsername: "admin",
    adminPasswordHash: createPasswordHash("StrongPass!234"),
    adminOtpSecret: otpSecret,
    adminRequireTotp: true,
    adminIpWhitelist: ["*"],
    adminFailedLoginLimit: 3,
    adminSessionTtlMs: 30 * 60_000,
    adminIdleTimeoutMs: 15 * 60_000,
    adminTrustedDeviceTtlMs: 30 * 24 * 60 * 60_000,
    adminAuthPerMinute: 20,
    adminPerMinute: 30,
    logFilePath: path.join(tempDir, "logs.enc"),
    allowedOrigins: ["http://127.0.0.1:3000"],
    ...overrides,
  };
}

async function startApp(config) {
  const app = createAiShieldApp(config);
  await new Promise((resolve) => {
    app.server.listen(0, "127.0.0.1", resolve);
  });

  const address = app.server.address();
  return {
    ...app,
    baseUrl: `http://127.0.0.1:${address.port}`,
  };
}

async function loginAdmin(baseUrl, otpSecret, options = {}) {
  const fingerprint = options.fingerprint ?? "device-fingerprint-alpha";
  const ip = options.ip ?? "198.51.100.50";

  const response = await fetch(`${baseUrl}/api/admin/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Device-Fingerprint": fingerprint,
      "X-Forwarded-For": ip,
    },
    body: JSON.stringify({
      username: options.username ?? "admin",
      password: options.password ?? "StrongPass!234",
      otp: Object.hasOwn(options, "otp") ? options.otp : generateTotpCode(otpSecret),
      trustDevice: options.trustDevice ?? false,
    }),
  });

  return {
    response,
    body: await response.json(),
    fingerprint,
    ip,
  };
}

test("admin login returns a token and protects admin log access", async (t) => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "ai-shield-admin-"));
  const config = buildAdminConfig(tempDir);
  const { server, baseUrl } = await startApp(config);

  t.after(() => new Promise((resolve) => server.close(resolve)));

  const login = await loginAdmin(baseUrl, config.adminOtpSecret);
  assert.equal(login.response.status, 200);
  assert.ok(login.body.token);

  const logsResponse = await fetch(`${baseUrl}/api/admin/logs`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${login.body.token}`,
      "X-Device-Fingerprint": login.fingerprint,
      "X-Forwarded-For": login.ip,
    },
  });

  assert.equal(logsResponse.status, 200);
  const logsBody = await logsResponse.json();
  assert.equal(logsBody.count, 0);
});

test("password-only login works when TOTP is disabled", async (t) => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "ai-shield-admin-"));
  const config = buildAdminConfig(tempDir, { adminRequireTotp: false, adminOtpSecret: "" });
  const { server, baseUrl } = await startApp(config);
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const login = await loginAdmin(baseUrl, "", { otp: "" });
  assert.equal(login.response.status, 200);
  assert.equal(login.body.security.twoFactorRequired, false);
});

test("TOTP remains required when enabled", async (t) => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "ai-shield-admin-"));
  const config = buildAdminConfig(tempDir);
  const { server, baseUrl } = await startApp(config);
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const login = await loginAdmin(baseUrl, config.adminOtpSecret, { otp: "" });
  assert.equal(login.response.status, 401);
  assert.equal(login.body.code, "admin_invalid_credentials");
});

test("an empty IP whitelist allows admin login", async (t) => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "ai-shield-admin-"));
  const config = buildAdminConfig(tempDir, { adminIpWhitelist: [] });
  const { server, baseUrl } = await startApp(config);
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const login = await loginAdmin(baseUrl, config.adminOtpSecret, { ip: "203.0.113.25" });
  assert.equal(login.response.status, 200);
  assert.equal(login.body.security.whitelistEnforced, false);
});

test("a configured IP whitelist blocks an unapproved IP", async (t) => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "ai-shield-admin-"));
  const config = buildAdminConfig(tempDir, { adminIpWhitelist: ["203.0.113.10"] });
  const { server, baseUrl } = await startApp(config);
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const login = await loginAdmin(baseUrl, config.adminOtpSecret, { ip: "203.0.113.25" });
  assert.equal(login.response.status, 403);
  assert.equal(login.body.code, "admin_ip_not_whitelisted");
});

test("trusted-device tokens expire after their configured lifetime", () => {
  let now = Date.now();
  const config = buildAdminConfig(os.tmpdir(), { adminTrustedDeviceTtlMs: 30 * 24 * 60 * 60_000 });
  const auth = new AdminAuthService(config, { now: () => now });
  const fingerprint = "trusted-device-fingerprint";
  const firstLogin = auth.login({ username: "admin", password: "StrongPass!234", otp: generateTotpCode(config.adminOtpSecret), ipAddress: "203.0.113.1", fingerprint, trustDevice: true });
  assert.equal(auth.isTrustedDeviceTokenValid(firstLogin.trustedDeviceToken, fingerprint), true);

  now += config.adminTrustedDeviceTtlMs + 1;
  assert.equal(auth.isTrustedDeviceTokenValid(firstLogin.trustedDeviceToken, fingerprint), false);
});

test("invalid trusted-device tokens cannot replace TOTP", () => {
  const config = buildAdminConfig(os.tmpdir());
  const auth = new AdminAuthService(config);
  assert.throws(() => auth.login({ username: "admin", password: "StrongPass!234", otp: "", ipAddress: "203.0.113.1", fingerprint: "device", trustedDeviceToken: "invalid.token.value" }), (error) => error.code === "admin_invalid_credentials");
});

test("signed token validation rejects an unexpected algorithm header", () => {
  const secret = Buffer.from("token-test-secret");
  const token = signTokenParts({ alg: "none", typ: "JWT" }, { role: "admin" }, secret);
  assert.throws(() => verifySignedToken(token, secret), /unsupported token header/i);
});

test("successful TOTP can issue an HttpOnly trusted-device cookie for later login", async (t) => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "ai-shield-admin-"));
  const config = buildAdminConfig(tempDir);
  const { server, baseUrl } = await startApp(config);
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const first = await loginAdmin(baseUrl, config.adminOtpSecret, { trustDevice: true });
  assert.equal(first.response.status, 200);
  const setCookie = first.response.headers.get("set-cookie");
  assert.match(setCookie, /^ai_shield_trusted_device=/);
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /SameSite=Strict/i);

  const secondResponse = await fetch(`${baseUrl}/api/admin/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Device-Fingerprint": first.fingerprint,
      "X-Forwarded-For": first.ip,
      Cookie: setCookie.split(";")[0],
    },
    body: JSON.stringify({ username: "admin", password: "StrongPass!234", otp: "" }),
  });
  const secondBody = await secondResponse.json();
  assert.equal(secondResponse.status, 200);
  assert.equal(secondBody.security.trustedDeviceUsed, true);
});

test("admin auth blocks an IP after 3 failed attempts and allows admin unlock", async (t) => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "ai-shield-admin-"));
  const config = buildAdminConfig(tempDir);
  const { server, baseUrl } = await startApp(config);

  t.after(() => new Promise((resolve) => server.close(resolve)));

  const blockedIp = "198.51.100.10";

  for (const expectedStatus of [401, 401, 423]) {
    const failed = await loginAdmin(baseUrl, config.adminOtpSecret, {
      ip: blockedIp,
      password: "wrong-password",
      otp: "000000",
    });
    assert.equal(failed.response.status, expectedStatus);
  }

  const stillBlocked = await loginAdmin(baseUrl, config.adminOtpSecret, {
    ip: blockedIp,
  });
  assert.equal(stillBlocked.response.status, 423);

  const admin = await loginAdmin(baseUrl, config.adminOtpSecret, {
    ip: "198.51.100.20",
    fingerprint: "device-fingerprint-beta",
  });
  assert.equal(admin.response.status, 200);

  const unlockResponse = await fetch(`${baseUrl}/api/admin/security/unlock-ip`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${admin.body.token}`,
      "Content-Type": "application/json",
      "X-Device-Fingerprint": "device-fingerprint-beta",
      "X-Forwarded-For": "198.51.100.20",
    },
    body: JSON.stringify({ ip: blockedIp }),
  });

  assert.equal(unlockResponse.status, 200);

  const postUnlock = await loginAdmin(baseUrl, config.adminOtpSecret, {
    ip: blockedIp,
    fingerprint: "device-fingerprint-gamma",
  });
  assert.equal(postUnlock.response.status, 200);
});

test("admin session rejects the wrong device fingerprint", async (t) => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "ai-shield-admin-"));
  const config = buildAdminConfig(tempDir);
  const { server, baseUrl } = await startApp(config);

  t.after(() => new Promise((resolve) => server.close(resolve)));

  const login = await loginAdmin(baseUrl, config.adminOtpSecret, {
    fingerprint: "expected-fingerprint",
  });
  assert.equal(login.response.status, 200);

  const sessionResponse = await fetch(`${baseUrl}/api/admin/auth/session`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${login.body.token}`,
      "X-Device-Fingerprint": "wrong-fingerprint",
      "X-Forwarded-For": login.ip,
    },
  });

  assert.equal(sessionResponse.status, 403);
  const sessionBody = await sessionResponse.json();
  assert.match(sessionBody.error, /device fingerprint/i);
});
