import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp } from "node:fs/promises";
import { createAiShieldApp } from "../src/app.js";
import {
  createPasswordHash,
  generateBase32Secret,
  generateTotpCode,
} from "../src/utils/adminSecurity.js";

function buildAdminConfig(tempDir, overrides = {}) {
  const otpSecret = overrides.adminOtpSecret ?? generateBase32Secret();
  return {
    host: "127.0.0.1",
    port: 0,
    masterKey: "test-master-key",
    adminUsername: "admin",
    adminPasswordHash: createPasswordHash("StrongPass!234"),
    adminOtpSecret: otpSecret,
    adminIpWhitelist: ["*"],
    adminFailedLoginLimit: 3,
    adminSessionTtlMs: 30 * 60_000,
    adminIdleTimeoutMs: 15 * 60_000,
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
      otp: options.otp ?? generateTotpCode(otpSecret),
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