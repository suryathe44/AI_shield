import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, readFile } from "node:fs/promises";
import { createAiShieldApp } from "../src/app.js";
import { FeedbackStore, calculateFeedbackMetrics } from "../src/services/feedbackStore.js";
import { PostgresFeedbackStore } from "../src/services/postgresFeedbackStore.js";
import { createPasswordHash, generateBase32Secret, generateTotpCode } from "../src/utils/adminSecurity.js";

async function fixture(t, overrides = {}) {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "ai-shield-feedback-"));
  const otpSecret = generateBase32Secret();
  const config = {
    host: "127.0.0.1", port: 0, masterKey: "feedback-test-key", adminUsername: "admin",
    adminPasswordHash: createPasswordHash("StrongPass!234"), adminOtpSecret: otpSecret,
    adminIpWhitelist: ["*"], adminFailedLoginLimit: 3, adminSessionTtlMs: 1_800_000,
    adminIdleTimeoutMs: 900_000, adminAuthPerMinute: 100, adminPerMinute: 100,
    feedbackPerMinute: 100, analyzePerMinute: 100, rateLimitWindowMs: 60_000,
    maxBodyBytes: 32_000, logFilePath: path.join(tempDir, "logs.enc"),
    feedbackFilePath: path.join(tempDir, "feedback.json"), allowedOrigins: [], ...overrides,
  };
  const app = createAiShieldApp(config);
  await new Promise((resolve) => app.server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => app.server.close(resolve)));
  return { ...app, config, otpSecret, baseUrl: `http://127.0.0.1:${app.server.address().port}` };
}

async function postFeedback(baseUrl, body) {
  const response = await fetch(`${baseUrl}/api/feedback`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  return { response, body: await response.json() };
}

async function adminHeaders(baseUrl, secret) {
  const fingerprint = "feedback-admin-device";
  const login = await fetch(`${baseUrl}/api/admin/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Device-Fingerprint": fingerprint },
    body: JSON.stringify({ username: "admin", password: "StrongPass!234", otp: generateTotpCode(secret) }),
  });
  const payload = await login.json();
  assert.equal(login.status, 200);
  return { Authorization: `Bearer ${payload.token}`, "X-Device-Fingerprint": fingerprint };
}

test("1. accepts valid feedback and returns a collision-resistant reference", async (t) => {
  const { baseUrl } = await fixture(t);
  const result = await postFeedback(baseUrl, { rating: 5, category: "Useful", comment: "Clear result" });
  assert.equal(result.response.status, 201);
  assert.match(result.body.feedbackId, /^FB-[0-9A-F]{12}$/);
});

test("2. accepts an empty optional comment", async (t) => {
  const { baseUrl } = await fixture(t);
  const result = await postFeedback(baseUrl, { rating: 4, category: "Other" });
  assert.equal(result.response.status, 201);
});

test("3. rejects a rating below 1", async (t) => {
  const { baseUrl } = await fixture(t);
  assert.equal((await postFeedback(baseUrl, { rating: 0, category: "Useful" })).response.status, 400);
});

test("4. rejects a rating above 5", async (t) => {
  const { baseUrl } = await fixture(t);
  assert.equal((await postFeedback(baseUrl, { rating: 6, category: "Useful" })).response.status, 400);
});

test("5. rejects a non-integer rating", async (t) => {
  const { baseUrl } = await fixture(t);
  assert.equal((await postFeedback(baseUrl, { rating: 4.5, category: "Useful" })).response.status, 400);
});

test("6. rejects an unknown category", async (t) => {
  const { baseUrl } = await fixture(t);
  assert.equal((await postFeedback(baseUrl, { rating: 3, category: "Security Incident" })).response.status, 400);
});

test("7. rejects comments over 500 characters", async (t) => {
  const { baseUrl } = await fixture(t);
  assert.equal((await postFeedback(baseUrl, { rating: 3, category: "Other", comment: "x".repeat(501) })).response.status, 400);
});

test("8. rejects a non-string comment", async (t) => {
  const { baseUrl } = await fixture(t);
  assert.equal((await postFeedback(baseUrl, { rating: 3, category: "Other", comment: { text: "no" } })).response.status, 400);
});

test("9. stores only the feedback allowlist and drops unexpected sensitive fields", async (t) => {
  const { baseUrl, config } = await fixture(t);
  await postFeedback(baseUrl, { rating: 2, category: "Confusing", comment: "Needs context", email: "user@example.com", messageContent: "secret OTP" });
  const records = JSON.parse(await readFile(config.feedbackFilePath, "utf8"));
  assert.deepEqual(Object.keys(records[0]).sort(), ["category", "comment", "createdAt", "id", "rating"]);
  assert.doesNotMatch(JSON.stringify(records), /user@example|secret OTP/);
});

test("10. keeps feedback separate from encrypted audit logs", async (t) => {
  const { baseUrl, config } = await fixture(t);
  await postFeedback(baseUrl, { rating: 5, category: "Useful", comment: "Good" });
  await assert.rejects(readFile(config.logFilePath, "utf8"), { code: "ENOENT" });
});

test("11. calculates rating, category, false-positive and false-negative metrics", () => {
  const metrics = calculateFeedbackMetrics([
    { rating: 1, category: "False Positive" }, { rating: 5, category: "False Negative" },
  ]);
  assert.deepEqual(metrics, { totalFeedback: 2, averageRating: 3, ratingCounts: { 1: 1, 2: 0, 3: 0, 4: 0, 5: 1 }, categoryCounts: { "False Positive": 1, "False Negative": 1 }, falsePositiveReports: 1, falseNegativeReports: 1 });
});

test("12. reads newest feedback first", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "ai-shield-feedback-store-"));
  const store = new FeedbackStore({ filePath: path.join(tempDir, "feedback.json") });
  const first = await store.append({ rating: 1, category: "Other", comment: "first" });
  const second = await store.append({ rating: 2, category: "Useful", comment: "second" });
  assert.deepEqual((await store.getAdminView()).feedback.map(({ id }) => id), [second.id, first.id]);
});

test("13. protects the admin feedback endpoint", async (t) => {
  const { baseUrl } = await fixture(t);
  const response = await fetch(`${baseUrl}/api/admin/feedback`, {
    headers: { "X-Device-Fingerprint": "unauthenticated-device" },
  });
  assert.equal(response.status, 401);
});

test("14. authenticated admin retrieval returns records, metrics, and storage limits", async (t) => {
  const { baseUrl, otpSecret } = await fixture(t);
  await postFeedback(baseUrl, { rating: 5, category: "Feature Request", comment: "Export metrics" });
  const response = await fetch(`${baseUrl}/api/admin/feedback`, { headers: await adminHeaders(baseUrl, otpSecret) });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.feedback.length, 1);
  assert.equal(payload.metrics.totalFeedback, 1);
  assert.deepEqual(payload.storage, { durableOnRender: false, type: "local-file" });
});

test("15. PostgreSQL store persists feedback and reports durable Render storage", async () => {
  const queries = [];
  const createdAt = "2026-08-30T06:00:00.000Z";
  const pool = {
    async query(sql, parameters) {
      queries.push({ sql, parameters });
      if (sql.includes("INSERT INTO")) {
        return { rows: [{ id: parameters[0], rating: parameters[1], category: parameters[2], comment: parameters[3], createdAt }] };
      }
      if (sql.includes("SELECT id")) {
        return { rows: [{ id: "FB-ABCDEF123456", rating: "5", category: "Useful", comment: "Clear", createdAt }] };
      }
      return { rows: [] };
    },
    async end() {},
  };
  const store = new PostgresFeedbackStore({ pool });

  const record = await store.append({ rating: 5, category: "Useful", comment: "Clear" });
  const adminView = await store.getAdminView();

  assert.match(record.id, /^FB-[0-9A-F]{12}$/);
  assert.deepEqual(queries[1].parameters.slice(1), [5, "Useful", "Clear"]);
  assert.equal(adminView.metrics.averageRating, 5);
  assert.deepEqual(adminView.storage, { durableOnRender: true, type: "postgresql" });
  assert.equal(queries.filter(({ sql }) => sql.includes("CREATE TABLE")).length, 1);
});
