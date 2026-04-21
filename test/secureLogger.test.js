import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, readFile } from "node:fs/promises";
import { SecureLogger } from "../src/services/secureLogger.js";

test("SecureLogger encrypts at rest and supports deletion", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "ai-shield-"));
  const logFilePath = path.join(tempDir, "logs.enc");
  const logger = new SecureLogger({
    logFilePath,
    masterKey: "test-master-key",
  });

  await logger.ensureReady();

  const receipt = await logger.appendLog({
    analysis: {
      classification: "SCAM",
      riskScore: 91,
      explanation: ["Credential harvesting attempt detected."],
      factors: {
        rules: [{ label: "Credential request" }],
        behaviors: [{ label: "Urgency pressure" }],
      },
    },
    content: "Send me your OTP and password immediately.",
    source: "message",
    consent: {
      storeLog: true,
      persistContentSnippet: true,
    },
    actorHint: "user-123",
    metadata: {
      sessionId: "session-1",
    },
  });

  const rawFile = await readFile(logFilePath, "utf8");
  assert.ok(!rawFile.includes("password"));
  assert.ok(receipt.id);

  const logs = await logger.readAllLogs();
  assert.equal(logs.length, 1);
  assert.equal(logs[0].classification, "SCAM");
  assert.match(logs[0].snippet, /OTP/i);

  const deleted = await logger.deleteLog(receipt.id);
  assert.equal(deleted, true);
  assert.equal((await logger.readAllLogs()).length, 0);
});