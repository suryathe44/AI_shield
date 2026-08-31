import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { createCipheriv, randomBytes, scryptSync } from "node:crypto";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
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
  const envelope = JSON.parse(rawFile);
  assert.ok(!rawFile.includes("password"));
  assert.equal(envelope.version, 2);
  assert.equal((await stat(logFilePath)).mode & 0o777, 0o600);
  assert.ok(receipt.id);

  const logs = await logger.readAllLogs();
  assert.equal(logs.length, 1);
  assert.equal(logs[0].classification, "SCAM");
  assert.match(logs[0].snippet, /OTP/i);

  const deleted = await logger.deleteLog(receipt.id);
  assert.equal(deleted, true);
  assert.equal((await logger.readAllLogs()).length, 0);
});

test("SecureLogger reads and migrates the legacy encrypted envelope", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "ai-shield-legacy-"));
  const logFilePath = path.join(tempDir, "logs.enc");
  const masterKey = "legacy-test-master-key";
  const key = scryptSync(masterKey, "ai-shield-secure-log", 32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update("[]", "utf8"), cipher.final()]);
  const legacyEnvelope = {
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
  await writeFile(logFilePath, JSON.stringify(legacyEnvelope), "utf8");

  const logger = new SecureLogger({ logFilePath, masterKey });
  assert.deepEqual(await logger.readAllLogs(), []);
  await logger.deleteAll();
  assert.equal(JSON.parse(await readFile(logFilePath, "utf8")).version, 2);
});
