import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp } from "node:fs/promises";
import { createAiShieldApp } from "../src/app.js";

test("POST /api/analyze returns explainable scam analysis", async (t) => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "ai-shield-api-"));
  const { server } = createAiShieldApp({
    host: "127.0.0.1",
    port: 0,
    masterKey: "test-master-key",
    logFilePath: path.join(tempDir, "logs.enc"),
    allowedOrigins: ["http://127.0.0.1:3000"],
  });

  await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });

  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/api/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      content:
        "Final warning: your mailbox is disabled today. Open www.mail-authentication.click and verify your password now.",
      consent: {
        process: true,
        storeLog: false,
      },
    }),
  });

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.ok(["SUSPICIOUS", "SCAM"].includes(body.analysis.classification));
  assert.ok(body.analysis.explanation.length > 0);
  assert.equal(body.privacy.thirdPartySharing, false);
});

test("POST /api/analyze/screen/capture uses the OCR service and returns extracted text", async (t) => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "ai-shield-api-"));
  const { server } = createAiShieldApp({
    host: "127.0.0.1",
    port: 0,
    masterKey: "test-master-key",
    logFilePath: path.join(tempDir, "logs.enc"),
    allowedOrigins: ["http://127.0.0.1:3000"],
    ocrService: {
      async extractTextFromDataUrl() {
        return {
          engine: "mock-ocr",
          lineCount: 2,
          text: "Urgent bank alert\nverify your password now",
        };
      },
    },
  });

  await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });

  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/api/analyze/screen/capture`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      imageDataUrl: "data:image/png;base64,AAAA",
      consent: {
        process: true,
        screenScan: true,
        storeLog: false,
      },
    }),
  });

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.ocr.engine, "mock-ocr");
  assert.equal(body.extractedText, "Urgent bank alert verify your password now");
  assert.ok(["SUSPICIOUS", "SCAM"].includes(body.analysis.classification));
});
