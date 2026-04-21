import test from "node:test";
import assert from "node:assert/strict";
import { analyzeContent } from "../shared/detectionEngine.js";

test("AI Shield flags obvious credential phishing as SCAM", () => {
  const analysis = analyzeContent({
    content:
      "URGENT: Your bank account will be frozen today. Click http://verify-bank-login.top and enter your password and OTP immediately.",
  });

  assert.equal(analysis.classification, "SCAM");
  assert.ok(analysis.riskScore >= 75);
  assert.ok(analysis.explanation.some((entry) => entry.includes("passwords") || entry.includes("OTP")));
});

test("AI Shield keeps normal benign content in SAFE range", () => {
  const analysis = analyzeContent({
    content: "Can we move tomorrow's engineering sync to 11 AM? I updated the calendar invite.",
  });

  assert.equal(analysis.classification, "SAFE");
  assert.ok(analysis.riskScore < 35);
});

test("AI Shield identifies gift-card impersonation as suspicious or worse", () => {
  const analysis = analyzeContent({
    content: "I'm in a meeting. Keep this confidential and buy gift cards right now, then send me the codes.",
  });

  assert.ok(["SUSPICIOUS", "SCAM"].includes(analysis.classification));
  assert.ok(analysis.highlights.some((item) => item.label.toLowerCase().includes("gift card")));
});