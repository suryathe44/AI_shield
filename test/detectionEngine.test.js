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
  assert.equal(analysis.mitre_attack_id, "T1566.002");
  assert.equal(analysis.f3_technique, "T1660");
  assert.equal(analysis.frameworkMappings.mitreF3[0].source, "attack-reused-by-f3");
  assert.ok(analysis.frameworkMappings.mitreAttack.some((entry) => entry.id === "T1598"));
  assert.ok(analysis.frameworkMappings.mitreF3.some((entry) => entry.id === "F1032"));
});

test("AI Shield keeps normal benign content in SAFE range", () => {
  const analysis = analyzeContent({
    content: "Can we move tomorrow's engineering sync to 11 AM? I updated the calendar invite.",
  });

  assert.equal(analysis.classification, "SAFE");
  assert.ok(analysis.riskScore < 35);
  assert.equal(analysis.mitre_attack_id, null);
  assert.equal(analysis.f3_technique, null);
  assert.deepEqual(analysis.frameworkMappings.mitreAttack, []);
  assert.deepEqual(analysis.frameworkMappings.mitreF3, []);
});

test("AI Shield identifies gift-card impersonation as suspicious or worse", () => {
  const analysis = analyzeContent({
    content: "I'm in a meeting. Keep this confidential and buy gift cards right now, then send me the codes.",
  });

  assert.ok(["SUSPICIOUS", "SCAM"].includes(analysis.classification));
  assert.ok(analysis.highlights.some((item) => item.label.toLowerCase().includes("gift card")));
});

test("AI Shield catches Hinglish KYC phishing with a defanged URL", () => {
  const analysis = analyzeContent({
    content: "SBI KYC update pending. Aaj hi hxxp://sbi-kyc[.]top open karke OTP aur card PIN enter karo warna account block ho jayega.",
  });
  assert.equal(analysis.classification, "SCAM");
  assert.ok(analysis.riskScore >= 70);
  assert.ok(analysis.stats.urlCount >= 1);
  assert.equal(analysis.confidence.level, "HIGH");
});

test("word-boundary matching does not treat known as urgency term now", () => {
  const analysis = analyzeContent({
    content: "The known issue is fixed now. No payment or account verification is required.",
  });
  assert.equal(analysis.classification, "SAFE");
  assert.equal(analysis.factors.behaviors.length, 0);
});

test("AI Shield catches advance-fee job scams", () => {
  const analysis = analyzeContent({
    content: "Work from home job confirmed. Registration fee bhejo, QR scan karo aur daily income guaranteed hai.",
  });
  assert.ok(["SUSPICIOUS", "SCAM"].includes(analysis.classification));
  assert.ok(analysis.factors.rules.some((rule) => rule.id === "fraudulent_opportunity"));
});

test("AI Shield maps explicit wire-transfer fraud without claiming completed theft", () => {
  const analysis = analyzeContent({
    content: "CEO request: keep this confidential and make an urgent wire transfer immediately.",
  });

  assert.ok(["SUSPICIOUS", "SCAM"].includes(analysis.classification));
  assert.ok(analysis.frameworkMappings.mitreF3.some((entry) => entry.id === "F1025.003"));
  assert.equal(
    analysis.frameworkMappings.mitreF3.find((entry) => entry.id === "F1025.003").source,
    "f3-native",
  );
  assert.equal(analysis.frameworkMappings.mappingType, "candidate-technique");
  assert.match(analysis.frameworkMappings.disclaimer, /do not prove/i);
});

test("a benign use of the word account does not receive framework mappings", () => {
  const analysis = analyzeContent({
    content: "The accounting team confirmed the monthly report is ready for review.",
  });

  assert.equal(analysis.classification, "SAFE");
  assert.equal(analysis.mitre_attack_id, null);
  assert.equal(analysis.f3_technique, null);
});
