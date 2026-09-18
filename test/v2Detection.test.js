import test from "node:test";
import assert from "node:assert/strict";
import { stat, readFile } from "node:fs/promises";
import { analyzeContent } from "../shared/detectionEngine.js";

test("v2 embedded model stays below the 500 KB research limit", async () => {
  const model = new URL("../research/v2/model.json", import.meta.url);
  assert.ok((await stat(model)).size < 500_000);
  const parsed = JSON.parse(await readFile(model, "utf8"));
  assert.equal(parsed.training.split, "stratified-80-20");
  assert.equal(parsed.training.trainPerClass, 800);
});

test("URL lexical signals cover IP, punycode, shortener, and risky TLD", () => {
  for (const url of ["http://198.51.100.4/login", "https://xn--paypl-4ve.example", "https://bit.ly/check", "https://account-check.top/login"]) {
    const result = analyzeContent({ content: `Verify your account at ${url}` });
    assert.ok(result.factors.rules.some((rule) => rule.id === "suspicious_link"), url);
  }
});

test("known-brand display name with unrelated sender domain is flagged", () => {
  const result = analyzeContent({ content: "From: Paytm Support <help@unrelated-example.net>\nYour monthly notice." });
  assert.ok(result.factors.rules.some((rule) => rule.id === "sender_domain_mismatch"));
});

test("known-brand display name with its official domain is not mismatched", () => {
  const result = analyzeContent({ content: "From: Paytm Support <help@paytm.com>\nYour monthly notice." });
  assert.ok(!result.factors.rules.some((rule) => rule.id === "sender_domain_mismatch"));
});

test("Devanagari UPI scam language is tokenized and warned on", () => {
  const result = analyzeContent({ content: "खाता बंद होगा। तुरंत यूपीआई पिन भेजो और पैसे भेजो।" });
  assert.notEqual(result.classification, "SAFE");
});

test("UPI collect request framed as receiving money is treated as a scam", () => {
  const result = analyzeContent({ content: "To receive your ₹5,000 refund, enter your UPI PIN and approve this collect request." });
  assert.equal(result.classification, "SCAM");
  assert.ok(result.factors.rules.some((rule) => rule.id === "upi_collect_deception"));
  assert.ok(result.recommendations.some((item) => item.includes("UPI PIN")));
});

test("UPI receipt and safety reminders do not trigger a fraud verdict", () => {
  for (const content of [
    "You have received ₹500 from Riya via UPI. Transaction successful.",
    "Security reminder: never share an OTP with anyone.",
    "UPI payment receipt mil gayi, dhanyavaad. PIN ya OTP kisi ko mat batana.",
    "Never enter your UPI PIN to receive money. Ignore collect requests from strangers.",
  ]) {
    assert.equal(analyzeContent({ content }).classification, "SAFE", content);
  }
});

test("a warning preface cannot conceal a later UPI PIN request", () => {
  const result = analyzeContent({ content: "Never share OTP. Enter your UPI PIN to receive your refund now." });
  assert.notEqual(result.classification, "SAFE");
});
