import fs from "node:fs";
import crypto from "node:crypto";
import { performance } from "node:perf_hooks";
import { analyzeContent } from "../shared/detectionEngine.js";

const root = new URL("../", import.meta.url);
const out = new URL("v2/", import.meta.url);
const split = JSON.parse(fs.readFileSync(new URL("v2/nazario_split.json", import.meta.url), "utf8"));

function makeSynthetic(language, positive) {
  const rows = [];
  const brands = language === "hi" ? ["Paytm", "SBI", "HDFC", "PhonePe"] : ["Barclays", "Chase", "HSBC", "Citibank"];
  for (let i = 0; i < 200; i += 1) {
    const brand = brands[i % brands.length];
    let text;
    if (positive && language === "hi") {
      const asks = ["UPI PIN share karo", "OTP turant bhejo", "QR scan karke processing fee bhejo", "lottery claim ke liye UPI payment karo"];
      const threats = ["KYC blocked hai", "account band ho jayega", "खाता बंद होगा", "अभी verify karo"];
      const links = ["http://paytm-kyc.top/verify", "https://xn--paytm-9za.example/login", "https://bit.ly/kyc-help", "http://198.51.100.42/pay"];
      text = `From: ${brand} Support <help${i}@alerts-example.com>\n${threats[i % 4]}. ${asks[(i * 3) % 4]}. ${links[(i * 5) % 4]} Ref ${1000 + i}`;
    } else if (positive) {
      const asks = ["send your OTP immediately", "confirm your password", "open the attachment and enable macros", "pay the urgent processing fee"];
      const threats = ["your banking account is locked", "unauthorized login detected", "funds will be frozen", "final security warning"];
      const links = ["http://secure-bank.top/login", "https://xn--bank-9za.example/verify", "https://tinyurl.com/bank-check", "http://203.0.113.17/auth"];
      text = `From: ${brand} Security <case${i}@notice-example.net>\n${threats[i % 4]}; ${asks[(i * 3) % 4]} at ${links[(i * 5) % 4]}. Case ${2000 + i}`;
    } else if (language === "hi") {
      const bodies = ["Kal ki meeting 3 baje confirm hai", "Aapka monthly statement official app mein available hai", "Maa ko call kar dena jab ghar pahucho", "UPI payment receipt mil gayi, dhanyavaad"];
      text = `${brand} note ${3000 + i}: ${bodies[i % bodies.length]}. Koi PIN ya OTP share mat karein.`;
    } else {
      const bodies = ["Your monthly statement is available in the official banking app", "The branch appointment is confirmed for Tuesday", "Thanks, the invoice was received and reconciled", "Security reminder: never share an OTP with anyone"];
      text = `${brand} notice ${4000 + i}: ${bodies[i % bodies.length]}.`;
    }
    rows.push({ id: `${language}-${positive ? "scam" : "safe"}-${i + 1}`, language, label: positive ? "scam" : "safe", text });
  }
  return rows;
}

const synthetic = [
  ...makeSynthetic("hi", true), ...makeSynthetic("hi", false),
  ...makeSynthetic("en", true), ...makeSynthetic("en", false),
];
fs.writeFileSync(new URL("v2/synthetic_scam_test.json", import.meta.url), JSON.stringify(synthetic, null, 2));

function evaluate(rows) {
  const predictions = [];
  const latencies = [];
  // Exclude one-time JIT/module warm-up from steady-state per-message latency.
  for (const row of rows.slice(0, 25)) analyzeContent({ content: row.text, source: "research-v2-warmup" });
  for (const row of rows) {
    const started = performance.now();
    const analysis = analyzeContent({ content: row.text, source: "research-v2" });
    latencies.push(performance.now() - started);
    predictions.push({
      id: row.id, language: row.language ?? "en", actual: row.label,
      predicted: analysis.classification === "SAFE" ? "safe" : "scam",
      classification: analysis.classification, riskScore: analysis.riskScore,
      mlProbability: analysis.factors.machineLearning.probabilities.scam,
    });
  }
  const sorted = [...latencies].sort((a, b) => a - b);
  return { predictions, latencyMedianMs: sorted[Math.floor(sorted.length / 2)], latencyP95Ms: sorted[Math.floor(sorted.length * 0.95)] };
}

const nazario = evaluate(split.test);
const scamOnly = evaluate(synthetic);
const hashes = {};
for (const name of ["../data/Nazario_5.csv", "../data/uci-sms/SMSSpamCollection", "model.json", "synthetic_scam_test.json"]) {
  const bytes = fs.readFileSync(new URL(name, out));
  hashes[name.split("/").pop()] = crypto.createHash("sha256").update(bytes).digest("hex");
}
fs.writeFileSync(new URL("v2/predictions_v2.json", import.meta.url), JSON.stringify({ nazario, synthetic: scamOnly }));
fs.writeFileSync(new URL("v2/evaluation_manifest.json", import.meta.url), JSON.stringify({ hashes, node: process.version }, null, 2));
console.log(JSON.stringify({ nazarioMedianMs: nazario.latencyMedianMs, syntheticMedianMs: scamOnly.latencyMedianMs, hashes }));
