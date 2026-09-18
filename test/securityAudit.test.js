import test from "node:test";
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { analyzeContent } from "../shared/detectionEngine.js";
import { TRAINING_CORPUS } from "../shared/trainingCorpus.js";

async function scripts(directory) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const url = new URL(entry.name + (entry.isDirectory() ? "/" : ""), directory);
    if (entry.isDirectory()) result.push(...await scripts(url));
    else if (entry.name.endsWith(".js")) result.push(url);
  }
  return result;
}

test("extension and bundled shared sources contain no direct network client calls", async () => {
  // Regression guard for the current code, not a general proof against obfuscated code.
  const files = [...await scripts(new URL("../extension/", import.meta.url)), ...await scripts(new URL("../shared/", import.meta.url))];
  for (const file of files) {
    const code = await readFile(file, "utf8");
    assert.doesNotMatch(code, /\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts)\s*\(/, file.pathname);
    assert.doesNotMatch(code, /\b(?:import|export)\s+.*?from\s*["']https?:/, file.pathname);
  }
});

test("shared scores stay finite, within verdict bands, and independent of UI source", () => {
  for (const content of ["", "   ", "🙂", ...TRAINING_CORPUS.map((sample) => sample.text)]) {
    const web = analyzeContent({ content, source: "message" });
    assert.ok(Number.isInteger(web.riskScore) && web.riskScore >= 0 && web.riskScore <= 100);
    const expected = web.riskScore >= 70 ? "SCAM" : web.riskScore >= 35 ? "SUSPICIOUS" : "SAFE";
    assert.equal(web.classification, expected);
    for (const source of ["selection", "page", "screen", "email"]) {
      const other = analyzeContent({ content, source });
      assert.equal(other.riskScore, web.riskScore);
      assert.equal(other.classification, web.classification);
    }
    if (web.classification === "SAFE" && content.trim()) {
      assert.equal(web.summary, "No suspicious patterns found, but verify via official channel.");
      assert.doesNotMatch([web.summary, ...web.recommendations, ...web.explanation].join(" "), /100% safe/i);
    }
  }
});
