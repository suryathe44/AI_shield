import test from "node:test";
import assert from "node:assert/strict";
import { analyzeContent } from "../shared/detectionEngine.js";
import { UrlReputationService, applyUrlReputation } from "../src/services/urlReputationService.js";

test("URL reputation sends only extracted URLs and upgrades known threats", async () => {
  let requestedUrl;
  const service = new UrlReputationService({
    apiKey: "test-key",
    fetchImpl: async (url) => {
      requestedUrl = new URL(url);
      return {
        ok: true,
        async json() {
          return { threats: [{ url: "https://bad.example/login", threatTypes: ["SOCIAL_ENGINEERING"] }] };
        },
      };
    },
  });
  const reputation = await service.checkContent("Secret message text https://bad.example/login");
  const analysis = applyUrlReputation(analyzeContent({ content: "Visit https://bad.example/login" }), reputation);

  assert.deepEqual(requestedUrl.searchParams.getAll("urls"), ["https://bad.example/login"]);
  assert.doesNotMatch(requestedUrl.toString(), /Secret message text/);
  assert.equal(analysis.classification, "SCAM");
  assert.ok(analysis.riskScore >= 95);
  assert.equal(analysis.factors.internetReputation.checked, true);
});

test("URL reputation fails open to local analysis when the provider is unavailable", async () => {
  const service = new UrlReputationService({
    apiKey: "test-key",
    fetchImpl: async () => { throw new Error("offline"); },
  });
  const local = analyzeContent({ content: "Please review https://example.com later." });
  const reputation = await service.checkContent("Please review https://example.com later.");
  const enriched = applyUrlReputation(local, reputation);

  assert.equal(reputation.unavailable, true);
  assert.equal(enriched.classification, local.classification);
  assert.equal(enriched.riskScore, local.riskScore);
});

test("URL reputation remains disabled without an API key", async () => {
  const reputation = await new UrlReputationService().checkContent("https://example.com");
  assert.equal(reputation.configured, false);
  assert.equal(reputation.checked, false);
});
