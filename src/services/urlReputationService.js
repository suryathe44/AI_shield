import { extractUrls } from "../../shared/textUtils.js";

export class UrlReputationService {
  constructor({ apiKey = "", timeoutMs = 2500, fetchImpl = globalThis.fetch } = {}) {
    this.apiKey = String(apiKey).trim();
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl;
  }

  async checkContent(content) {
    const urls = extractUrls(content).slice(0, 50);
    if (!this.apiKey || urls.length === 0) {
      return {
        provider: "google-safe-browsing-v5",
        configured: Boolean(this.apiKey),
        checked: false,
        checkedUrlCount: 0,
        matches: [],
      };
    }

    const endpoint = new URL("https://safebrowsing.googleapis.com/v5/urls:search");
    endpoint.searchParams.set("key", this.apiKey);
    for (const url of urls) {
      endpoint.searchParams.append("urls", url);
    }

    try {
      const response = await this.fetchImpl(endpoint, {
        method: "GET",
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (!response.ok) {
        throw new Error(`Safe Browsing returned HTTP ${response.status}`);
      }
      const payload = await response.json();
      const matches = Array.isArray(payload.threats)
        ? payload.threats.map((threat) => ({
          url: threat.url,
          threatTypes: Array.isArray(threat.threatTypes) ? threat.threatTypes : [],
        }))
        : [];
      return {
        provider: "google-safe-browsing-v5",
        configured: true,
        checked: true,
        checkedUrlCount: urls.length,
        matches,
      };
    } catch {
      return {
        provider: "google-safe-browsing-v5",
        configured: true,
        checked: false,
        checkedUrlCount: 0,
        matches: [],
        unavailable: true,
      };
    }
  }
}

export function applyUrlReputation(analysis, reputation) {
  const enriched = {
    ...analysis,
    factors: {
      ...analysis.factors,
      internetReputation: reputation,
    },
  };

  if (!reputation?.matches?.length) {
    return enriched;
  }

  const threatNames = Array.from(new Set(reputation.matches.flatMap((match) => match.threatTypes)));
  const reason = `Internet reputation identified a known unsafe URL${
    threatNames.length ? ` (${threatNames.join(", ")})` : ""
  }.`;

  return {
    ...enriched,
    classification: "SCAM",
    riskScore: Math.max(95, analysis.riskScore),
    confidence: { score: 99, level: "HIGH", evidenceCount: (analysis.confidence?.evidenceCount ?? 0) + 1 },
    summary: "A known unsafe URL was confirmed by internet reputation data. Treat this content as hostile.",
    explanation: Array.from(new Set([reason, ...analysis.explanation])).slice(0, 6),
    alerts: Array.from(new Set(["Known malicious or deceptive link detected by internet reputation verification.", ...analysis.alerts])),
    recommendations: Array.from(new Set([
      "Do not open the confirmed unsafe link; block and report the sender.",
      ...analysis.recommendations,
    ])).slice(0, 4),
  };
}
