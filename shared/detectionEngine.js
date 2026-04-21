import {
  BEHAVIOR_SIGNALS,
  CLASSIFICATION_THRESHOLDS,
  KEYWORD_GROUPS,
  SUSPICIOUS_TLDS,
  URL_SHORTENERS,
} from "./constants.js";
import {
  clamp,
  dedupeBy,
  extractDomain,
  extractUrls,
  findMatchedTerms,
  makeSnippet,
  normalizeText,
  safePreview,
  stripSubdomain,
  tokenize,
} from "./textUtils.js";
import { TRAINING_CORPUS } from "./trainingCorpus.js";

const LABELS = ["safe", "suspicious", "scam"];
const MODEL = trainModel(TRAINING_CORPUS);

function trainModel(corpus) {
  const docCounts = Object.fromEntries(LABELS.map((label) => [label, 0]));
  const tokenCounts = Object.fromEntries(LABELS.map((label) => [label, new Map()]));
  const totalTokens = Object.fromEntries(LABELS.map((label) => [label, 0]));
  const vocabulary = new Set();

  for (const sample of corpus) {
    docCounts[sample.label] += 1;
    const tokens = tokenize(sample.text);

    for (const token of tokens) {
      vocabulary.add(token);
      tokenCounts[sample.label].set(token, (tokenCounts[sample.label].get(token) ?? 0) + 1);
      totalTokens[sample.label] += 1;
    }
  }

  return {
    docCounts,
    tokenCounts,
    totalDocs: corpus.length,
    totalTokens,
    vocabulary: Array.from(vocabulary),
  };
}

function softmax(logScores) {
  const maxLog = Math.max(...Object.values(logScores));
  const expScores = Object.fromEntries(
    Object.entries(logScores).map(([label, score]) => [label, Math.exp(score - maxLog)]),
  );
  const total = Object.values(expScores).reduce((sum, value) => sum + value, 0);

  return Object.fromEntries(Object.entries(expScores).map(([label, score]) => [label, score / total]));
}

function summarizeMlSignals(tokens) {
  const vocabularySize = MODEL.vocabulary.length || 1;
  const uniqueTokens = Array.from(new Set(tokens));
  const tokenSignals = uniqueTokens
    .map((token) => {
      const scamLikelihood =
        Math.log(((MODEL.tokenCounts.scam.get(token) ?? 0) + 1) / (MODEL.totalTokens.scam + vocabularySize)) -
        Math.log(((MODEL.tokenCounts.safe.get(token) ?? 0) + 1) / (MODEL.totalTokens.safe + vocabularySize));

      const suspiciousLikelihood =
        Math.log(((MODEL.tokenCounts.suspicious.get(token) ?? 0) + 1) / (MODEL.totalTokens.suspicious + vocabularySize)) -
        Math.log(((MODEL.tokenCounts.safe.get(token) ?? 0) + 1) / (MODEL.totalTokens.safe + vocabularySize));

      return {
        token,
        impact: Math.max(scamLikelihood, suspiciousLikelihood),
      };
    })
    .filter((entry) => entry.impact > 0.25)
    .sort((left, right) => right.impact - left.impact);

  return tokenSignals.slice(0, 5).map((entry) => entry.token.replace(/_/g, " "));
}

function runMlClassifier(text) {
  const tokens = tokenize(text);
  const vocabularySize = MODEL.vocabulary.length || 1;
  const logScores = {};

  for (const label of LABELS) {
    const prior = (MODEL.docCounts[label] + 1) / (MODEL.totalDocs + LABELS.length);
    let score = Math.log(prior);

    for (const token of tokens) {
      const frequency = MODEL.tokenCounts[label].get(token) ?? 0;
      score += Math.log((frequency + 1) / (MODEL.totalTokens[label] + vocabularySize));
    }

    logScores[label] = score;
  }

  const probabilities = softmax(logScores);
  const riskScore = Math.round(clamp(probabilities.scam * 100 + probabilities.suspicious * 55, 0, 100));

  return {
    probabilities,
    riskScore,
    topIndicators: summarizeMlSignals(tokens),
  };
}

function buildEvidence(text, terms) {
  return terms.slice(0, 3).map((term) => ({
    label: term,
    snippet: makeSnippet(text, term),
  }));
}

function detectRules(text) {
  const normalized = normalizeText(text);
  const urls = extractUrls(text);
  const hits = [];

  if (urls.length > 0) {
    const issues = [];

    for (const url of urls) {
      const domain = stripSubdomain(extractDomain(url));
      const tld = domain.split(".").pop() ?? "";

      if (url.startsWith("http://")) {
        issues.push(`insecure link transport (${url})`);
      }
      if (/\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(domain)) {
        issues.push(`raw IP address in link (${domain})`);
      }
      if (domain.includes("xn--")) {
        issues.push(`punycode domain (${domain})`);
      }
      if (URL_SHORTENERS.has(domain)) {
        issues.push(`link shortener (${domain})`);
      }
      if (SUSPICIOUS_TLDS.has(tld)) {
        issues.push(`high-risk TLD (${domain})`);
      }
      if (/[0-9]/.test(domain.replace(/\./g, "")) && /[a-z]/.test(domain)) {
        issues.push(`brand-like domain variation (${domain})`);
      }
    }

    if (issues.length > 0) {
      hits.push({
        id: "suspicious_link",
        label: "Suspicious link pattern",
        weight: clamp(18 + issues.length * 5, 18, 32),
        reason: `The message contains link patterns often used in phishing: ${issues.slice(0, 3).join(", ")}.`,
        evidence: urls.slice(0, 3).map((url) => ({
          label: url,
          snippet: makeSnippet(text, url),
        })),
      });
    }
  }

  const credentialTerms = findMatchedTerms(normalized, KEYWORD_GROUPS.credentials);
  if (credentialTerms.length > 0) {
    hits.push({
      id: "credential_request",
      label: "Credential request",
      weight: 24,
      reason: "The content asks for secrets like passwords, OTPs, or verification codes.",
      evidence: buildEvidence(text, credentialTerms),
    });
  }

  const paymentTerms = findMatchedTerms(normalized, KEYWORD_GROUPS.payments);
  if (paymentTerms.length > 0) {
    hits.push({
      id: "payment_redirection",
      label: "High-risk payment request",
      weight: 20,
      reason: "The sender requests payment through channels that are commonly abused in scams.",
      evidence: buildEvidence(text, paymentTerms),
    });
  }

  const remoteTerms = findMatchedTerms(normalized, KEYWORD_GROUPS.remoteAccess);
  if (remoteTerms.length > 0) {
    hits.push({
      id: "remote_access_request",
      label: "Remote access request",
      weight: 18,
      reason: "The content encourages remote access or screen control, which is a frequent tech-support scam tactic.",
      evidence: buildEvidence(text, remoteTerms),
    });
  }

  const malwareTerms = findMatchedTerms(normalized, KEYWORD_GROUPS.malware);
  if (malwareTerms.length > 0) {
    hits.push({
      id: "malicious_attachment_pattern",
      label: "Suspicious attachment instruction",
      weight: 18,
      reason: "The message tries to get the user to open files or enable risky content.",
      evidence: buildEvidence(text, malwareTerms),
    });
  }

  const threatTerms = findMatchedTerms(normalized, ["account suspended", "funds will be frozen", "legal action", "arrest warrant", "mailbox is almost disabled"]);
  if (threatTerms.length > 0) {
    hits.push({
      id: "threat_based_compliance",
      label: "Threat-based compliance",
      weight: 17,
      reason: "The sender uses account shutdown, legal, or security threats to drive immediate action.",
      evidence: buildEvidence(text, threatTerms),
    });
  }

  return hits;
}

function detectBehaviorSignals(text) {
  return BEHAVIOR_SIGNALS.flatMap((signal) => {
    const matches = findMatchedTerms(text, signal.phrases);
    if (matches.length === 0) {
      return [];
    }

    return [
      {
        ...signal,
        weight: clamp(signal.weight + matches.length * 2, signal.weight, signal.weight + 6),
        evidence: buildEvidence(text, matches),
      },
    ];
  });
}

function buildRecommendations(classification, ruleHits) {
  const recommendations = [];

  if (classification === "SCAM") {
    recommendations.push("Do not click links, open attachments, reply, or send money.");
    recommendations.push("Verify the request using a trusted channel you already know.");
    recommendations.push("Report the message to your security team or platform immediately.");
  } else if (classification === "SUSPICIOUS") {
    recommendations.push("Pause before acting and verify the sender independently.");
    recommendations.push("Avoid sharing passwords, OTPs, payment details, or confidential data.");
  } else {
    recommendations.push("No major scam indicators were found, but continue normal verification habits.");
  }

  if (ruleHits.some((hit) => hit.id === "credential_request")) {
    recommendations.push("Never share one-time codes or passwords through messages.");
  }

  if (ruleHits.some((hit) => hit.id === "payment_redirection")) {
    recommendations.push("Confirm any payment request with a known phone number or official portal.");
  }

  return dedupeBy(recommendations, (item) => item).slice(0, 4);
}

function classifyRisk(riskScore, ruleHits, mlResult) {
  const strongCombination =
    ruleHits.some((hit) => hit.id === "suspicious_link") &&
    ruleHits.some((hit) => hit.id === "credential_request");
  const paymentAndUrgency =
    ruleHits.some((hit) => hit.id === "payment_redirection") &&
    ruleHits.some((hit) => hit.id === "threat_based_compliance");

  if (
    riskScore >= CLASSIFICATION_THRESHOLDS.scam ||
    strongCombination ||
    paymentAndUrgency ||
    (mlResult.probabilities.scam > 0.8 && ruleHits.length > 0)
  ) {
    return "SCAM";
  }

  if (
    riskScore >= CLASSIFICATION_THRESHOLDS.suspicious ||
    mlResult.probabilities.scam > 0.45 ||
    ruleHits.length >= 2
  ) {
    return "SUSPICIOUS";
  }

  return "SAFE";
}

export function analyzeContent({ content, source = "message" }) {
  const original = String(content ?? "").trim();

  if (!original) {
    return {
      source,
      classification: "SAFE",
      riskScore: 0,
      summary: "No content was provided for analysis.",
      explanation: [],
      alerts: [],
      recommendations: [],
      factors: {
        machineLearning: { riskScore: 0, probabilities: { safe: 1, suspicious: 0, scam: 0 }, topIndicators: [] },
        rules: [],
        behaviors: [],
      },
      highlights: [],
      stats: { wordCount: 0, urlCount: 0 },
    };
  }

  const ruleHits = detectRules(original);
  const behaviorHits = detectBehaviorSignals(original);
  const mlResult = runMlClassifier(original);
  const ruleScore = clamp(ruleHits.reduce((sum, hit) => sum + hit.weight, 0), 0, 100);
  const behaviorScore = clamp(behaviorHits.reduce((sum, hit) => sum + hit.weight, 0), 0, 100);

  let combinationBonus = 0;
  if (ruleHits.some((hit) => hit.id === "suspicious_link") && ruleHits.some((hit) => hit.id === "credential_request")) {
    combinationBonus += 18;
  }
  if (behaviorHits.some((hit) => hit.id === "urgency_pressure") && behaviorHits.some((hit) => hit.id === "payment_pressure")) {
    combinationBonus += 12;
  }
  if (behaviorHits.some((hit) => hit.id === "fake_authority") && ruleHits.some((hit) => hit.id === "remote_access_request")) {
    combinationBonus += 10;
  }

  const riskScore = Math.round(
    clamp(ruleScore * 0.45 + behaviorScore * 0.22 + mlResult.riskScore * 0.33 + combinationBonus, 0, 100),
  );
  const classification = classifyRisk(riskScore, ruleHits, mlResult);

  const explanation = [];

  if (ruleHits.length > 0) {
    explanation.push(...ruleHits.slice(0, 3).map((hit) => hit.reason));
  }
  if (behaviorHits.length > 0) {
    explanation.push(...behaviorHits.slice(0, 2).map((hit) => hit.reason));
  }
  if (mlResult.topIndicators.length > 0) {
    explanation.push(
      `The local ML classifier associated this content with scam-related wording such as ${mlResult.topIndicators
        .slice(0, 3)
        .join(", ")}.`,
    );
  }

  const alerts =
    classification === "SCAM"
      ? ["High-risk message detected. Avoid links, credentials, payments, and direct replies."]
      : classification === "SUSPICIOUS"
        ? ["Potential scam indicators detected. Verify before you act."]
        : [];

  const highlights = dedupeBy(
    [...ruleHits, ...behaviorHits].flatMap((hit) =>
      hit.evidence.map((evidence) => ({
        type: hit.label,
        label: evidence.label,
        snippet: evidence.snippet,
        weight: hit.weight,
      })),
    ),
    (entry) => `${entry.type}:${entry.label}`,
  ).slice(0, 8);

  const summary =
    classification === "SCAM"
      ? "This content shows multiple coordinated scam indicators and should be treated as hostile."
      : classification === "SUSPICIOUS"
        ? "This content shows enough phishing or manipulation signals to warrant verification before any action."
        : "No dominant scam pattern was detected, though normal caution is still recommended.";

  return {
    source,
    classification,
    riskScore,
    summary,
    explanation: dedupeBy(explanation, (item) => item).slice(0, 6),
    alerts,
    recommendations: buildRecommendations(classification, ruleHits),
    factors: {
      machineLearning: {
        riskScore: mlResult.riskScore,
        probabilities: mlResult.probabilities,
        topIndicators: mlResult.topIndicators,
      },
      rules: ruleHits,
      behaviors: behaviorHits,
    },
    highlights,
    preview: safePreview(original, 180),
    stats: {
      wordCount: original.split(/\s+/).filter(Boolean).length,
      urlCount: extractUrls(original).length,
    },
  };
}