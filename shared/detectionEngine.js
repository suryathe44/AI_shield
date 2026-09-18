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
import { MODEL_DATA } from "./modelData.js";
import { attachFrameworkMappings } from "./frameworkMappings.js";

const LABELS = MODEL_DATA.labels;
const MODEL = {
  ...MODEL_DATA,
  tokenCounts: Object.fromEntries(
    MODEL_DATA.labels.map((label) => [label, new Map(Object.entries(MODEL_DATA.tokenCounts[label]))]),
  ),
  vocabulary: new Set([
    ...Object.keys(MODEL_DATA.tokenCounts.safe),
    ...Object.keys(MODEL_DATA.tokenCounts.scam),
  ]),
};

function softmax(logScores) {
  const maxLog = Math.max(...Object.values(logScores));
  const expScores = Object.fromEntries(
    Object.entries(logScores).map(([label, score]) => [label, Math.exp(score - maxLog)]),
  );
  const total = Object.values(expScores).reduce((sum, value) => sum + value, 0);

  return Object.fromEntries(Object.entries(expScores).map(([label, score]) => [label, score / total]));
}

function summarizeMlSignals(tokens) {
  const vocabularySize = MODEL.vocabularySize || 1;
  const uniqueTokens = Array.from(new Set(tokens)).filter((token) => MODEL.vocabulary.has(token));
  const tokenSignals = uniqueTokens
    .map((token) => {
      const scamLikelihood =
        Math.log(((MODEL.tokenCounts.scam.get(token) ?? 0) + 1) / (MODEL.totalTokens.scam + vocabularySize)) -
        Math.log(((MODEL.tokenCounts.safe.get(token) ?? 0) + 1) / (MODEL.totalTokens.safe + vocabularySize));

      return {
        token,
        impact: scamLikelihood,
      };
    })
    .filter((entry) => entry.impact > 0.25)
    .sort((left, right) => right.impact - left.impact);

  return tokenSignals.slice(0, 5).map((entry) => entry.token.replace(/_/g, " "));
}

function runMlClassifier(text) {
  const tokens = tokenize(text);
  const normalized = normalizeText(text);
  const vocabularySize = MODEL.vocabularySize || 1;
  const logScores = {};

  for (const label of LABELS) {
    const prior = (MODEL.docCounts[label] + 1) / (MODEL.totalDocs + LABELS.length);
    let score = Math.log(prior);

    for (const token of tokens) {
      if (!MODEL.vocabulary.has(token)) continue;
      const frequency = MODEL.tokenCounts[label].get(token) ?? 0;
      score += Math.log((frequency + 1) / (MODEL.totalTokens[label] + vocabularySize));
    }

    logScores[label] = score;
  }

  const probabilities = softmax(logScores);
  probabilities.suspicious = 0;
  const riskScore = Math.round(clamp(probabilities.scam * 100, 0, 100));

  return {
    probabilities,
    riskScore,
    topIndicators: summarizeMlSignals(tokens),
    negatedSafetyAdvice: /\b(?:no|never|do not|don't)\b.{0,45}\b(?:share|send|required|payment|otp|password|verification)\b/i.test(normalized),
  };
}

function buildEvidence(text, terms) {
  return terms.slice(0, 3).map((term) => ({
    label: term,
    snippet: makeSnippet(text, term),
  }));
}

function isSafetyReminder(text) {
  const normalized = normalizeText(text);
  const advisesAgainstSharing = /\b(?:never|do not|don't)\s+(?:enter|share|send|reveal)\b|\b(?:mat batana|mat bhejo|share mat|pin ya otp kisi ko mat|share na karein)\b|(?:कभी|किसी को)\s+(?:भी\s+)?(?:पिन|ओटीपी).{0,20}(?:न दें|मत बताएं|साझा न करें)/i.test(normalized);
  if (!advisesAgainstSharing) return false;
  const hasCoercion = /\b(?:urgent|immediately|kyc blocked|account band|verify now|click here|lekin|magar|however|but)\b|खाता बंद|तुरंत|[.!?]\s*(?:enter|send|share|approve|click|bhejo|batao)\b/i.test(normalized);
  return !hasCoercion && extractUrls(text).length === 0;
}

const BRAND_DOMAINS = Object.freeze({
  amazon: ["amazon.com", "amazon.in"],
  google: ["google.com"],
  hdfc: ["hdfcbank.com"],
  icici: ["icicibank.com"],
  microsoft: ["microsoft.com"],
  paypal: ["paypal.com"],
  paytm: ["paytm.com"],
  sbi: ["sbi.co.in"],
});

function detectSenderMismatch(text) {
  const header = String(text).split(/\r?\n/, 1)[0];
  const match = header.match(/^(?:from:\s*)?["']?([^<"']+?)["']?\s*<[^@<>\s]+@([^<>\s]+)>/i);
  if (!match) return null;
  const displayName = normalizeText(match[1]);
  const senderDomain = stripSubdomain(match[2].toLowerCase().replace(/[>,;].*$/, ""));
  const brand = Object.keys(BRAND_DOMAINS).find((name) => displayName.includes(name));
  if (!brand || BRAND_DOMAINS[brand].some((domain) => senderDomain === domain || senderDomain.endsWith(`.${domain}`))) {
    return null;
  }
  return {
    id: "sender_domain_mismatch",
    label: "Sender identity mismatch",
    weight: 24,
    reason: `The display name claims ${brand}, but the sender domain is ${senderDomain}.`,
    evidence: [{ label: `${match[1].trim()} <…@${senderDomain}>`, snippet: safePreview(header, 120) }],
  };
}

function detectRules(text, safetyReminder = false) {
  const normalized = normalizeText(text);
  const urls = extractUrls(text);
  const hits = [];
  const senderMismatch = detectSenderMismatch(text);
  if (senderMismatch) hits.push(senderMismatch);

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
  if (credentialTerms.length > 0 && !safetyReminder) {
    hits.push({
      id: "credential_request",
      label: "Credential request",
      weight: 24,
      reason: "The content asks for secrets like passwords, OTPs, or verification codes.",
      evidence: buildEvidence(text, credentialTerms),
    });
  }

  const paymentTerms = findMatchedTerms(normalized, KEYWORD_GROUPS.payments);
  if (paymentTerms.length > 0 && !safetyReminder) {
    hits.push({
      id: "payment_redirection",
      label: "High-risk payment request",
      weight: 20,
      reason: "The sender requests payment through channels that are commonly abused in scams.",
      evidence: buildEvidence(text, paymentTerms),
    });
  }

  const receiveClaim = /\b(?:receive|refund|lottery|prize|cashback|paise milenge|paisa milega)\b|पैसे मिलेंगे|इनाम/i.test(normalized);
  const collectAction = /\b(?:upi pin|approve (?:the |this )?collect request|scan (?:the |this )?qr|qr scan)\b|यूपीआई पिन|कलेक्ट रिक्वेस्ट/i.test(normalized);
  if (receiveClaim && collectAction && !safetyReminder) {
    hits.push({
      id: "upi_collect_deception",
      label: "UPI receive-money deception",
      weight: 30,
      reason: "The message links receiving money or a prize to a UPI PIN, collect approval, or QR scan. Verify independently before acting.",
      evidence: [{ label: "UPI receive-money request", snippet: safePreview(text, 120) }],
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

  const identityTerms = findMatchedTerms(normalized, [
    "aadhaar", "aadhar", "pan card", "date of birth", "bank details", "card number", "payment screenshot",
  ]);
  if (identityTerms.length > 0) {
    hits.push({
      id: "sensitive_data_request",
      label: "Sensitive personal-data request",
      weight: 18,
      reason: "The message requests identity, banking, or payment evidence that can be abused for fraud.",
      evidence: buildEvidence(text, identityTerms),
    });
  }

  const opportunityTerms = findMatchedTerms(normalized, [
    "guaranteed return", "guaranteed profit", "daily income", "work from home", "task job", "trading group",
  ]);
  if (opportunityTerms.length > 0) {
    hits.push({
      id: "fraudulent_opportunity",
      label: "High-risk opportunity claim",
      weight: 17,
      reason: "The message uses unrealistic job or investment claims commonly seen in advance-fee scams.",
      evidence: buildEvidence(text, opportunityTerms),
    });
  }

  return hits;
}

function detectBehaviorSignals(text, safetyReminder = false) {
  return BEHAVIOR_SIGNALS.flatMap((signal) => {
    if (safetyReminder && ["credential_harvest", "payment_pressure"].includes(signal.id)) return [];
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

  if (ruleHits.some((hit) => hit.id === "upi_collect_deception")) {
    recommendations.push("Do not enter a UPI PIN or approve a collect request to receive money. Check the transaction in your own UPI app.");
  }

  if (classification === "SCAM") {
    recommendations.push("Do not click links, open attachments, reply, or send money.");
    recommendations.push("Verify the request using a trusted channel you already know.");
    recommendations.push("Report the message to your security team or platform immediately.");
  } else if (classification === "SUSPICIOUS") {
    recommendations.push("Pause before acting and verify the sender independently.");
    recommendations.push("Avoid sharing passwords, OTPs, payment details, or confidential data.");
  } else {
    recommendations.push("Verify via an official channel before sharing sensitive information or making payments.");
  }

  if (ruleHits.some((hit) => hit.id === "credential_request")) {
    recommendations.push("Never share one-time codes or passwords through messages.");
  }

  if (ruleHits.some((hit) => hit.id === "payment_redirection")) {
    recommendations.push("Confirm any payment request with a known phone number or official portal.");
  }

  return dedupeBy(recommendations, (item) => item).slice(0, 4);
}

function classifyRisk(riskScore, ruleHits, behaviorHits, mlResult) {
  const strongCombination =
    ruleHits.some((hit) => hit.id === "suspicious_link") &&
    ruleHits.some((hit) => hit.id === "credential_request");
  const paymentAndUrgency =
    ruleHits.some((hit) => hit.id === "payment_redirection") &&
    (ruleHits.some((hit) => hit.id === "threat_based_compliance") ||
      behaviorHits.some((hit) => ["urgency_pressure", "fear_tactics", "secrecy_pressure"].includes(hit.id)));
  const credentialPressure =
    ruleHits.some((hit) => hit.id === "credential_request") &&
    behaviorHits.some((hit) => ["urgency_pressure", "fear_tactics", "fake_authority"].includes(hit.id));
  const advanceFeeOpportunity =
    ruleHits.some((hit) => hit.id === "fraudulent_opportunity") &&
    ruleHits.some((hit) => hit.id === "payment_redirection");
  const upiReceiveDeception = ruleHits.some((hit) => hit.id === "upi_collect_deception");

  if (
    riskScore >= CLASSIFICATION_THRESHOLDS.scam ||
    strongCombination ||
    paymentAndUrgency ||
    credentialPressure ||
    advanceFeeOpportunity ||
    upiReceiveDeception ||
    (mlResult.probabilities.scam > 0.8 && ruleHits.length > 0 && !mlResult.negatedSafetyAdvice && !mlResult.suppressed)
  ) {
    return "SCAM";
  }

  if (
    riskScore >= CLASSIFICATION_THRESHOLDS.suspicious ||
    (mlResult.probabilities.scam > 0.45 && !mlResult.negatedSafetyAdvice && !mlResult.suppressed) ||
    ruleHits.length >= 2
  ) {
    return "SUSPICIOUS";
  }

  return "SAFE";
}

function buildConfidence(riskScore, ruleHits, behaviorHits, mlResult) {
  const evidenceCount = ruleHits.length + behaviorHits.length;
  const thresholdDistance = Math.min(
    Math.abs(riskScore - CLASSIFICATION_THRESHOLDS.suspicious),
    Math.abs(riskScore - CLASSIFICATION_THRESHOLDS.scam),
  );
  const modelCertainty = Math.max(...Object.values(mlResult.probabilities));
  const score = Math.round(clamp(42 + evidenceCount * 8 + thresholdDistance * 0.7 + modelCertainty * 15, 0, 99));
  return {
    score,
    level: score >= 80 ? "HIGH" : score >= 60 ? "MEDIUM" : "LOW",
    evidenceCount,
  };
}

export function analyzeContent({ content, source = "message" }) {
  const original = String(content ?? "").trim();

  if (!original) {
    return attachFrameworkMappings({
      source,
      classification: "SAFE",
      riskScore: 0,
      confidence: { score: 100, level: "HIGH", evidenceCount: 0 },
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
    });
  }

  const safetyReminder = isSafetyReminder(original);
  const ruleHits = detectRules(original, safetyReminder);
  const behaviorHits = detectBehaviorSignals(original, safetyReminder);
  const mlResult = runMlClassifier(original);
  if (safetyReminder) {
    mlResult.riskScore = 0;
    mlResult.topIndicators = [];
    mlResult.suppressed = true;
  } else if (ruleHits.length === 0 && behaviorHits.length === 0 && tokenize(original).length <= 60) {
    // Short, evidence-free text is outside the email-trained model's reliable
    // domain; do not turn a bare transaction receipt into a fraud warning.
    mlResult.riskScore = Math.min(mlResult.riskScore, 34);
    mlResult.topIndicators = [];
    mlResult.suppressed = true;
  }
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
  if (ruleHits.some((hit) => hit.id === "credential_request") && behaviorHits.some((hit) => ["urgency_pressure", "fear_tactics", "fake_authority"].includes(hit.id))) {
    combinationBonus += 16;
  }
  if (ruleHits.some((hit) => hit.id === "fraudulent_opportunity") && ruleHits.some((hit) => hit.id === "payment_redirection")) {
    combinationBonus += 16;
  }
  if (ruleHits.some((hit) => hit.id === "sensitive_data_request") && (extractUrls(original).length > 0 || behaviorHits.some((hit) => hit.id === "fake_authority"))) {
    combinationBonus += 12;
  }

  const rawRiskScore = Math.round(
    clamp(ruleScore * 0.5 + behaviorScore * 0.24 + mlResult.riskScore * 0.26 + combinationBonus, 0, 100),
  );
  const classification = classifyRisk(rawRiskScore, ruleHits, behaviorHits, mlResult);
  const riskScore = classification === "SCAM"
    ? Math.max(CLASSIFICATION_THRESHOLDS.scam, rawRiskScore)
    : classification === "SUSPICIOUS"
      ? Math.max(CLASSIFICATION_THRESHOLDS.suspicious, rawRiskScore)
      : Math.min(CLASSIFICATION_THRESHOLDS.suspicious - 1, rawRiskScore);

  const explanation = [];

  if (ruleHits.length > 0) {
    explanation.push(...ruleHits.slice(0, 3).map((hit) => hit.reason));
  }
  if (behaviorHits.length > 0) {
    explanation.push(...behaviorHits.slice(0, 2).map((hit) => hit.reason));
  }
  if (classification !== "SAFE" && mlResult.topIndicators.length > 0) {
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
        : "No suspicious patterns found, but verify via official channel.";

  return attachFrameworkMappings({
    source,
    classification,
    riskScore,
    confidence: buildConfidence(riskScore, ruleHits, behaviorHits, mlResult),
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
  });
}
