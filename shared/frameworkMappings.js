const MITRE_ATTACK_VERSION = "19.1";
const MITRE_F3_VERSION = "1.1";

const ATTACK = Object.freeze({
  maliciousAttachment: {
    id: "T1566.001",
    name: "Phishing: Spearphishing Attachment",
    tactic: "initial-access",
  },
  maliciousLink: {
    id: "T1566.002",
    name: "Phishing: Spearphishing Link",
    tactic: "initial-access",
  },
  phishingForInformation: {
    id: "T1598",
    name: "Phishing for Information",
    tactic: "reconnaissance",
  },
  remoteAccess: {
    id: "T1219",
    name: "Remote Access Software",
    tactic: "command-and-control",
  },
});

const F3 = Object.freeze({
  phishing: {
    id: "T1660",
    name: "Phishing",
    tactic: "initial-access",
    source: "attack-reused-by-f3",
  },
  phishingForInformation: {
    id: "T1598",
    name: "Phishing for Information",
    tactic: "reconnaissance",
    source: "attack-reused-by-f3",
  },
  impersonateOfficial: {
    id: "F1032",
    name: "Impersonate Official",
    tactic: "initial-access",
    source: "f3-native",
  },
  fakeWebsite: {
    id: "F1020.002",
    name: "Create Fake Materials: Fake Website",
    tactic: "resource-development",
    source: "f3-native",
  },
  wireTransfer: {
    id: "F1025.003",
    name: "Electronic Funds Transfer: Wire Transfer",
    tactic: "monetization",
    source: "f3-native",
  },
  remoteAccess: {
    id: "T1219",
    name: "Remote Access Tools",
    tactic: "positioning",
    source: "attack-reused-by-f3",
  },
});

function includesEvidence(rule, term) {
  return rule?.evidence?.some((item) => String(item.label).toLowerCase() === term) ?? false;
}

function addMapping(collection, technique, evidence) {
  if (collection.some((entry) => entry.id === technique.id)) {
    return;
  }

  collection.push({
    ...technique,
    confidence: "candidate",
    evidence,
  });
}

export function attachFrameworkMappings(analysis) {
  const rules = Array.isArray(analysis?.factors?.rules) ? analysis.factors.rules : [];
  const behaviors = Array.isArray(analysis?.factors?.behaviors) ? analysis.factors.behaviors : [];
  const ruleById = new Map(rules.map((rule) => [rule.id, rule]));
  const behaviorIds = new Set(behaviors.map((behavior) => behavior.id));
  const reputation = analysis?.factors?.internetReputation;
  const confirmedThreatTypes = new Set(
    reputation?.matches?.flatMap((match) => match.threatTypes ?? []) ?? [],
  );
  const nonSafe = analysis?.classification === "SCAM" || analysis?.classification === "SUSPICIOUS";
  const attack = [];
  const f3 = [];

  if (nonSafe && (ruleById.has("suspicious_link") || reputation?.matches?.length > 0)) {
    addMapping(
      attack,
      ATTACK.maliciousLink,
      reputation?.matches?.length > 0
        ? "Internet reputation confirmed an unsafe URL."
        : "Suspicious link indicators were detected in the submitted content.",
    );
    addMapping(f3, F3.phishing, "The content uses an electronic link-based phishing pattern.");
  }

  if (nonSafe && ruleById.has("malicious_attachment_pattern")) {
    addMapping(
      attack,
      ATTACK.maliciousAttachment,
      "The content directs the recipient to open or enable potentially malicious content.",
    );
    addMapping(f3, F3.phishing, "The content uses an electronic phishing-delivery pattern.");
  }

  const credentialPressure = ruleById.has("credential_request") && (
    ruleById.has("suspicious_link")
    || behaviorIds.has("fake_authority")
    || behaviorIds.has("urgency_pressure")
    || behaviorIds.has("fear_tactics")
  );
  if (nonSafe && credentialPressure) {
    addMapping(
      attack,
      ATTACK.phishingForInformation,
      "The content attempts to obtain credentials or verification secrets through social engineering.",
    );
    addMapping(
      f3,
      F3.phishingForInformation,
      "The content requests credentials, OTPs, or other actionable sensitive information.",
    );
  }

  const officialImpersonation = behaviorIds.has("fake_authority") && (
    ruleById.has("credential_request")
    || ruleById.has("payment_redirection")
    || ruleById.has("sensitive_data_request")
    || ruleById.has("threat_based_compliance")
  );
  if (nonSafe && officialImpersonation) {
    addMapping(
      f3,
      F3.impersonateOfficial,
      "An authority or institution is invoked alongside a sensitive request or threat.",
    );
  }

  if (nonSafe && ruleById.has("remote_access_request")) {
    addMapping(attack, ATTACK.remoteAccess, "The recipient is asked to install or use remote-access software.");
    addMapping(f3, F3.remoteAccess, "Remote-access tooling is requested as part of the suspected fraud flow.");
  }

  const paymentRule = ruleById.get("payment_redirection");
  if (nonSafe && includesEvidence(paymentRule, "wire transfer")) {
    addMapping(f3, F3.wireTransfer, "The content explicitly requests a wire transfer.");
  }

  if (nonSafe && confirmedThreatTypes.has("SOCIAL_ENGINEERING")) {
    addMapping(
      f3,
      F3.fakeWebsite,
      "Internet reputation classified a submitted URL as social engineering.",
    );
  }

  return {
    ...analysis,
    mitre_attack_id: attack[0]?.id ?? null,
    f3_technique: f3[0]?.id ?? null,
    frameworkMappings: {
      mappingType: "candidate-technique",
      disclaimer: "Mappings describe message evidence and do not prove successful compromise or fraud.",
      mitreAttackVersion: MITRE_ATTACK_VERSION,
      mitreF3Version: MITRE_F3_VERSION,
      mitreAttack: attack,
      mitreF3: f3,
    },
  };
}
