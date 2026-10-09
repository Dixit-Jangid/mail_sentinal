/**
 * AI/ML Threat Classification Service
 * Multi-class probabilistic inference engine for email security forensics.
 * Classifies emails across 5 distinct target classes:
 *  - Legitimate: Authorized, standard communications with valid authentication and no deception.
 *  - Suspicious: Unverified or unusual anomalies, social engineering triggers, or low-trust routing.
 *  - Impersonated: Display name spoofing, domain lookalikes, executive VIP coercion, or Reply-To traps.
 *  - Phishing: Malicious credential harvesting, fake login portals, weaponized links, or toxic attachments.
 *  - Fraud: Financial wire diversion, fake invoices, BEC scams, or payroll rerouting.
 */

export const THREAT_CLASSES = [
  "Legitimate",
  "Suspicious",
  "Impersonated",
  "Phishing",
  "Fraud",
];

export const CLASS_METADATA = {
  Legitimate: {
    label: "Legitimate Communication",
    color: "#16a34a",
    bgColor: "#dcfce7",
    borderColor: "#86efac",
    badge: "BENIGN",
    description: "Verified domain cryptographic alignment, authentic headers, and neutral communicative intent.",
  },
  Suspicious: {
    label: "Suspicious Traffic",
    color: "#d97706",
    bgColor: "#fef3c7",
    borderColor: "#fcd34d",
    badge: "ANOMALOUS",
    description: "Contains urgency anomalies, unverified sender routing, or unclassified linguistic pressure.",
  },
  Impersonated: {
    label: "Identity Impersonation",
    color: "#ea580c",
    bgColor: "#ffedd5",
    borderColor: "#fdba74",
    badge: "SPOOFED",
    description: "Header forgery, executive identity impersonation, display name mismatch, or lookalike domain.",
  },
  Phishing: {
    label: "Credential Phishing",
    color: "#dc2626",
    bgColor: "#fee2e2",
    borderColor: "#fca5a5",
    badge: "MALICIOUS",
    description: "Targeted attempts to harvest credentials, session tokens, or install dangerous payloads.",
  },
  Fraud: {
    label: "Financial Fraud / BEC",
    color: "#9333ea",
    bgColor: "#f3e8ff",
    borderColor: "#d8b4fe",
    badge: "FRAUDULENT",
    description: "Business Email Compromise, invoice manipulation, bank account redirection, or wire fraud.",
  },
};

/**
 * Multi-vector feature extractor and classifier.
 */
export function classifyEmailThreat({
  spf = "Unknown",
  dkim = "Unknown",
  dmarc = "Unknown",
  protocolAudit = {},
  nlpAudit = {},
  fraudPatterns = [],
  suspiciousLinksCount = 0,
  dangerousAttachmentsCount = 0,
  totalUrlsCount = 0,
  domainIntel = {},
  originGeo = {},
  isTorExitNode = false,
  hopTrace = {},
}) {
  // Raw class logit accumulators
  let logits = {
    Legitimate: 10,
    Suspicious: 5,
    Impersonated: 2,
    Phishing: 2,
    Fraud: 2,
  };

  const featureContributions = [];

  const addScore = (cls, points, reason, category = "General") => {
    logits[cls] += points;
    featureContributions.push({ class: cls, points, reason, category });
  };

  // 1. Authentication & Protocol Vector
  const authPass = spf === "Pass" && dkim === "Pass";
  const authFail = spf === "Fail" || dkim === "Fail" || dmarc === "Fail";

  if (authPass && !protocolAudit.replyToMismatch && !protocolAudit.displayNameSpoofing) {
    addScore("Legitimate", 35, "Cryptographic SPF and DKIM authentication verified with domain alignment", "Authentication");
  } else if (authFail) {
    addScore("Suspicious", 20, "Failed SPF/DKIM/DMARC authentication checks", "Authentication");
    addScore("Impersonated", 25, "Cryptographic alignment failure suggests forged origin identity", "Authentication");
  }

  // 2. Reply-To and Return-Path Traps
  if (protocolAudit.replyToMismatch) {
    addScore("Impersonated", 35, "Reply-To header is diverted to a disparate domain", "Header Forensics");
    addScore("Fraud", 20, "Channel redirection typical of BEC wire interception", "Header Forensics");
    logits.Legitimate = Math.max(0, logits.Legitimate - 25);
  }

  if (protocolAudit.displayNameSpoofing) {
    addScore("Impersonated", 45, `Display name spoofing detected (${protocolAudit.fromName})`, "Identity");
    addScore("Phishing", 15, "Display name mimicry used to deceive recipient", "Identity");
    logits.Legitimate = Math.max(0, logits.Legitimate - 30);
  }

  // 3. Domain & Infrastructure Intel
  if (domainIntel?.typosquattingDetected) {
    addScore("Impersonated", 40, `Typosquatted domain mimicking ${domainIntel.typosquattingTarget}`, "Domain Intel");
    addScore("Phishing", 30, "Lookalike domain deployed for deceptive interaction", "Domain Intel");
    logits.Legitimate = 0;
  }

  if (domainIntel?.isNewlyRegistered) {
    addScore("Suspicious", 25, `Newly registered domain (<${domainIntel.ageInDays || 30} days old)`, "Domain Intel");
    addScore("Phishing", 20, "Fresh domain infrastructure typical of disposable phishing kits", "Domain Intel");
  }

  if (domainIntel && domainIntel.hasMx === false && domainIntel.isRegistered) {
    addScore("Suspicious", 20, "Sender domain lacks valid inbound MX mail exchangers", "Domain Intel");
  }

  // 4. IP & Routing Forensics
  if (isTorExitNode) {
    addScore("Suspicious", 35, "Transmitted through authenticated Tor Project exit node", "Network Intel");
    addScore("Fraud", 25, "Adversary employing onion routing to evade legal attribution", "Network Intel");
    logits.Legitimate = Math.max(0, logits.Legitimate - 30);
  }

  if (originGeo?.isVpn || originGeo?.isProxy) {
    addScore("Suspicious", 18, `Anonymized connection detected: ${originGeo.vpnType || "VPN/Proxy"}`, "Network Intel");
  }

  if (hopTrace?.isRelayManipulated) {
    addScore("Suspicious", 22, "Mail-hop relay manipulation or clock retrograde anomaly detected", "Header Forensics");
  }

  // 5. Fraud Pattern Detection Vector
  const detectedFraudTypes = Array.isArray(fraudPatterns)
    ? fraudPatterns.filter((p) => p.status === "DETECTED")
    : [];

  const paymentDiversion = detectedFraudTypes.find((p) => p.key === "payment_diversion");
  const fakeInvoice = detectedFraudTypes.find((p) => p.key === "fake_invoice");
  const credentialHarvesting = detectedFraudTypes.find((p) => p.key === "credential_harvesting");
  const executiveImpersonation = detectedFraudTypes.find((p) => p.key === "executive_impersonation");
  const becPatterns = detectedFraudTypes.find((p) => p.key === "bec_patterns");

  if (paymentDiversion) {
    addScore("Fraud", 50, "Wire diversion, account change, or banking rerouting cues identified", "Fraud Pattern");
    logits.Legitimate = 0;
  }

  if (fakeInvoice) {
    addScore("Fraud", 40, "Fake billing statement, overdue demand, or unsolicited invoice pattern", "Fraud Pattern");
    addScore("Phishing", 15, "Invoice used as lure vector", "Fraud Pattern");
    logits.Legitimate = Math.max(0, logits.Legitimate - 20);
  }

  if (credentialHarvesting) {
    addScore("Phishing", 50, "Credential capture, re-authentication lure, or password reset coercion", "Fraud Pattern");
    logits.Legitimate = 0;
  }

  if (executiveImpersonation) {
    addScore("Impersonated", 45, "VIP executive coercion, confidential request, or urgent favor language", "Fraud Pattern");
    addScore("Fraud", 25, "Executive authority utilized to force unauthorized action", "Fraud Pattern");
    logits.Legitimate = Math.max(0, logits.Legitimate - 25);
  }

  if (becPatterns) {
    addScore("Fraud", 45, "Vendor Email Compromise (VEC) or business workflow compromise pattern", "Fraud Pattern");
    logits.Legitimate = 0;
  }

  // 6. Suspicious Payloads & Links
  if (dangerousAttachmentsCount > 0) {
    addScore("Phishing", 50, `${dangerousAttachmentsCount} executable/script payload attachments detected`, "Payloads");
    logits.Legitimate = 0;
  }

  if (suspiciousLinksCount > 0) {
    addScore("Phishing", Math.min(suspiciousLinksCount * 20, 50), `${suspiciousLinksCount} malicious or deceptive URLs identified`, "Payloads");
    logits.Legitimate = Math.max(0, logits.Legitimate - 20);
  } else if (totalUrlsCount > 0 && authPass) {
    addScore("Legitimate", 5, "Embedded hyperlinks comply with normal communicative layout", "Payloads");
  }

  // 7. Linguistic Urgency & Threat Signals
  if (nlpAudit?.urgencyScore > 20) {
    addScore("Suspicious", 20, "High psychological urgency and artificial time-constraint triggers", "NLP");
  }

  // Softmax normalization to compute probabilities [0, 100]%
  const expValues = {};
  let sumExp = 0;
  // Scaled temperature for smooth distribution
  const temperature = 18;

  for (const cls of THREAT_CLASSES) {
    const raw = Math.max(0, logits[cls]);
    const exp = Math.exp(raw / temperature);
    expValues[cls] = exp;
    sumExp += exp;
  }

  const distribution = {};
  for (const cls of THREAT_CLASSES) {
    distribution[cls] = Math.round((expValues[cls] / sumExp) * 100);
  }

  // Ensure sum equals 100
  const currentSum = Object.values(distribution).reduce((a, b) => a + b, 0);
  const diff = 100 - currentSum;
  // Adjust highest class by the diff
  let maxCls = THREAT_CLASSES[0];
  let maxProb = -1;
  for (const cls of THREAT_CLASSES) {
    if (distribution[cls] > maxProb) {
      maxProb = distribution[cls];
      maxCls = cls;
    }
  }
  distribution[maxCls] += diff;

  // Primary Classification & Confidence
  const primaryClass = maxCls;
  const confidence = distribution[primaryClass];

  // Rationale synthesis
  const topReasons = featureContributions
    .filter((f) => f.class === primaryClass)
    .sort((a, b) => b.points - a.points)
    .slice(0, 3)
    .map((f) => f.reason);

  const rationale = topReasons.length > 0
    ? topReasons.join(". ") + "."
    : CLASS_METADATA[primaryClass].description;

  return {
    primaryClass,
    confidence,
    distribution,
    metadata: CLASS_METADATA[primaryClass],
    featureContributions,
    rationale,
    isThreat: primaryClass !== "Legitimate",
    severity: primaryClass === "Legitimate"
      ? "SAFE"
      : primaryClass === "Suspicious"
      ? "MEDIUM"
      : "CRITICAL",
  };
}
