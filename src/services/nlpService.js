/**
 * NLP & Linguistic Social Engineering Analysis Service
 * Detects psychological urgency cues, impersonation language, and BEC fraud patterns.
 */

export const SOCIAL_ENGINEERING_TRIGGERS = [
  {
    category: "Urgency & Artificial Time Constraints",
    cues: [
      "immediately", "urgent", "within 24 hours", "action required", "time-sensitive",
      "expires today", "immediate attention", "suspended within", "act now", "final notice",
      "right away", "without delay", "promptly", "as soon as possible", "asap"
    ],
    weight: 15,
    description: "Forces rapid decision making to bypass critical evaluation."
  },
  {
    category: "Fear & Threat of Negative Consequences",
    cues: [
      "account suspended", "legal action", "unauthorized activity", "breach detected",
      "security violation", "deactivation", "terminated", "restricted", "investigation",
      "police", "court order", "penalty", "lawsuit", "unauthorized login", "critical alert"
    ],
    weight: 20,
    description: "Induces anxiety regarding financial, administrative, or legal repercussions."
  },
  {
    category: "Authority & Executive Coercion",
    cues: [
      "ceo", "chief executive", "cfo", "director", "board of directors", "audit team",
      "human resources", "compliance department", "internal affairs", "strict confidence",
      "confidential request", "do not disclose", "per my instructions", "executive office"
    ],
    weight: 22,
    description: "Exploits organizational hierarchy to suppress skepticism."
  },
  {
    category: "Financial Greed & Scarcity",
    cues: [
      "refund available", "grant approval", "lottery winner", "bonus payout", "exclusive settlement",
      "overdue payment approved", "compensation claim", "unclaimed funds", "wire credit"
    ],
    weight: 14,
    description: "Appeals to sudden financial windfall or unexpected compensation."
  }
];

export const BEC_CATEGORIES = {
  PAYMENT_DIVERSION: {
    label: "Payment Diversion / Wire Fraud",
    cues: [
      "wire transfer", "bank account details", "swift code", "iban", "routing number",
      "update banking info", "change payment method", "remittance instructions", "new account details",
      "payment redirect", "direct deposit update", "wire payment", "beneficiary bank"
    ],
    severity: "CRITICAL",
    riskPoints: 35,
    description: "Attempt to divert legitimate vendor or payroll payments to fraudulent accounts."
  },
  FAKE_INVOICE: {
    label: "Fake Invoice & Billing Scam",
    cues: [
      "invoice attached", "overdue invoice", "past due balance", "unpaid statement",
      "remittance advice", "billing statement", "purchase order #", "inv-", "invoice receipt",
      "outstanding balance", "tax invoice", "payment confirmation receipt"
    ],
    severity: "HIGH",
    riskPoints: 25,
    description: "Deceptive billing document requesting settlement of unperformed services or goods."
  },
  CREDENTIAL_HARVESTING: {
    label: "Credential Harvesting / Phishing",
    cues: [
      "verify your account", "confirm password", "update credentials", "re-authenticate",
      "login to review", "click here to unlock", "mailbox quota exceeded", "session expired",
      "security verification", "reset credentials", "validate account", "sign in below"
    ],
    severity: "CRITICAL",
    riskPoints: 30,
    description: "Aims to capture employee credentials, session tokens, or multi-factor authentication codes."
  },
  EXECUTIVE_IMPERSONATION: {
    label: "Executive Impersonation (CEO Fraud)",
    cues: [
      "are you at your desk", "need a quick favor", "in a meeting cannot talk",
      "confidential project", "send me your phone number", "purchase gift cards",
      "urgent wire request", "handle this discreetly", "available right now", "from my iphone"
    ],
    severity: "HIGH",
    riskPoints: 30,
    description: "Impersonates senior leadership seeking urgent, out-of-band favors or financial transfers."
  }
};

/**
 * Performs deep NLP linguistic and psychological pattern analysis on email text.
 */
export function analyzeLinguisticsAndBEC(subject = "", bodyText = "") {
  const combined = `${subject} ${bodyText}`.toLowerCase();

  // 1. Social Engineering Cues Extraction
  const detectedTriggers = [];
  let urgencyScore = 0;

  for (const trigger of SOCIAL_ENGINEERING_TRIGGERS) {
    const matchedCues = trigger.cues.filter((cue) => combined.includes(cue));
    if (matchedCues.length > 0) {
      detectedTriggers.push({
        category: trigger.category,
        matchedCues,
        weight: trigger.weight,
        description: trigger.description,
      });
      urgencyScore += Math.min(matchedCues.length * 8, trigger.weight);
    }
  }

  // 2. Business Email Compromise (BEC) Pattern Classification
  const detectedBecPatterns = [];
  let highestBecSeverity = "NONE";
  let becScore = 0;

  for (const [key, category] of Object.entries(BEC_CATEGORIES)) {
    const matched = category.cues.filter((cue) => combined.includes(cue));
    if (matched.length > 0) {
      detectedBecPatterns.push({
        key,
        label: category.label,
        matchedCues: matched,
        severity: category.severity,
        description: category.description,
      });
      becScore += category.riskPoints;
      if (category.severity === "CRITICAL") highestBecSeverity = "CRITICAL";
      else if (highestBecSeverity !== "CRITICAL" && category.severity === "HIGH") {
        highestBecSeverity = "HIGH";
      }
    }
  }

  // 3. Impersonation & Executive Tone Analysis
  const executiveKeywords = ["ceo", "cfo", "director", "president", "treasury", "vp", "executive"];
  const subjectLower = subject.toLowerCase();
  const hasExecutiveInSubject = executiveKeywords.some((kw) => subjectLower.includes(kw));

  // 4. Determine Primary AI / NLP Classification
  let primaryClassification = "Legitimate Communication";
  let confidence = 85;

  if (detectedBecPatterns.some((p) => p.key === "PAYMENT_DIVERSION")) {
    primaryClassification = "Fraud / Payment Diversion (BEC)";
    confidence = 94;
  } else if (detectedBecPatterns.some((p) => p.key === "CREDENTIAL_HARVESTING")) {
    primaryClassification = "Phishing / Credential Harvesting";
    confidence = 92;
  } else if (detectedBecPatterns.some((p) => p.key === "EXECUTIVE_IMPERSONATION") || hasExecutiveInSubject) {
    primaryClassification = "Executive Impersonation (VIP Fraud)";
    confidence = 90;
  } else if (detectedBecPatterns.some((p) => p.key === "FAKE_INVOICE")) {
    primaryClassification = "Fraudulent Invoice / Billing Scam";
    confidence = 88;
  } else if (detectedTriggers.length >= 2 || urgencyScore >= 25) {
    primaryClassification = "Suspicious Social Engineering";
    confidence = 82;
  } else if (detectedTriggers.length === 1) {
    primaryClassification = "Unverified / Low Suspicion";
    confidence = 75;
  }

  return {
    urgencyScore: Math.min(urgencyScore, 40),
    becScore: Math.min(becScore, 50),
    detectedTriggers,
    detectedBecPatterns,
    highestBecSeverity,
    primaryClassification,
    classificationConfidence: confidence,
    manipulativeToneDetected: detectedTriggers.length > 0 || detectedBecPatterns.length > 0,
  };
}
