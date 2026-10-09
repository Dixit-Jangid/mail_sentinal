/**
 * Advanced Fraud-Pattern Detection Service
 * Detects 5 major email fraud archetypes:
 *  1. Payment diversion (wire rerouting, banking changes, cryptocurrency, escrow diversion)
 *  2. Fake invoice (unsolicited invoices, overdue notices, PO manipulation, billing scams)
 *  3. Credential harvesting (login lures, quota exhaustion, password resets, MFA fatigue)
 *  4. Executive impersonation (CEO/VIP fraud, "Are you at your desk?", confidential requests)
 *  5. BEC patterns (Vendor Email Compromise, payroll redirection, internal account takeover spoofing)
 */

export const FRAUD_ARCHETYPES = {
  PAYMENT_DIVERSION: {
    key: "payment_diversion",
    title: "Payment Diversion & Wire Redirection",
    mitreTechnique: "T1566 / T1534 (Financial Fraud / Account Rerouting)",
    severity: "CRITICAL",
    description: "Tactics attempting to divert vendor disbursements, settlement wires, or supplier payments to fraudulent accounts.",
    patterns: [
      /wire\s+transfer/i,
      /bank\s+account\s+(?:details|information|number)/i,
      /swift(?:\s+code)?/i,
      /iban/i,
      /routing\s+number/i,
      /update(?:\s+our|\s+my)?\s+banking(?:\s+details|\s+info)?/i,
      /change(?:\s+of)?\s+payment\s+method/i,
      /remittance\s+instructions/i,
      /new\s+(?:bank\s+)?account\s+details/i,
      /payment\s+redirect/i,
      /direct\s+deposit\s+update/i,
      /beneficiary\s+bank/i,
      /escrow\s+(?:transfer|reroute)/i,
      /bitcoin|btc|usdt|ethereum|crypto\s+wallet/i,
      /settlement\s+funds/i,
    ],
    countermeasures: [
      "Enforce mandatory dual-custody voice callback verification to verified vendor phone numbers before modifying bank details.",
      "Verify SWIFT/IBAN changes against pre-authorized accounts payable master record.",
      "Quarantine any message requesting urgent banking modification.",
    ],
  },

  FAKE_INVOICE: {
    key: "fake_invoice",
    title: "Fake Invoice & Billing Extortion",
    mitreTechnique: "T1566.001 (Spearphishing Attachment / Fake Document)",
    severity: "HIGH",
    description: "Deceptive billing statements, past-due balance threats, or unverified purchase orders designed to coerce immediate financial settlement.",
    patterns: [
      /invoice\s+(?:attached|enclosed|#|no|number)/i,
      /overdue\s+invoice/i,
      /past\s+due\s+(?:balance|account|notice)/i,
      /unpaid\s+(?:statement|invoice|balance)/i,
      /remittance\s+advice/i,
      /billing\s+statement/i,
      /purchase\s+order\s+(?:#|no|\d+)/i,
      /\binv[-_]?\d{3,}/i,
      /invoice\s+receipt/i,
      /outstanding\s+balance/i,
      /tax\s+invoice/i,
      /payment\s+confirmation\s+receipt/i,
      /attached\s+(?:pdf|statement|doc|spreadsheet)/i,
      /fees\s+will\s+apply\s+if\s+unpaid/i,
    ],
    countermeasures: [
      "Cross-reference PO and invoice numbers against internal ERP / procurement systems before authorizing payment.",
      "Do not open invoice attachments (.pdf, .xlsm, .iso, .zip) without gateway sandbox detonation.",
      "Check vendor domain syntax for missing letters or subtle character substitutions.",
    ],
  },

  CREDENTIAL_HARVESTING: {
    key: "credential_harvesting",
    title: "Credential Harvesting & Account Takeover",
    mitreTechnique: "T1566.002 / T1598 (Phishing for Information & Session Hijacking)",
    severity: "CRITICAL",
    description: "Deceptive portals, session expiration notices, or password validation lures crafted to capture employee credentials or session cookies.",
    patterns: [
      /verify\s+your\s+(?:account|identity|credentials)/i,
      /confirm\s+(?:your\s+)?password/i,
      /update\s+(?:your\s+)?credentials/i,
      /re-?authenticate/i,
      /login\s+to\s+(?:review|continue|verify)/i,
      /click\s+here\s+to\s+(?:unlock|verify|access)/i,
      /mailbox\s+(?:storage|quota)\s+(?:exceeded|full|limit)/i,
      /session\s+expired/i,
      /security\s+verification\s+required/i,
      /reset\s+(?:your\s+)?(?:password|credentials)/i,
      /validate\s+(?:your\s+)?account/i,
      /sign\s+in\s+(?:below|here|now)/i,
      /keep\s+same\s+password/i,
      /microsoft\s+365\s+security\s+alert/i,
      /google\s+workspace\s+action\s+required/i,
    ],
    countermeasures: [
      "Do not enter passwords on external landing pages linked via email.",
      "Deploy FIDO2 / WebAuthn hardware security keys to immunize against reverse-proxy phishing kits.",
      "Immediately reset user credentials and revoke active OAuth tokens if a link was clicked.",
    ],
  },

  EXECUTIVE_IMPERSONATION: {
    key: "executive_impersonation",
    title: "Executive Impersonation (CEO / VIP Fraud)",
    mitreTechnique: "T1534 / T1589 (Internal Spearphishing & Identity Spoofing)",
    severity: "HIGH",
    description: "Impersonation of senior corporate leadership requesting confidential assistance, urgent out-of-band favors, or financial transfers.",
    patterns: [
      /are\s+you\s+at\s+your\s+desk/i,
      /need\s+a\s+quick\s+favor/i,
      /in\s+a\s+meeting(?:\s+cannot\s+talk)?/i,
      /confidential\s+(?:project|request|acquisition)/i,
      /send\s+me\s+your\s+(?:cell|mobile|phone)\s+number/i,
      /purchase\s+(?:apple|google|amazon|itunes)?\s*gift\s*cards/i,
      /handle\s+this\s+discreetly/i,
      /available\s+right\s+now/i,
      /sent\s+from\s+my\s+iphone/i,
      /per\s+my\s+(?:confidential\s+)?instructions/i,
      /do\s+not\s+call\s+me/i,
      /urgent\s+task\s+for\s+you/i,
    ],
    countermeasures: [
      "Establish out-of-band verification policies for any financial or confidential request originating from executive names.",
      "Configure mail gateway display-name protection filters for all C-suite and VIP employee names.",
      "Never purchase or transmit gift cards or wire funds based on email instructions alone.",
    ],
  },

  BEC_PATTERNS: {
    key: "bec_patterns",
    title: "Business Email Compromise (BEC & VEC)",
    mitreTechnique: "T1566 / T1598 (Vendor Email Compromise & Thread Hijacking)",
    severity: "HIGH",
    description: "Complex social engineering targeting corporate operational workflows, thread hijacking, or payroll redirection.",
    patterns: [
      /payroll\s+(?:update|change|reroute|deposit)/i,
      /re:\s*re:\s*urgent/i,
      /our\s+auditors\s+require/i,
      /revised\s+(?:contract|terms|payment\s+schedule)/i,
      /updated\s+vendor\s+information/i,
      /w-?2\s+(?:forms|request)/i,
      /direct\s+deposit\s+slip/i,
      /confidential\s+settlement\s+agreement/i,
      /transfer\s+authorization/i,
      /wire\s+approval/i,
    ],
    countermeasures: [
      "Verify unexpected payroll deposit modifications through HR self-service portals rather than email.",
      "Examine full email routing headers for sudden Reply-To changes in long-running email threads.",
      "Block external auto-forwarding rules on employee Microsoft 365 / Google mailboxes.",
    ],
  },
};

/**
 * Extracts snippet context around a matched regex.
 */
function extractSnippet(text, match) {
  if (!text || !match) return "";
  const index = match.index || 0;
  const matchLen = match[0]?.length || 0;
  const start = Math.max(0, index - 40);
  const end = Math.min(text.length, index + matchLen + 40);
  const prefix = start > 0 ? "..." : "";
  const suffix = end < text.length ? "..." : "";
  return `${prefix}${text.substring(start, end).trim()}${suffix}`;
}

/**
 * Deep inspection of email text and metadata for advanced fraud patterns.
 */
export function detectAdvancedFraudPatterns({
  subject = "",
  bodyText = "",
  replyToMismatch = false,
  displayNameSpoofing = false,
  dangerousAttachmentsCount = 0,
}) {
  const combined = `${subject}\n${bodyText}`;
  const patternsFound = [];

  for (const [code, archetype] of Object.entries(FRAUD_ARCHETYPES)) {
    const matchedPhrases = [];
    const snippets = [];

    for (const regex of archetype.patterns) {
      const match = combined.match(regex);
      if (match) {
        matchedPhrases.push(match[0]);
        snippets.push(extractSnippet(combined, match));
      }
    }

    // Contextual boost factors
    let status = "CLEAN";
    let scoreImpact = 0;

    if (matchedPhrases.length > 0) {
      if (matchedPhrases.length >= 2 || (code === "PAYMENT_DIVERSION" && replyToMismatch)) {
        status = "DETECTED";
        scoreImpact = archetype.severity === "CRITICAL" ? 35 : 25;
      } else {
        status = "SUSPECTED";
        scoreImpact = archetype.severity === "CRITICAL" ? 20 : 15;
      }
    } else if (code === "EXECUTIVE_IMPERSONATION" && displayNameSpoofing) {
      status = "DETECTED";
      scoreImpact = 30;
      matchedPhrases.push("Display Name Spoofing");
      snippets.push("Adversary mimicking internal VIP display identity.");
    } else if (code === "CREDENTIAL_HARVESTING" && dangerousAttachmentsCount > 0) {
      status = "SUSPECTED";
      scoreImpact = 20;
    }

    patternsFound.push({
      key: archetype.key,
      title: archetype.title,
      code,
      status,
      severity: archetype.severity,
      mitreTechnique: archetype.mitreTechnique,
      description: archetype.description,
      matchedCount: matchedPhrases.length,
      matchedPhrases: Array.from(new Set(matchedPhrases)),
      snippets: Array.from(new Set(snippets)).slice(0, 3),
      countermeasures: archetype.countermeasures,
      scoreImpact: status === "CLEAN" ? 0 : scoreImpact,
    });
  }

  const detectedCount = patternsFound.filter((p) => p.status === "DETECTED").length;
  const suspectedCount = patternsFound.filter((p) => p.status === "SUSPECTED").length;
  const totalFraudScore = patternsFound.reduce((acc, p) => acc + p.scoreImpact, 0);

  return {
    patterns: patternsFound,
    hasActiveFraud: detectedCount > 0,
    detectedCount,
    suspectedCount,
    totalFraudScore: Math.min(totalFraudScore, 60),
    summary: detectedCount > 0
      ? `${detectedCount} critical fraud pattern(s) confirmed: ${patternsFound.filter((p) => p.status === "DETECTED").map((p) => p.title).join(", ")}`
      : suspectedCount > 0
      ? `${suspectedCount} suspicious fraud indicator(s) identified.`
      : "No advanced fraud signatures detected.",
  };
}
