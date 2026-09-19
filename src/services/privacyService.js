/**
 * Privacy and Data Protection Compliance Service (DPDP / GDPR / ISO 27701 / HIPAA)
 * Provides multi-field PII redaction, configurable retention policies,
 * and sensitive-data handling compliance frameworks.
 */

export const RETENTION_POLICIES = [
  { id: "30_days", label: "30 Days (Triage / Incident Quarantine)", days: 30, description: "Standard operational triage retention." },
  { id: "90_days", label: "90 Days (Corporate SOC Standard)", days: 90, description: "Recommended for internal corporate incident audits." },
  { id: "180_days", label: "180 Days (PCI-DSS / Regulatory Review)", days: 180, description: "Extended retention for payment security compliance." },
  { id: "365_days", label: "1 Year (Legal Hold & Compliance)", days: 365, description: "Preserved for ongoing litigation or compliance reporting." },
  { id: "2555_days", label: "7 Years (Law Enforcement / ISO 27037)", days: 2555, description: "Statutory criminal forensics preservation period." },
  { id: "ephemeral", label: "Ephemeral / Zero-Retention (Volatile Only)", days: 0, description: "No server persistence; wiped immediately upon session close." },
];

export const COMPLIANCE_FRAMEWORKS = [
  { code: "GDPR_ART_32", name: "EU GDPR Article 32 & 17", badge: "GDPR COMPLIANT", description: "Security of processing and right to erasure through configurable automated data purging." },
  { code: "DPDP_ACT_2023", name: "India DPDP Act 2023", badge: "DPDP COMPLIANT", description: "Section 8 compliance for reasonable security safeguards and personal data obfuscation." },
  { code: "ISO_27701", name: "ISO/IEC 27701 PIMS", badge: "ISO 27701", description: "Privacy Information Management System controls for digital evidence handling." },
  { code: "HIPAA_SECURITY", name: "HIPAA Security Rule", badge: "HIPAA COMPLIANT", description: "Safeguards electronic protected health information (ePHI) from unmasked exposure." },
];

/**
 * Masks an email address: e.g. "john.doe@company.com" -> "j***e@company.com"
 */
export function maskEmail(email) {
  if (!email || typeof email !== "string") return email;
  return email.replace(/([a-zA-Z0-9_\-.+]+)@([a-zA-Z0-9-.]+)/g, (_, user, domain) => {
    if (user.length <= 2) {
      return `${user[0] || "*"}***@${domain}`;
    }
    return `${user[0]}***${user[user.length - 1]}@${domain}`;
  });
}

/**
 * Masks an IP address: e.g. "198.51.100.24" -> "198.51.***.***"
 */
export function maskIP(ip) {
  if (!ip || typeof ip !== "string") return ip;
  return ip.replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, "$1.$2.***.***");
}

/**
 * Masks phone numbers: e.g. "+1-555-123-4567" -> "+1-***-***-4567"
 */
export function maskPhone(phone) {
  if (!phone || typeof phone !== "string") return phone;
  return phone.replace(/(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?(\d{4})/g, "$1***-***-$2");
}

/**
 * Masks credit card or bank account sequences: e.g. "4532 1234 5678 9012" -> "****-****-****-9012"
 */
export function maskFinancial(text) {
  if (!text || typeof text !== "string") return text;
  return text.replace(/\b(?:\d[ -]*?){13,16}\b/g, (match) => {
    const clean = match.replace(/\D/g, "");
    const last4 = clean.slice(-4);
    return `****-****-****-${last4}`;
  });
}

/**
 * Masks personal names: e.g. "John Smith" -> "J*** S***"
 */
export function maskName(name) {
  if (!name || typeof name !== "string") return name;
  return name.split(/\s+/).map((part) => {
    if (part.length <= 1) return part;
    return `${part[0]}***`;
  }).join(" ");
}

/**
 * Comprehensive multi-field text sanitizer.
 */
export function maskSensitiveText(text, isMasked = true) {
  if (!text || typeof text !== "string" || !isMasked) return text;

  let sanitized = text;

  // 1. Mask Emails
  sanitized = sanitized.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, (match) =>
    maskEmail(match)
  );

  // 2. Mask IPv4 Addresses
  sanitized = sanitized.replace(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g, (match) => {
    if (match.startsWith("127.") || match === "0.0.0.0") return match;
    return maskIP(match);
  });

  // 3. Mask Financial Accounts / Credit Cards
  sanitized = maskFinancial(sanitized);

  // 4. Mask Phone Numbers
  sanitized = maskPhone(sanitized);

  return sanitized;
}

/**
 * Computes scheduled retention expiration and purge countdown.
 */
export function computeRetentionStatus(createdAtIso, policyDays = 90) {
  if (!createdAtIso) {
    return {
      policyDays,
      daysRemaining: policyDays,
      status: "ACTIVE",
      purgeScheduledFor: "Unknown",
      isExpired: false,
    };
  }

  try {
    const created = new Date(createdAtIso);
    if (isNaN(created.getTime())) {
      return { policyDays, daysRemaining: policyDays, status: "ACTIVE", purgeScheduledFor: "Unknown", isExpired: false };
    }

    if (policyDays === 0) {
      return {
        policyDays: 0,
        daysRemaining: 0,
        status: "EPHEMERAL",
        purgeScheduledFor: "Session End (Immediate Wipe)",
        isExpired: false,
      };
    }

    const expiryMs = created.getTime() + policyDays * 24 * 60 * 60 * 1000;
    const nowMs = Date.now();
    const remainingMs = expiryMs - nowMs;
    const daysRemaining = Math.max(0, Math.ceil(remainingMs / (1000 * 60 * 60 * 24)));

    const isExpired = remainingMs <= 0;
    const isExpiringSoon = daysRemaining <= 7 && !isExpired;

    return {
      policyDays,
      daysRemaining,
      purgeScheduledFor: new Date(expiryMs).toLocaleDateString(),
      status: isExpired ? "SCHEDULED_PURGE" : isExpiringSoon ? "EXPIRING_SOON" : "ACTIVE",
      isExpired,
      isExpiringSoon,
    };
  } catch {
    return { policyDays, daysRemaining: policyDays, status: "ACTIVE", purgeScheduledFor: "Unknown", isExpired: false };
  }
}
