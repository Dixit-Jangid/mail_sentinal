/**
 * Privacy and Data Protection Compliance Service (DPDP / GDPR / ISO 27701)
 * Provides configurable redaction and masking for sensitive identifiers.
 */

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
 * Masks phone numbers or monetary accounts if detected
 */
export function maskSensitiveText(text, isMasked = true) {
  if (!text || typeof text !== "string" || !isMasked) return text;

  let sanitized = text;

  // Mask emails
  sanitized = sanitized.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, (match) =>
    maskEmail(match)
  );

  // Mask IPv4
  sanitized = sanitized.replace(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g, (match) => {
    if (match.startsWith("127.") || match === "0.0.0.0") return match;
    return maskIP(match);
  });

  // Mask credit card / account sequences (13-19 digits)
  sanitized = sanitized.replace(/\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,4}\b/g, "****-****-****-****");

  return sanitized;
}
