/**
 * Email Header & Relay Route Protocol Analysis Service
 * Traces mail hop chains, detects relay manipulation, and isolates the earliest reliable sending node.
 */

import { extractIPAddresses } from "./emailAnalyzer";
import { isPrivateIP } from "./geoIpService";

/**
 * Parses raw 'Received' headers into structured hop records.
 */
export function traceReceivedHops(headers = []) {
  const receivedHeaders = headers
    .filter((h) => h?.key?.toLowerCase() === "received")
    .map((h) => (typeof h.value === "string" ? h.value : String(h.value || "")));

  if (receivedHeaders.length === 0) {
    return {
      hops: [],
      earliestOriginatingIP: null,
      relayAnomalies: ["No 'Received' headers present in email metadata."],
      isRelayManipulated: true,
    };
  }

  // In RFC 5322, Received headers are prepended: the topmost header is the final recipient MTA,
  // and the bottom-most header is the earliest sender hop. We reverse them to get chronological order (Hop 1 = Origin).
  const chronological = [...receivedHeaders].reverse();
  const hops = [];
  const relayAnomalies = [];
  let previousDate = null;

  chronological.forEach((headerText, index) => {
    const hopNumber = index + 1;
    const cleanText = headerText.replace(/\s+/g, " ");

    // Extract 'from' clause
    const fromMatch = cleanText.match(/from\s+([^\s;()]+)(?:\s+\(([^()]+)\))?/i);
    const fromHost = fromMatch ? fromMatch[1] : "Unknown Host";
    const fromDetails = fromMatch && fromMatch[2] ? fromMatch[2] : "";

    // Extract 'by' clause
    const byMatch = cleanText.match(/by\s+([^\s;()]+)/i);
    const byHost = byMatch ? byMatch[1] : "MTA Node";

    // Extract protocol / cipher
    const withMatch = cleanText.match(/with\s+([^\s;]+)/i);
    const protocol = withMatch ? withMatch[1].toUpperCase() : "SMTP";

    // Extract IP address from this hop - prioritize the 'from' clause sending IP
    let primaryIP = null;
    if (fromDetails) {
      const fromIpMatch = fromDetails.match(/\[([0-9a-fA-F:.]+)\]|\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/);
      if (fromIpMatch) {
        primaryIP = fromIpMatch[1] || fromIpMatch[2];
      }
    }
    if (!primaryIP) {
      const hopIPs = extractIPAddresses(cleanText);
      primaryIP = hopIPs[0] || null;
    }

    // Extract date/time from the end of Received header (after semicolon ';')
    let timestamp = null;
    let hopDate = null;
    let delaySeconds = 0;

    const semiIndex = cleanText.lastIndexOf(";");
    if (semiIndex !== -1) {
      const dateStr = cleanText.substring(semiIndex + 1).trim();
      const parsed = new Date(dateStr);
      if (!isNaN(parsed.getTime())) {
        hopDate = parsed;
        timestamp = parsed.toUTCString();
        if (previousDate) {
          const diffSec = Math.round((parsed.getTime() - previousDate.getTime()) / 1000);
          delaySeconds = diffSec;
          if (diffSec < -60) {
            relayAnomalies.push(`Clock anomaly detected at Hop #${hopNumber}: Timestamp precedes previous hop by ${Math.abs(diffSec)}s (Possible relay timestamp manipulation).`);
          }
        }
        previousDate = parsed;
      }
    }

    const isPrivate = isPrivateIP(primaryIP);

    hops.push({
      hopNumber,
      fromHost,
      fromDetails,
      byHost,
      protocol,
      primaryIP,
      isPrivate: Boolean(isPrivate),
      timestamp: timestamp || "Header Timestamp Unspecified",
      hopDate: hopDate ? hopDate.toISOString() : null,
      delaySeconds,
      isEncrypted: protocol.includes("TLS") || protocol.includes("ESMTPS") || protocol.includes("SECURE"),
      rawHeader: cleanText,
    });
  });

  // Find the earliest reliable originating public IP node
  // Walk from Hop 1 forward to find the first valid non-private IP
  let earliestOriginatingIP = null;
  let originHopNumber = 1;

  for (const hop of hops) {
    if (hop.primaryIP && !hop.isPrivate) {
      earliestOriginatingIP = hop.primaryIP;
      originHopNumber = hop.hopNumber;
      break;
    }
  }

  // If all were private or not found, check hops[0].primaryIP
  if (!earliestOriginatingIP && hops.length > 0 && hops[0].primaryIP) {
    earliestOriginatingIP = hops[0].primaryIP;
  }

  return {
    hops,
    earliestOriginatingIP,
    originHopNumber,
    totalHops: hops.length,
    relayAnomalies,
    isRelayManipulated: relayAnomalies.length > 0,
  };
}

/**
 * Deep protocol alignment & sender forgery inspection.
 */
export function auditHeaderProtocolAlignment(parsedEmail = {}, headers = []) {
  const getHeader = (name) => {
    const h = headers.find((item) => item?.key?.toLowerCase() === name.toLowerCase());
    return (h?.value || "").trim();
  };

  const fromRaw = parsedEmail.from?.address || getHeader("from") || "";
  const fromName = parsedEmail.from?.name || "";
  const returnPath = getHeader("return-path").replace(/[<>]/g, "");
  const replyTo = getHeader("reply-to").replace(/[<>]/g, "");
  const messageId = getHeader("message-id");
  const dkimSignature = getHeader("dkim-signature");
  const authResults = getHeader("authentication-results");

  const fromDomain = fromRaw.includes("@") ? fromRaw.split("@")[1].toLowerCase().replace(/[>]/g, "").trim() : "";
  const returnPathDomain = returnPath.includes("@") ? returnPath.split("@")[1].toLowerCase().trim() : "";
  const replyToDomain = replyTo.includes("@") ? replyTo.split("@")[1].toLowerCase().trim() : "";

  const anomalies = [];

  // 1. Reply-To Mismatch Check (Classic Phishing Technique)
  let replyToMismatch = false;
  if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
    replyToMismatch = true;
    anomalies.push({
      type: "REPLY_TO_MISMATCH",
      severity: "HIGH",
      detail: `Header 'From' domain (${fromDomain}) does not match 'Reply-To' domain (${replyToDomain}). Replies will be routed to an alternate address.`,
    });
  }

  // 2. Return-Path (Envelope-From) Alignment
  let returnPathMismatch = false;
  if (returnPathDomain && fromDomain && returnPathDomain !== fromDomain) {
    returnPathMismatch = true;
    anomalies.push({
      type: "RETURN_PATH_MISMATCH",
      severity: "MEDIUM",
      detail: `Envelope Return-Path domain (${returnPathDomain}) differs from Header From domain (${fromDomain}). Potential relay or third-party mailing service.`,
    });
  }

  // 3. Display Name Spoofing Check
  let displayNameSpoofing = false;
  const brandKeywords = ["paypal", "microsoft", "google", "apple", "amazon", "chase", "wells fargo", "bank", "support", "security team", "it helpdesk", "admin"];
  const lowerName = fromName.toLowerCase();
  for (const brand of brandKeywords) {
    if (lowerName.includes(brand) && !fromDomain.includes(brand.replace(/\s+/g, ""))) {
      displayNameSpoofing = true;
      anomalies.push({
        type: "DISPLAY_NAME_SPOOFING",
        severity: "CRITICAL",
        detail: `Display name claims to be '${fromName}' (${brand.toUpperCase()}), but actual sending domain is '${fromDomain}'.`,
      });
      break;
    }
  }

  // 4. Message-ID Anomaly
  let messageIdAnomaly = false;
  if (!messageId) {
    messageIdAnomaly = true;
    anomalies.push({
      type: "MISSING_MESSAGE_ID",
      severity: "LOW",
      detail: "Email lacks a standard Message-ID header, common in automated spam scripts.",
    });
  } else if (fromDomain && !messageId.toLowerCase().includes(fromDomain)) {
    // Soft anomaly
    messageIdAnomaly = true;
  }

  // 5. DKIM Signature Presence & Selector
  let dkimSelector = null;
  if (dkimSignature) {
    const selectorMatch = dkimSignature.match(/s=([a-zA-Z0-9_-]+)/i);
    dkimSelector = selectorMatch ? selectorMatch[1] : "default";
  }

  return {
    fromRaw,
    fromName,
    fromDomain,
    returnPath,
    returnPathDomain,
    replyTo,
    replyToDomain,
    replyToMismatch,
    returnPathMismatch,
    displayNameSpoofing,
    messageId,
    messageIdAnomaly,
    hasDkimSignature: Boolean(dkimSignature),
    dkimSelector,
    authResults,
    anomalies,
  };
}
