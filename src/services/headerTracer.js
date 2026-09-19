/**
 * Email Header & Relay Route Protocol Analysis Service
 * Traces mail hop chains, audits 3-way header alignment, detects relay manipulation,
 * isolates the earliest reliable sending node, and identifies routing anomalies.
 */

import { extractIPAddresses } from "./emailAnalyzer";
import { isPrivateIP } from "./geoIpService";

/**
 * Three-Way Header Correlation Matrix:
 * Correlates From (RFC 5322) vs Reply-To (RFC 5322) vs Return-Path / Envelope-From (RFC 5321).
 */
export function auditThreeWayCorrelation(parsedEmail = {}, headers = []) {
  const getHeader = (name) => {
    const h = headers.find((item) => item?.key?.toLowerCase() === name.toLowerCase());
    return (h?.value || "").trim();
  };

  const fromRaw = parsedEmail.from?.address || getHeader("from") || "";
  const fromName = parsedEmail.from?.name || "";
  const returnPathRaw = getHeader("return-path").replace(/[<>]/g, "").trim();
  const replyToRaw = getHeader("reply-to").replace(/[<>]/g, "").trim();
  const senderRaw = getHeader("sender").replace(/[<>]/g, "").trim();

  const extractDomain = (addr) => {
    if (!addr || !addr.includes("@")) return "";
    return addr.split("@")[1].toLowerCase().replace(/[>]/g, "").trim();
  };

  const fromDomain = extractDomain(fromRaw);
  const returnPathDomain = extractDomain(returnPathRaw);
  const replyToDomain = extractDomain(replyToRaw);
  const senderDomain = extractDomain(senderRaw);

  const freeWebmailDomains = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "proton.me", "zoho.com", "mail.com", "yandex.com"
  ];

  const matrix = {
    from: {
      address: fromRaw,
      name: fromName,
      domain: fromDomain,
      isFreeWebmail: freeWebmailDomains.includes(fromDomain),
    },
    replyTo: {
      address: replyToRaw || fromRaw,
      domain: replyToDomain || fromDomain,
      isSpecified: Boolean(replyToRaw),
      isFreeWebmail: freeWebmailDomains.includes(replyToDomain),
    },
    returnPath: {
      address: returnPathRaw || "Unspecified",
      domain: returnPathDomain,
      isSpecified: Boolean(returnPathRaw),
      isFreeWebmail: freeWebmailDomains.includes(returnPathDomain),
    },
    sender: {
      address: senderRaw || "Identical to From",
      domain: senderDomain,
      isSpecified: Boolean(senderRaw),
    },
  };

  // Alignment evaluations
  const replyToMismatch = Boolean(replyToDomain && fromDomain && replyToDomain !== fromDomain);
  const returnPathMismatch = Boolean(returnPathDomain && fromDomain && returnPathDomain !== fromDomain);
  const senderMismatch = Boolean(senderDomain && fromDomain && senderDomain !== fromDomain);

  // Deceptive trapping signals
  const freeWebmailRedirectTrap = replyToMismatch && freeWebmailDomains.includes(replyToDomain) && !freeWebmailDomains.includes(fromDomain);
  const freeWebmailBounceTrap = returnPathMismatch && freeWebmailDomains.includes(returnPathDomain) && !freeWebmailDomains.includes(fromDomain);

  let correlationStatus = "FULL_ALIGNMENT";
  let correlationSeverity = "SAFE";
  let correlationScore = 100; // 100 = perfect alignment, lower = higher risk
  const riskFlags = [];

  if (replyToMismatch) {
    correlationScore -= 40;
    riskFlags.push({
      type: "REPLY_TO_DIVERSION",
      severity: "CRITICAL",
      title: "Reply-To Redirection Trap Detected",
      detail: `Victim replies will be directed away from sender domain (${fromDomain}) to alternate recipient (${matrix.replyTo.address}). Common BEC wire-fraud tactic.`,
    });
  }

  if (freeWebmailRedirectTrap) {
    correlationScore -= 20;
    riskFlags.push({
      type: "FREE_WEBMAIL_TRAP",
      severity: "CRITICAL",
      title: "Free Webmail Diversion Sinkhole",
      detail: `Header 'From' claims corporate domain (${fromDomain}), but 'Reply-To' routes replies to a free personal webmail account (${matrix.replyTo.address}).`,
    });
  }

  if (returnPathMismatch) {
    correlationScore -= 25;
    riskFlags.push({
      type: "RETURN_PATH_MISMATCH",
      severity: "MEDIUM",
      title: "Envelope Sender (Return-Path) Disconnect",
      detail: `Delivery failure bounces and DMARC alignment route to (${matrix.returnPath.address}) rather than the displayed sender (${fromDomain}).`,
    });
  }

  if (senderMismatch) {
    correlationScore -= 15;
    riskFlags.push({
      type: "SENDER_HEADER_DISCREPANCY",
      severity: "LOW",
      title: "Transmitting Agent (Sender Header) Mismatch",
      detail: `RFC 5322 'Sender' header (${matrix.sender.address}) differs from author 'From'. Indicates mailing list or proxy transmission.`,
    });
  }

  if (correlationScore <= 40) {
    correlationStatus = "CRITICAL_DEVIATION";
    correlationSeverity = "CRITICAL";
  } else if (correlationScore < 85) {
    correlationStatus = "PARTIAL_MISALIGNMENT";
    correlationSeverity = "HIGH";
  }

  return {
    matrix,
    correlationStatus,
    correlationSeverity,
    correlationScore: Math.max(0, correlationScore),
    replyToMismatch,
    returnPathMismatch,
    senderMismatch,
    freeWebmailRedirectTrap,
    freeWebmailBounceTrap,
    riskFlags,
    summary: replyToMismatch
      ? "CRITICAL MISALIGNMENT: Reply-To routes replies to an unaligned destination."
      : returnPathMismatch
      ? "PARTIAL ALIGNMENT: Envelope bounce path differs from author domain."
      : "PERFECT ALIGNMENT: From, Reply-To, and Return-Path domains match completely.",
  };
}

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
      originHopNumber: 0,
      totalHops: 0,
      relayAnomalies: ["No 'Received' headers present in email metadata (Severe routing anomaly)."],
      isRelayManipulated: true,
      hopAnomaliesAudit: { anomalies: ["No Received headers present"], isRelayManipulated: true },
      relayManipulationAudit: { isManipulated: true, chainIntegrity: "MISSING_HEADERS" },
    };
  }

  // Chronological order: bottom-most Received header is earliest sender hop (Hop 1)
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

    // Extract IP address from this hop
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

    // Extract date/time from the end of Received header
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
            relayAnomalies.push(
              `Clock retrograde anomaly at Hop #${hopNumber}: Timestamp precedes previous hop by ${Math.abs(diffSec)}s (MTA clock tampering or header forgery).`
            );
          } else if (diffSec > 300) {
            relayAnomalies.push(
              `Excessive MTA queue delay at Hop #${hopNumber}: Message delayed by ${diffSec}s before forwarding.`
            );
          }
        }
        previousDate = parsed;
      }
    }

    const isPrivate = isPrivateIP(primaryIP);
    const isEncrypted = protocol.includes("TLS") || protocol.includes("ESMTPS") || protocol.includes("SECURE");

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
      isEncrypted,
      rawHeader: cleanText,
    });
  });

  // Find the earliest reliable originating public IP node
  let earliestOriginatingIP = null;
  let originHopNumber = 1;

  for (const hop of hops) {
    if (hop.primaryIP && !hop.isPrivate) {
      earliestOriginatingIP = hop.primaryIP;
      originHopNumber = hop.hopNumber;
      break;
    }
  }

  if (!earliestOriginatingIP && hops.length > 0 && hops[0].primaryIP) {
    earliestOriginatingIP = hops[0].primaryIP;
  }

  // Deep anomaly and manipulation audits
  const hopAnomaliesAudit = auditHopAnomalies(hops);
  const relayManipulationAudit = auditRelayManipulation(hops, headers);

  return {
    hops,
    earliestOriginatingIP,
    originHopNumber,
    totalHops: hops.length,
    relayAnomalies,
    isRelayManipulated: relayAnomalies.length > 0 || relayManipulationAudit.isManipulated,
    hopAnomaliesAudit,
    relayManipulationAudit,
  };
}

/**
 * Mail-hop anomaly detection: clock retrogrades, excessive delays, routing loops.
 */
export function auditHopAnomalies(hops = []) {
  const anomalies = [];
  let unencryptedHopsCount = 0;
  let maxHopDelay = 0;
  let hasClockRetrograde = false;

  hops.forEach((hop) => {
    if (!hop.isEncrypted && !hop.isPrivate) {
      unencryptedHopsCount++;
    }

    if (hop.delaySeconds < -60) {
      hasClockRetrograde = true;
      anomalies.push({
        hop: hop.hopNumber,
        severity: "HIGH",
        type: "CLOCK_RETROGRADE",
        detail: `Hop #${hop.hopNumber} timestamp preceded prior hop by ${Math.abs(hop.delaySeconds)}s.`,
      });
    }

    if (hop.delaySeconds > maxHopDelay) {
      maxHopDelay = hop.delaySeconds;
    }

    if (hop.delaySeconds > 300) {
      anomalies.push({
        hop: hop.hopNumber,
        severity: "MEDIUM",
        type: "EXCESSIVE_TRANSIT_DELAY",
        detail: `Hop #${hop.hopNumber} experienced ${hop.delaySeconds}s latency. Possible greylisting or queue buffering.`,
      });
    }
  });

  if (hops.length > 7) {
    anomalies.push({
      hop: hops.length,
      severity: "MEDIUM",
      type: "EXCESSIVE_HOP_COUNT",
      detail: `Unusually high hop count (${hops.length} hops). Indicates open relay looping or anonymizing proxy relay chain.`,
    });
  }

  if (unencryptedHopsCount > 0) {
    anomalies.push({
      hop: 0,
      severity: "LOW",
      type: "PLAINTEXT_TRANSPORT",
      detail: `${unencryptedHopsCount} transit hops transmitted in plaintext (no TLS encryption), vulnerable to eavesdropping.`,
    });
  }

  return {
    anomalies,
    unencryptedHopsCount,
    maxHopDelay,
    hasClockRetrograde,
    isAbnormal: anomalies.length > 0,
  };
}

/**
 * Relay manipulation detection: verifies MTA transit chain integrity and detects fake header injections.
 */
export function auditRelayManipulation(hops = [], headers = []) {
  const indicators = [];
  let brokenChainHops = 0;

  // 1. MTA Chaining Continuity Verification
  // In legitimate email transmission, the 'by' MTA of Hop N will usually correspond
  // to or forward toward the 'from' or connecting MTA of Hop N+1.
  for (let i = 0; i < hops.length - 1; i++) {
    const currentHop = hops[i];
    const nextHop = hops[i + 1];

    const currentBy = (currentHop.byHost || "").toLowerCase();
    const nextFrom = (nextHop.fromHost || "").toLowerCase();

    // Check if there is any domain/host continuity
    const currentDomain = currentBy.split(".").slice(-2).join(".");
    const nextDomain = nextFrom.split(".").slice(-2).join(".");

    if (currentDomain && nextDomain && currentDomain !== nextDomain && !currentBy.includes("localhost") && !nextFrom.includes("localhost")) {
      brokenChainHops++;
    }
  }

  if (brokenChainHops >= 2 && hops.length >= 3) {
    indicators.push({
      severity: "HIGH",
      type: "MTA_CHAIN_DISCONTINUITY",
      detail: "Mismatched MTA handoff signatures across consecutive hops. Possible fabricated Received header injection.",
    });
  }

  // 2. Private IP appearing in middle of public internet hops
  let seenPublicHop = false;
  let privateIpAfterPublic = false;

  for (const hop of hops) {
    if (hop.primaryIP && !hop.isPrivate) {
      seenPublicHop = true;
    } else if (hop.primaryIP && hop.isPrivate && seenPublicHop) {
      privateIpAfterPublic = true;
    }
  }

  if (privateIpAfterPublic) {
    indicators.push({
      severity: "MEDIUM",
      type: "INTERNAL_IP_ANOMALY",
      detail: "RFC 1918 private subnet address identified in transit after public internet nodes. Likely simulated or modified headers.",
    });
  }

  // 3. User-Agent / X-Mailer forensics
  const getHeader = (name) => {
    const h = headers.find((item) => item?.key?.toLowerCase() === name.toLowerCase());
    return (h?.value || "").trim();
  };

  const xMailer = getHeader("x-mailer");
  const userAgent = getHeader("user-agent");
  const xOriginatingIp = getHeader("x-originating-ip");

  let clientSoftwareType = "Standard Mail User Agent (MUA)";
  const suspectMailers = ["phpmailer", "python", "curl", "massmail", "sendgrid", "darkmailer", "bulk", "supersender"];

  const combinedMailer = `${xMailer} ${userAgent}`.toLowerCase();
  for (const suspect of suspectMailers) {
    if (combinedMailer.includes(suspect)) {
      clientSoftwareType = `Automated Mailer Script (${suspect.toUpperCase()})`;
      indicators.push({
        severity: "HIGH",
        type: "SUSPECT_MAILER_SOFTWARE",
        detail: `Message generated by automated script tool: ${xMailer || userAgent}`,
      });
      break;
    }
  }

  const isManipulated = indicators.length > 0;
  const chainIntegrity = isManipulated
    ? indicators.some((ind) => ind.severity === "HIGH")
      ? "SUSPECTED_FABRICATION"
      : "ANOMALOUS_CHAIN"
    : "VERIFIED_CONTINUOUS";

  return {
    isManipulated,
    chainIntegrity,
    indicators,
    xMailer: xMailer || "Not Specified",
    userAgent: userAgent || "Not Specified",
    xOriginatingIp: xOriginatingIp ? xOriginatingIp.replace(/[\[\]]/g, "") : null,
    clientSoftwareType,
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
  const returnPath = getHeader("return-path").replace(/[<>]/g, "").trim();
  const replyTo = getHeader("reply-to").replace(/[<>]/g, "").trim();
  const messageId = getHeader("message-id").trim();
  const dkimSignature = getHeader("dkim-signature");
  const authResults = getHeader("authentication-results");

  const fromDomain = fromRaw.includes("@") ? fromRaw.split("@")[1].toLowerCase().replace(/[>]/g, "").trim() : "";
  const returnPathDomain = returnPath.includes("@") ? returnPath.split("@")[1].toLowerCase().trim() : "";
  const replyToDomain = replyTo.includes("@") ? replyTo.split("@")[1].toLowerCase().trim() : "";

  const threeWayAudit = auditThreeWayCorrelation(parsedEmail, headers);
  const anomalies = [...threeWayAudit.riskFlags];

  // Display Name Spoofing Check
  let displayNameSpoofing = false;
  const brandKeywords = [
    "paypal", "microsoft", "google", "apple", "amazon", "chase", "wells fargo",
    "bank of america", "bank", "support", "security team", "it helpdesk", "admin", "treasury", "cfo", "ceo"
  ];
  const lowerName = fromName.toLowerCase();

  for (const brand of brandKeywords) {
    if (lowerName.includes(brand) && !fromDomain.includes(brand.replace(/\s+/g, ""))) {
      displayNameSpoofing = true;
      anomalies.push({
        type: "DISPLAY_NAME_SPOOFING",
        severity: "CRITICAL",
        detail: `Display name claims to be '${fromName}' (${brand.toUpperCase()}), but sending domain is '${fromDomain}'.`,
      });
      break;
    }
  }

  // Message-ID Anomaly
  let messageIdAnomaly = false;
  if (!messageId) {
    messageIdAnomaly = true;
    anomalies.push({
      type: "MISSING_MESSAGE_ID",
      severity: "LOW",
      detail: "Email lacks a standard Message-ID header, common in automated mass-mail scripts.",
    });
  } else if (fromDomain && !messageId.toLowerCase().includes(fromDomain)) {
    messageIdAnomaly = true;
  }

  // DKIM Signature Presence & Selector
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
    replyToMismatch: threeWayAudit.replyToMismatch,
    returnPathMismatch: threeWayAudit.returnPathMismatch,
    displayNameSpoofing,
    messageId,
    messageIdAnomaly,
    hasDkimSignature: Boolean(dkimSignature),
    dkimSelector,
    authResults,
    anomalies,
    threeWayAudit,
  };
}
