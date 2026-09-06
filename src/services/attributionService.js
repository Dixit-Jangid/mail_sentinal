/**
 * Identity Correlation & Infrastructure Attribution Service
 * Builds graph relationship topology and confidence-based actor/infrastructure classification.
 */

/**
 * Classifies probable origin infrastructure and threat actor type.
 */
export function determineAttribution({
  spf = "Unknown",
  dkim = "Unknown",
  dmarc = "Unknown",
  protocolAudit = {},
  nlpAudit = {},
  originGeo = {},
  detectedKeywords = [],
  suspiciousLinks = 0,
}) {
  const { replyToMismatch, displayNameSpoofing } = protocolAudit;
  const isAuthPassed = spf === "Pass" && dkim === "Pass";
  const isAuthFailed = spf === "Fail" || dkim === "Fail" || dmarc === "Fail";
  const isVpnOrCloud = originGeo?.isCloud || originGeo?.isProxy || originGeo?.isPrivate;

  let infrastructureType;
  let attributionConfidence;
  let attributionSummary;
  let campaignTag;

  if (isAuthPassed && (nlpAudit?.detectedBecPatterns?.length > 0 || replyToMismatch)) {
    infrastructureType = "Compromised Legitimate Account";
    attributionConfidence = 88;
    attributionSummary =
      "Email passes cryptographic sender verification (SPF/DKIM), but exhibits severe BEC linguistic markers or Reply-To redirection. High probability of authorized account takeover (ATO) or compromised corporate credentials.";
    campaignTag = "Campaign #ATO-BEC-Executive";
  } else if (displayNameSpoofing || (isAuthFailed && replyToMismatch)) {
    infrastructureType = "Spoofed Domain / Forged Headers";
    attributionConfidence = 95;
    attributionSummary =
      "Direct header spoofing detected. Sender forged the display name or envelope to deceive recipient, failing DMARC/SPF authentication.";
    campaignTag = "Campaign #Brand-Impersonation-Deception";
  } else if (isVpnOrCloud || originGeo?.org?.toLowerCase().includes("hosting") || originGeo?.org?.toLowerCase().includes("cloud")) {
    infrastructureType = "Anonymized Relay / Cloud Bulletproof Infrastructure";
    attributionConfidence = 84;
    attributionSummary =
      "Transmission routed through public cloud compute, VPS hosting, or anonymizing VPN node to obscure physical adversary origin.";
    campaignTag = "Campaign #Cloud-Relay-Harvester";
  } else if (nlpAudit?.detectedBecPatterns?.some((p) => p.key === "PAYMENT_DIVERSION")) {
    infrastructureType = "Financial Fraud Syndicate (BEC)";
    attributionConfidence = 90;
    attributionSummary =
      "Specialized financial fraud group targeting wire transfer redirection and accounting workflows.";
    campaignTag = "Campaign #FIN-WireDiversion-Global";
  } else if (nlpAudit?.detectedBecPatterns?.some((p) => p.key === "CREDENTIAL_HARVESTING")) {
    infrastructureType = "Phishing-as-a-Service (PhaaS) Kit";
    attributionConfidence = 86;
    attributionSummary =
      "Automated credential harvesting infrastructure matching known PhaaS templates.";
    campaignTag = "Campaign #O365-CredentialHarvest";
  } else {
    infrastructureType = isAuthPassed ? "Legitimate Sender Infrastructure" : "Unverified Transmission Node";
    attributionConfidence = 70;
    attributionSummary = isAuthPassed
      ? "Standard enterprise mail routing with verified domain alignment."
      : "Sender origin lacks alignment but shows minimal malicious payload.";
    campaignTag = "Standard Traffic";
  }

  // Refine confidence with multi-signal corroboration
  if (suspiciousLinks > 0 || detectedKeywords.length > 0) {
    attributionConfidence = Math.min(attributionConfidence + 2, 99);
  }

  return {
    infrastructureType,
    attributionConfidence,
    attributionSummary,
    campaignTag,
  };
}

/**
 * Generates graph relationship topology for visual SVG correlation view:
 * Sender Domain <-> Origin IP <-> MX Host <-> Reply-To Alias <-> Threat IOCs
 */
export function buildCorrelationGraph({
  from = "",
  fromDomain = "",
  replyTo = "",
  originIP = "",
  mxRecords = [],
  suspiciousLinks = [],
  fileName = "",
}) {
  const nodes = [];
  const edges = [];

  // Root Node: Email File / Evidence
  nodes.push({
    id: "evidence",
    label: fileName || "Analyzed Message",
    type: "evidence",
    icon: "FileText",
    color: "#3b82f6",
  });

  // Sender Domain Node
  if (fromDomain) {
    nodes.push({
      id: "domain",
      label: fromDomain,
      type: "domain",
      icon: "Globe",
      color: "#8b5cf6",
    });
    edges.push({ from: "evidence", to: "domain", label: "Sender Domain" });

    // MX Host Nodes (first 1-2 records)
    if (mxRecords && mxRecords.length > 0) {
      const primaryMx = typeof mxRecords[0] === "string" ? mxRecords[0] : mxRecords[0]?.exchange || "mail.host";
      nodes.push({
        id: "mx_host",
        label: primaryMx,
        type: "mx",
        icon: "Server",
        color: "#64748b",
      });
      edges.push({ from: "domain", to: "mx_host", label: "MX Exchanger" });
    }
  }

  // Origin IP Node
  if (originIP) {
    nodes.push({
      id: "origin_ip",
      label: originIP,
      type: "ip",
      icon: "Network",
      color: "#f59e0b",
    });
    edges.push({ from: "evidence", to: "origin_ip", label: "Hop 0 Origin" });
  }

  // Reply-To Node if mismatch exists
  if (replyTo && replyTo !== from) {
    nodes.push({
      id: "reply_to",
      label: replyTo,
      type: "reply_to",
      icon: "AlertCircle",
      color: "#ef4444",
    });
    edges.push({ from: "evidence", to: "reply_to", label: "Redirect Reply" });
  }

  // Suspicious Link Nodes (up to 2)
  if (suspiciousLinks && suspiciousLinks.length > 0) {
    suspiciousLinks.slice(0, 2).forEach((link, idx) => {
      let shortUrl;
      try {
        shortUrl = new URL(link).hostname;
      } catch {
        shortUrl = link.substring(0, 25);
      }
      const linkId = `ioc_link_${idx}`;
      nodes.push({
        id: linkId,
        label: shortUrl,
        type: "threat_ioc",
        icon: "Link2",
        color: "#dc2626",
      });
      edges.push({ from: "evidence", to: linkId, label: "Embedded URL" });
    });
  }

  return { nodes, edges };
}
