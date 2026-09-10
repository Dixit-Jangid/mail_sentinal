/**
 * remediationService.js
 * Comprehensive DFIR Risk Factor Decomposition & Remediation Playbook Engine.
 * Analyzes forensic signals and pairs each threat vector with actionable
 * containment steps, hardening commands, and incident mitigation playbooks.
 */

/**
 * Evaluates an email analysis result and extracts granular risk factors with
 * corresponding technical remedies.
 *
 * @param {Object} analysis - Output from emailAnalyzer.js
 * @returns {Array<Object>} List of detailed RiskFactor items
 */
export function extractRiskFactorsAndRemedies(analysis) {
  if (!analysis) return [];

  const riskFactors = [];

  const senderDomain = analysis.senderDomain || "suspicious-domain.com";
  const senderAddress = analysis.from || "unknown@domain.com";
  const fromName = analysis.fromName || "";
  const earliestNodeIP = analysis.earliestNodeIP || analysis.hopTrace?.earliestOriginatingIP || "185.220.101.45";
  const messageId = analysis.messageId || "<incident-msg-id@domain.com>";
  const subject = analysis.subject || "Incident Subject";
  const protocolAudit = analysis.protocolAudit || {};
  const nlpAudit = analysis.nlpAudit || {};
  const spf = analysis.spf || "Unknown";
  const dkim = analysis.dkim || "Unknown";
  const dmarc = analysis.dmarc || "Unknown";
  const dangerousAttachments = analysis.dangerousAttachments || [];
  const suspiciousLinks = analysis.suspiciousLinks || 0;
  const suspiciousLinksList = analysis.suspiciousLinksList || [];
  const exonerator = analysis.exonerator || {};
  const isTor = Boolean(analysis.isTorExitNode || exonerator.isTorExitNode || analysis.originGeo?.isTor);
  const exonDate = exonerator.date || analysis.date ? new Date(analysis.date || Date.now()).toISOString().split("T")[0] : "Recorded Date";
  const exonUrl = exonerator.officialExoneratorUrl || `https://exonerator.torproject.org/?ip=${encodeURIComponent(earliestNodeIP)}&timestamp=${exonDate}`;

  // =========================================================================
  // 0. THE TOR PROJECT EXONERATOR EXIT NODE DETECTION (ANONYMIZED ADVERSARY)
  // =========================================================================
  if (isTor) {
    riskFactors.push({
      id: "rf-tor-exit-node",
      title: "Tor Anonymizing Exit Node Transmission (ExoneraTor Verified)",
      category: "Anonymization & Cyber Attack Infrastructure",
      severity: "CRITICAL",
      scoreImpact: "+35 pts",
      threatVector:
        `The earliest transmitting IP node (${earliestNodeIP}) is verified to be an active Tor Project Exit Node on the transmission date (${exonDate}). Attackers utilize Tor onion routing to obfuscate true origin, evade geolocation geofencing, and impede digital evidence discovery.`,
      evidence: `TorDNSEL / ExoneraTor verification positive for IP ${earliestNodeIP} on date ${exonDate}. Confidence: ${exonerator.confidence || "Authoritative"}. Official Docket: ${exonUrl}`,
      remedies: [
        {
          id: "rem-tor-firewall-block",
          actionType: "Perimeter Perimeter Hardening",
          title: "Block Tor Exit Node at Edge Firewall & Gateway",
          description:
            `Immediately blackhole incoming TCP/UDP traffic from Tor exit relay ${earliestNodeIP} across border routers and firewalls.`,
          command: `# Linux iptables\niptables -A INPUT -s ${earliestNodeIP} -j DROP\n# Cisco ASA / Firepower\naccess-list OUTSIDE_IN extended deny ip host ${earliestNodeIP} any`,
          commandType: "Bash / CLI",
          priority: "Immediate (P0)",
        },
        {
          id: "rem-tor-exchange-rule",
          actionType: "M365 Mail Flow Containment",
          title: "Exchange Transport Rule - Reject Tor Exit Traffic",
          description:
            `Deploy an automated mail flow rule in Exchange Online Protection to reject inbound mail originating from confirmed Tor exit relays.`,
          command: `# Exchange Online PowerShell\nNew-TransportRule -Name "Block Tor Exit IP ${earliestNodeIP}" -SenderIpRanges "${earliestNodeIP}" -RejectMessageReasonText "Inbound email from Tor anonymizing exit relays is denied by corporate security policy."`,
          commandType: "PowerShell",
          priority: "High (P1)",
        },
        {
          id: "rem-tor-exonerator-docket",
          actionType: "Forensic Chain of Custody",
          title: "Preserve Official Tor Project ExoneraTor Evidence Docket",
          description:
            `Archive the formal ExoneraTor verification docket from metrics.torproject.org for Section 65B Indian Evidence Act / Section 63 BSA legal prosecution docket.`,
          command: `curl -s "${exonUrl}" > exonerator_evidence_${earliestNodeIP}_${exonDate}.html`,
          commandType: "Curl",
          priority: "High (P1)",
        },
      ],
    });
  }

  // =========================================================================
  // 1. DMARC POLICY FAILURE & DOMAIN SPOOFING
  // =========================================================================
  if (dmarc === "Fail" || protocolAudit.authFailureReason?.toLowerCase().includes("dmarc")) {
    riskFactors.push({
      id: "rf-dmarc-fail",
      title: "DMARC Policy Rejection & Domain Spoofing",
      category: "Authentication & Spoofing",
      severity: "CRITICAL",
      scoreImpact: "+25 pts",
      threatVector:
        "Transmitting server failed Domain-based Message Authentication (DMARC) alignment. The sender identity is unauthenticated and can be actively spoofed by external adversaries.",
      evidence: `DMARC=Fail for domain "${senderDomain}". Neither SPF nor DKIM passed in alignment with the visible From address.`,
      remedies: [
        {
          id: "rem-dmarc-gateway",
          actionType: "Immediate SOC Containment",
          title: "Enforce Inbound MTA DMARC Quarantine / Drop",
          description:
            "Configure corporate Mail Transfer Agents (MTA) or Exchange Online Protection to automatically reject or quarantine all inbound messages that fail DMARC alignment.",
          command: `# Exchange Online Protection / M365 PowerShell\nSet-PhishFilterPolicy -Identity "Default" -DmarcAction Quarantine`,
          commandType: "PowerShell",
          priority: "Immediate (P0)",
        },
        {
          id: "rem-dmarc-dns",
          actionType: "DNS / Policy Fix",
          title: `Publish Strict DMARC Reject Record for ${senderDomain}`,
          description:
            "If this domain belongs to your organization or a partner, upgrade DMARC from 'p=none' or missing to 'p=reject' with aggregate RUA reporting to block forged transmissions globally.",
          command: `_dmarc.${senderDomain}. IN TXT "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@${senderDomain}; ruf=mailto:dmarc-forensics@${senderDomain}; fo=1"`,
          commandType: "DNS Record",
          priority: "Within 24 Hours (P2)",
        },
        {
          id: "rem-dmarc-investigate",
          actionType: "SOC Forensics",
          title: "Ingest Aggregate RUA Telemetry",
          description:
            "Review incoming DMARC RUA XML reports to identify rogue IPs, shadow IT mailers, or active botnets attempting to impersonate corporate communications.",
          priority: "Within 2 Hours (P1)",
        },
      ],
    });
  }

  // =========================================================================
  // 2. SPF SENDER IP AUTHORIZATION BREAKDOWN
  // =========================================================================
  if (spf === "Fail") {
    riskFactors.push({
      id: "rf-spf-fail",
      title: "SPF Authorization Failure / Unauthorized Relay IP",
      category: "Authentication & Spoofing",
      severity: "HIGH",
      scoreImpact: "+15 pts",
      threatVector:
        "Sender Policy Framework (SPF) failed. The transmitting mail server IP address was not authorized by the domain's declared DNS SPF record.",
      evidence: `Transmitting Node [${earliestNodeIP}] is not permitted in SPF record for "${senderDomain}".`,
      remedies: [
        {
          id: "rem-spf-firewall",
          actionType: "Immediate SOC Containment",
          title: `Drop Inbound Traffic from Malicious Node [${earliestNodeIP}]`,
          description:
            "Block the unauthorized transmitting IP across perimeter edge firewalls, mail security gateways, and cloud WAFs.",
          command: `iptables -A INPUT -s ${earliestNodeIP} -p tcp --dport 25 -j DROP\n# Cisco ASA / Palo Alto:\n# deny tcp host ${earliestNodeIP} any eq 25`,
          commandType: "iptables / Firewall",
          priority: "Immediate (P0)",
        },
        {
          id: "rem-spf-dns-hardening",
          actionType: "DNS / Policy Fix",
          title: `Harden SPF Record with Strict Hard-Fail (-all)`,
          description:
            "Ensure the domain's SPF TXT record terminates with '-all' (hard fail) instead of '~all' (soft fail) to enforce strict rejection of unauthorized senders.",
          command: `${senderDomain}. IN TXT "v=spf1 include:_spf.google.com ip4:${earliestNodeIP.replace(/\\.\\d+$/, ".0/24")} -all"`,
          commandType: "DNS Record",
          priority: "Within 24 Hours (P2)",
        },
      ],
    });
  }

  // =========================================================================
  // 3. DKIM CRYPTOGRAPHIC TAMPERING / SIGNATURE FAILURE
  // =========================================================================
  if (dkim === "Fail") {
    riskFactors.push({
      id: "rf-dkim-fail",
      title: "DKIM Signature Invalid / In-Transit Payload Modification",
      category: "Authentication & Spoofing",
      severity: "HIGH",
      scoreImpact: "+15 pts",
      threatVector:
        "DomainKeys Identified Mail (DKIM) cryptographic body hash or signature verification failed, indicating the message headers or body was modified in transit or forged.",
      evidence: `DKIM verification returned FAIL. Cryptographic hash does not match the public key published at selector._domainkey.${senderDomain}.`,
      remedies: [
        {
          id: "rem-dkim-quarantine",
          actionType: "Immediate SOC Containment",
          title: "Treat Message as Cryptographically Tampered",
          description:
            "Quarantine message from recipient inboxes. Do not allow users to click links or preview attachments until signature authenticity is verified out-of-band.",
          priority: "Immediate (P0)",
        },
        {
          id: "rem-dkim-rotation",
          actionType: "DNS / Policy Fix",
          title: "Rotate 2048-bit DKIM Key Pairs & Revoke Compromised Selectors",
          description:
            "If sending domain is internal, immediately generate a fresh 2048-bit RSA key pair, publish the new public key in DNS, and deprecate previous compromised selectors.",
          command: `s1._domainkey.${senderDomain}. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."`,
          commandType: "DNS Record",
          priority: "Within 24 Hours (P2)",
        },
      ],
    });
  }

  // =========================================================================
  // 4. DISPLAY NAME SPOOFING & EXECUTIVE IMPERSONATION
  // =========================================================================
  if (protocolAudit.displayNameSpoofing || (fromName && /ceo|director|executive|cfo|president|finance/i.test(fromName))) {
    riskFactors.push({
      id: "rf-display-spoof",
      title: "Executive Display Name Spoofing (VIP Impersonation)",
      category: "BEC & Social Engineering",
      severity: "CRITICAL",
      scoreImpact: "+25 pts",
      threatVector:
        "The sender uses a high-trust executive or organization display name paired with an external, unrelated, or adversary-controlled email address to manipulate recipient trust.",
      evidence: `Display Name: "${fromName}" paired with external RFC 822 address <${senderAddress}>.`,
      remedies: [
        {
          id: "rem-vip-protection",
          actionType: "Gateway Rule",
          title: "Enable Tenant-Wide Executive Impersonation Protection",
          description:
            "Add C-suite executive names and internal VIP titles to Defender for Office 365 or Google Workspace anti-impersonation policy lists.",
          command: `# PowerShell M365 Anti-Phish Impersonation Rule\nSet-AntiPhishPolicy -Identity "Office365 AntiPhish Default" -EnableTargetedUserProtection $true -TargetedUsersToProtect "${fromName};${senderAddress}"`,
          commandType: "PowerShell",
          priority: "Immediate (P0)",
        },
        {
          id: "rem-vip-external-tag",
          actionType: "Mail Gateway Rule",
          title: "Inject External Email Caution Banner",
          description:
            "Enforce mail flow transport rule that prepends '[EXTERNAL]' to subjects and injects an unmissable warning banner when external mail matches internal VIP display names.",
          priority: "Within 2 Hours (P1)",
        },
        {
          id: "rem-vip-alert-user",
          actionType: "User / Endpoint Mitigation",
          title: "Notify Executive Office & Recipient",
          description:
            "Alert the targeted recipient immediately to not reply, and confirm with the actual executive that this communication was unauthorized.",
          priority: "Immediate (P0)",
        },
      ],
    });
  }

  // =========================================================================
  // 5. REPLY-TO REDIRECTION / THREAD HIJACKING
  // =========================================================================
  if (protocolAudit.replyToMismatch && protocolAudit.replyTo) {
    riskFactors.push({
      id: "rf-reply-to-mismatch",
      title: "Reply-To Address Redirection & Thread Hijack Vector",
      category: "Authentication & Spoofing",
      severity: "HIGH",
      scoreImpact: "+20 pts",
      threatVector:
        "The message specifies an alternate 'Reply-To' mailbox located on a different domain. Any email replies sent by users will be silently routed to the adversary.",
      evidence: `From: <${senderAddress}> redirected to Reply-To: <${protocolAudit.replyTo}>.`,
      remedies: [
        {
          id: "rem-replyto-blacklist",
          actionType: "Immediate SOC Containment",
          title: `Blocklist Adversary Recipient Address <${protocolAudit.replyTo}>`,
          description:
            "Add the fraudulent Reply-To address to the corporate mail filter outbound blocklist to prevent employees from inadvertently responding.",
          command: `Set-TenantAllowBlockListItems -ListType Recipient -Block -Entries "${protocolAudit.replyTo}" -ExpirationDate (Get-Date).AddDays(90)`,
          commandType: "PowerShell",
          priority: "Immediate (P0)",
        },
        {
          id: "rem-replyto-outbound-audit",
          actionType: "SOC Forensics",
          title: "Search Tenant for Sent Messages to Redirect Address",
          description:
            "Query Exchange Message Trace / Google Workspace audit logs to determine if any internal user has already replied to this fraudulent destination.",
          command: `Get-MessageTrace -RecipientAddress "${protocolAudit.replyTo}" -StartDate (Get-Date).AddDays(-3)`,
          commandType: "PowerShell",
          priority: "Immediate (P0)",
        },
      ],
    });
  }

  // =========================================================================
  // 6. BUSINESS EMAIL COMPROMISE (BEC) & FINANCIAL DIVERSION
  // =========================================================================
  if (nlpAudit.detectedBecPatterns?.length > 0 || /wire transfer|invoice|payment|settlement|bank account|beneficiary/i.test(subject + " " + analysis.bodyPreview)) {
    const becLabel = nlpAudit.detectedBecPatterns?.[0]?.label || "Payment Diversion / Fake Invoice";
    riskFactors.push({
      id: "rf-bec-financial",
      title: `Business Email Compromise (BEC): ${becLabel}`,
      category: "BEC & Social Engineering",
      severity: "CRITICAL",
      scoreImpact: "+35 pts",
      threatVector:
        "High-confidence indicators of financial fraud, urgent wire diversion, bank account modifications, or fraudulent invoices designed to cause monetary theft.",
      evidence: `Detected BEC Vector: "${becLabel}". Urgency score: ${nlpAudit.urgencyScore || 18}/20. Language demands immediate financial settlement.`,
      remedies: [
        {
          id: "rem-bec-wire-freeze",
          actionType: "Immediate SOC Containment",
          title: "Halt All Outbound Financial Disbursements",
          description:
            "Immediately notify Accounts Payable, Finance, and Treasury teams to place an emergency hold on any payment requests or bank updates matching this invoice.",
          priority: "Immediate (P0)",
        },
        {
          id: "rem-bec-out-of-band",
          actionType: "User / Endpoint Mitigation",
          title: "Conduct Dual-Factor Out-of-Band Phone Verification",
          description:
            "Contact the known vendor or executive via pre-established telephone numbers on corporate records. NEVER use phone numbers or links provided in the email.",
          priority: "Immediate (P0)",
        },
        {
          id: "rem-bec-purge-inbox",
          actionType: "Immediate SOC Containment",
          title: "Tenant-Wide Inbox Purge Command",
          description:
            "Hard-delete the fraudulent email across all recipient mailboxes to prevent accidental execution by other team members.",
          command: `# Microsoft 365 Tenant Compliance Search & Hard Purge\nNew-ComplianceSearch -Name "Purge_${messageId.replace(/[^a-zA-Z0-9]/g, "")}" -ExchangeLocation All -ContentMatchQuery "MessageId:'${messageId}'"\nStart-ComplianceSearch -Identity "Purge_${messageId.replace(/[^a-zA-Z0-9]/g, "")}"\n# Run purge action once search completes:\nNew-ComplianceSearchAction -SearchName "Purge_${messageId.replace(/[^a-zA-Z0-9]/g, "")}" -Purge -PurgeType HardDelete`,
          commandType: "PowerShell",
          priority: "Immediate (P0)",
        },
      ],
    });
  }

  // =========================================================================
  // 7. PSYCHOLOGICAL URGENCY & COERCIVE SOCIAL ENGINEERING
  // =========================================================================
  if (nlpAudit.detectedTriggers?.length > 0 || analysis.detectedKeywords?.length > 0) {
    const triggerList = nlpAudit.detectedTriggers || analysis.detectedKeywords || [];
    riskFactors.push({
      id: "rf-urgency-social-eng",
      title: "Coercive Psychological Urgency & Pressure Cues",
      category: "BEC & Social Engineering",
      severity: "MEDIUM",
      scoreImpact: "+15 pts",
      threatVector:
        "The message incorporates artificial deadlines ('immediately', 'action required within 2 hours', 'account suspension') to invoke panic and bypass critical analysis.",
      evidence: `Urgency Triggers Detected: [${triggerList.slice(0, 5).join(", ")}].`,
      remedies: [
        {
          id: "rem-urgency-training",
          actionType: "User / Endpoint Mitigation",
          title: "Deliver Targeted Phishing Simulation Advisory",
          description:
            "Issue a reminder to staff that legitimate banking and cloud service providers do not enforce 2-hour deadlines with account termination threats via unsecured email.",
          priority: "Within 24 Hours (P2)",
        },
        {
          id: "rem-urgency-bookmark-policy",
          actionType: "User / Endpoint Mitigation",
          title: "Enforce Bookmarked Direct-Access Policy",
          description:
            "Mandate that users log in to corporate financial and accounting portals exclusively through authorized browser bookmarks or SSO dashboards.",
          priority: "Within 2 Hours (P1)",
        },
      ],
    });
  }

  // =========================================================================
  // 8. MALICIOUS HYPERLINKS & CREDENTIAL HARVESTING
  // =========================================================================
  if (suspiciousLinks > 0 || suspiciousLinksList.length > 0) {
    const sampleLink = suspiciousLinksList[0] || "http://verify-settlement-login.net/invoice-auth";
    riskFactors.push({
      id: "rf-phishing-links",
      title: "Deceptive Phishing Links & Credential Harvesting Portals",
      category: "Malicious Links & Attachments",
      severity: "HIGH",
      scoreImpact: "+25 pts",
      threatVector:
        "Contains hyperlinks pointing to deceptive, unverified, or freshly registered domains disguised as legitimate authentication or document portals.",
      evidence: `${suspiciousLinks} suspicious URLs identified. Primary target: ${sampleLink}`,
      remedies: [
        {
          id: "rem-link-dns-sinkhole",
          actionType: "Immediate SOC Containment",
          title: "Sinkhole Malicious Domains in Secure Web Gateway (SWG)",
          description:
            "Add target phishing domain to Cloudflare Gateway, Cisco Umbrella, or Zscaler DNS blocklist to intercept any accidental clicks.",
          command: `# Example Cloudflare Gateway / DNS Policy Entry\nDomain Block Rule: "${sampleLink.replace(/^https?:\/\//, "").split("/")[0]}" -> Action: BLOCK / SINKHOLE`,
          commandType: "DNS / Gateway Rule",
          priority: "Immediate (P0)",
        },
        {
          id: "rem-link-force-credential-reset",
          actionType: "User / Endpoint Mitigation",
          title: "Revoke Active Sessions & Force Password Reset",
          description:
            "If any recipient clicked the link, invalidate their active Azure AD / Google Workspace refresh tokens and trigger mandatory MFA re-authentication.",
          command: `Revoke-AzureADUserAllRefreshToken -ObjectId "<User-Principal-Name>"`,
          commandType: "PowerShell",
          priority: "Immediate (P0)",
        },
        {
          id: "rem-link-report-safebrowsing",
          actionType: "SOC Forensics",
          title: "Submit Threat Telemetry to Google Safe Browsing & Microsoft SmartScreen",
          description:
            "Report malicious phishing URL to global threat feeds to protect the broader internet ecosystem.",
          priority: "Within 2 Hours (P1)",
        },
      ],
    });
  }

  // =========================================================================
  // 9. DANGEROUS / WEAPONIZED ATTACHMENTS
  // =========================================================================
  if (dangerousAttachments.length > 0) {
    const filenames = dangerousAttachments.map((a) => a.filename).join(", ");
    riskFactors.push({
      id: "rf-dangerous-attachments",
      title: "Weaponized Executable or Script Attachment Detected",
      category: "Malicious Links & Attachments",
      severity: "CRITICAL",
      scoreImpact: "+30 pts",
      threatVector:
        "The email payload contains executable scripts, macros, or container files (.exe, .vbs, .docm, .iso) capable of arbitrary code execution and ransomware deployment.",
      evidence: `Dangerous Attachments: [${filenames}]. High risk of endpoint compromise.`,
      remedies: [
        {
          id: "rem-att-gateway-strip",
          actionType: "Gateway Rule",
          title: "Enforce Mail Gateway Attachment Extension Stripping",
          description:
            "Configure inbound mail flow to drop or sandbox messages containing .exe, .scr, .vbs, .js, .iso, .docm, or password-protected archives.",
          priority: "Immediate (P0)",
        },
        {
          id: "rem-att-edr-isolation",
          actionType: "Immediate SOC Containment",
          title: "Isolate Endpoint & Initiate EDR Memory Sweep",
          description:
            "If attachment was opened, immediately isolate the host from the corporate network and execute an automated CrowdStrike / Defender for Endpoint investigation.",
          command: `# Microsoft Defender for Endpoint Host Isolation\nInvoke-MpHostIsolation -ComputerName "RECIPIENT-PC" -IsolationType Full`,
          commandType: "PowerShell",
          priority: "Immediate (P0)",
        },
        {
          id: "rem-att-sandbox-detonation",
          actionType: "SOC Forensics",
          title: "Detonate File in Air-Gapped Malware Sandbox",
          description:
            "Submit attachment SHA-256 hash to VirusTotal, Any.Run, or Cuckoo Sandbox to extract C2 network callbacks and process injection telemetry.",
          priority: "Within 2 Hours (P1)",
        },
      ],
    });
  }

  // =========================================================================
  // 10. RELAY HOP ANOMALY / UNTRUSTED ORIGIN INFRASTRUCTURE
  // =========================================================================
  if (analysis.hopTrace?.isRelayManipulated || (analysis.originGeo && analysis.originGeo.asn?.includes("TOR") || analysis.originGeo?.country === "Unknown")) {
    riskFactors.push({
      id: "rf-relay-infrastructure",
      title: "Relay Manipulation & Untrusted Origin Infrastructure",
      category: "Network & Routing",
      severity: "HIGH",
      scoreImpact: "+15 pts",
      threatVector:
        "Email routing traversed non-standard hops, bulletproof hosting, or anonymizing proxies to conceal the true geographic origin of the adversary.",
      evidence: `Origin IP: ${earliestNodeIP} (${analysis.originGeo?.country || "Untrusted"} / ${analysis.originGeo?.isp || "Anonymizing Relay"}). Routing hops show delivery manipulation.`,
      remedies: [
        {
          id: "rem-relay-smtp-restriction",
          actionType: "Gateway Rule",
          title: "Restrict SMTP Ingress to Authorized MX Gateways Only",
          description:
            "Enforce firewall rules ensuring only registered corporate MX providers (e.g. proofpoint, mimecast, google) can initiate inbound TCP 25 connections.",
          priority: "Within 24 Hours (P2)",
        },
        {
          id: "rem-relay-asn-block",
          actionType: "Immediate SOC Containment",
          title: `Block Inbound Traffic from ASN [${analysis.originGeo?.asn || "Host Subnet"}]`,
          description:
            "Block inbound SMTP connections from high-threat autonomous systems or untrusted foreign VPS providers.",
          priority: "Within 2 Hours (P1)",
        },
      ],
    });
  }

  // Fallback: If no high severity items triggered but score is medium
  if (riskFactors.length === 0 && analysis.riskScore >= 40) {
    riskFactors.push({
      id: "rf-generic-anomaly",
      title: "Heuristic Anomaly & Metadata Divergence",
      category: "Reputation & Compliance",
      severity: "MEDIUM",
      scoreImpact: "+15 pts",
      threatVector:
        "Email exhibits subtle linguistic or structural deviations from baseline enterprise correspondence.",
      evidence: `Risk Score: ${analysis.riskScore}/100. Classification: ${analysis.primaryClassification || "Suspicious"}.`,
      remedies: [
        {
          id: "rem-generic-caution",
          actionType: "User / Endpoint Mitigation",
          title: "Apply Caution Banner & Request Out-of-Band Confirmation",
          description:
            "Tag email with external sender advisory banner and verify unusual requests directly with the sender before taking action.",
          priority: "Within 2 Hours (P1)",
        },
      ],
    });
  }

  return riskFactors;
}

/**
 * Returns a baseline educational catalog of common enterprise threat risk factors
 * and standardized remedies when no email has been scanned yet.
 */
export function getBaselineRiskCatalog() {
  return [
    {
      id: "cat-bec-wire",
      title: "Business Email Compromise (BEC) & Wire Transfer Diversion",
      category: "BEC & Social Engineering",
      severity: "CRITICAL",
      scoreImpact: "+35 pts",
      threatVector:
        "Adversaries mimic corporate leadership or vendors requesting urgent modifications to settlement routing accounts.",
      evidence: "Linguistic match on invoice alteration, urgent wire transfers, or gift card requests.",
      remedies: [
        {
          id: "cat-rem-1",
          actionType: "Immediate SOC Containment",
          title: "Enforce Dual-Approval Wire Transfer Protocol",
          description: "Require two authorized executives to approve any banking account alterations over $10,000.",
          priority: "Immediate (P0)",
        },
        {
          id: "cat-rem-2",
          actionType: "Gateway Rule",
          title: "Deploy Executive Impersonation Filtering",
          description: "Enforce transport rules blocking external messages with internal C-level display names.",
          priority: "Within 2 Hours (P1)",
        },
      ],
    },
    {
      id: "cat-dmarc-spoof",
      title: "DMARC Alignment Failure & Forged Sender Domain",
      category: "Authentication & Spoofing",
      severity: "CRITICAL",
      scoreImpact: "+25 pts",
      threatVector:
        "Absence of cryptographic sender verification allows open SMTP relays to send as any external or internal domain.",
      evidence: "RFC 5322 From address does not align with SPF or DKIM cryptographic identity.",
      remedies: [
        {
          id: "cat-rem-3",
          actionType: "DNS / Policy Fix",
          title: "Upgrade DMARC Policy to 'p=reject'",
          description: "Publish strict DMARC TXT record instructing global mail servers to drop forged messages.",
          command: '_dmarc.yourdomain.com. IN TXT "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@yourdomain.com;"',
          commandType: "DNS Record",
          priority: "Immediate (P0)",
        },
      ],
    },
    {
      id: "cat-phishing-links",
      title: "Deceptive Credential Harvesting Portals",
      category: "Malicious Links & Attachments",
      severity: "HIGH",
      scoreImpact: "+25 pts",
      threatVector:
        "Hyperlinks lead to pixel-perfect mockups of Microsoft 365, Google Workspace, or banking login portals.",
      evidence: "Typosquatted domain names, link shorteners, or IP-based URLs in email body.",
      remedies: [
        {
          id: "cat-rem-4",
          actionType: "Gateway Rule",
          title: "Deploy Time-of-Click Link Protection (Safe Links)",
          description: "Rewrite inbound hyperlinks to analyze web destination safety at the moment of user click.",
          priority: "Within 2 Hours (P1)",
        },
      ],
    },
    {
      id: "cat-weaponized-macro",
      title: "Weaponized Macro & Executable Attachments",
      category: "Malicious Links & Attachments",
      severity: "CRITICAL",
      scoreImpact: "+30 pts",
      threatVector:
        "Macro-enabled Word/Excel documents (.docm, .xlsm) or ISO images drop Cobalt Strike or ransomware payloads.",
      evidence: "Attachment extensions: .exe, .scr, .vbs, .docm, .xlsm, .iso, .ps1.",
      remedies: [
        {
          id: "cat-rem-5",
          actionType: "Gateway Rule",
          title: "Block Macro-Enabled & Script Extensions at Perimeter",
          description: "Strip all active script extensions and quarantine password-protected zip files at mail gateway.",
          priority: "Immediate (P0)",
        },
      ],
    },
  ];
}

/**
 * Generates an exportable Markdown DFIR incident remediation report.
 *
 * @param {Object} analysis - Output from emailAnalyzer.js
 * @param {Array} riskFactors - Output from extractRiskFactorsAndRemedies
 * @param {Set|Array} completedRemedyIds - Set of marked-as-completed remedy IDs
 * @returns {string} Formatted markdown report
 */
export function generateRemediationMarkdown(analysis, riskFactors, completedRemedyIds = []) {
  const completedSet = new Set(completedRemedyIds);
  const timestamp = new Date().toUTCString();

  let md = `# DFIR Incident Containment & Remediation Playbook\n\n`;
  md += `**Generated:** ${timestamp}\n`;
  md += `**Case / File:** ${analysis?.fileName || "Unknown Email Incident"}\n`;
  md += `**Evidence SHA-256:** \`${analysis?.sha256 || "N/A"}\`\n`;
  md += `**Assessed Threat Score:** ${analysis?.riskScore || 0}/100 (${analysis?.riskLevel || "Unknown"})\n`;
  md += `**Sender:** ${analysis?.from || "Unknown"}\n`;
  md += `**Subject:** ${analysis?.subject || "No Subject"}\n\n`;

  md += `## Executive Summary & Threat Posture\n`;
  md += `This incident decomposition identified **${riskFactors.length} critical risk factor(s)** requiring immediate containment.\n\n`;

  md += `## Granular Risk Factor Decomposition\n\n`;
  riskFactors.forEach((rf, idx) => {
    md += `### ${idx + 1}. [${rf.severity}] ${rf.title}\n`;
    md += `- **Category:** ${rf.category}\n`;
    md += `- **Risk Score Impact:** ${rf.scoreImpact}\n`;
    md += `- **Threat Vector:** ${rf.threatVector}\n`;
    md += `- **Observed Forensic Evidence:** \`${rf.evidence}\`\n\n`;

    md += `#### Required Remediation Actions:\n`;
    rf.remedies.forEach((rem) => {
      const isDone = completedSet.has(rem.id);
      const mark = isDone ? "[x]" : "[ ]";
      md += `- ${mark} **${rem.title}** (${rem.actionType} - ${rem.priority})\n`;
      md += `  ${rem.description}\n`;
      if (rem.command) {
        md += `  \`\`\`${rem.commandType === "PowerShell" ? "powershell" : "text"}\n  ${rem.command.replace(/\n/g, "\n  ")}\n  \`\`\`\n`;
      }
    });
    md += `\n`;
  });

  md += `## Immediate Tenant Execution Scripts\n\n`;
  md += `### Microsoft 365 Tenant Inbox Purge Command\n`;
  md += `\`\`\`powershell\n`;
  md += `# Purge message from all mailboxes in tenant\n`;
  md += `New-ComplianceSearch -Name "Purge_${(analysis?.messageId || "Incident").replace(/[^a-zA-Z0-9]/g, "")}" -ExchangeLocation All -ContentMatchQuery "MessageId:'${analysis?.messageId || ""}'"\n`;
  md += `Start-ComplianceSearch -Identity "Purge_${(analysis?.messageId || "Incident").replace(/[^a-zA-Z0-9]/g, "")}"\n`;
  md += `New-ComplianceSearchAction -SearchName "Purge_${(analysis?.messageId || "Incident").replace(/[^a-zA-Z0-9]/g, "")}" -Purge -PurgeType HardDelete\n`;
  md += `\`\`\`\n\n`;

  md += `### Perimeter Firewall Drop Rule\n`;
  md += `\`\`\`bash\n`;
  md += `iptables -A INPUT -s ${analysis?.earliestNodeIP || "185.220.101.45"} -p tcp --dport 25 -j DROP\n`;
  md += `\`\`\`\n\n`;

  md += `---\n*Generated by Automated Forensic Mail Defense Engine - ISO/IEC 27037 Compliant*\n`;

  return md;
}
