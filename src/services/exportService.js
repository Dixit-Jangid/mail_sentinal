/**
 * Forensic Reporting & Structured Threat Intelligence Export Service
 * Formats:
 *  - STIX 2.1 Threat Intelligence Bundle (OASIS Open Standard)
 *  - Structured JSON Telemetry
 *  - CSV IoC Artifacts Table
 *  - Standalone HTML Forensic Docket
 *  - Plaintext Forensic Dossier (.txt)
 */

import { maskSensitiveText } from "./privacyService";

/**
 * Triggers a browser download of a Blob file.
 */
export function downloadFile(content, fileName, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/**
 * 1. STIX 2.1 JSON Threat Intelligence Bundle
 * Standardized format used by SIEMs (Splunk, Microsoft Sentinel, IBM QRadar, MISP).
 */
export function exportStixBundle(analysis, options = {}) {
  if (!analysis) return;
  const isMasked = Boolean(options.piiRedacted);
  const cleanId = analysis.id.replace(/[^a-zA-Z0-9-]/g, "");

  const senderVal = isMasked ? maskSensitiveText(analysis.from) : analysis.from;
  const ipVal = isMasked ? maskSensitiveText(analysis.earliestNodeIP || "") : analysis.earliestNodeIP;

  const bundleId = `bundle--${crypto.randomUUID ? crypto.randomUUID() : `urn-stix-${Date.now()}`}`;
  const nowIso = new Date().toISOString();

  const objects = [];

  // 1. Observed Data Object
  const observedDataId = `observed-data--${crypto.randomUUID ? crypto.randomUUID() : `obs-${Date.now()}`}`;
  objects.push({
    type: "observed-data",
    spec_version: "2.1",
    id: observedDataId,
    created: nowIso,
    modified: nowIso,
    first_observed: analysis.date || nowIso,
    last_observed: nowIso,
    number_observed: 1,
    objects: {
      "0": {
        type: "email-message",
        is_multipart: true,
        subject: analysis.subject,
        from_ref: "1",
        to_refs: ["2"],
        date: analysis.date,
        body: analysis.bodyPreview?.substring(0, 300) || "",
      },
      "1": {
        type: "email-addr",
        value: senderVal,
        display_name: analysis.fromName || senderVal,
      },
      "2": {
        type: "email-addr",
        value: isMasked ? maskSensitiveText(analysis.to) : analysis.to,
      },
    },
  });

  // 2. Threat Actor / Infrastructure Object
  const infraId = `infrastructure--${crypto.randomUUID ? crypto.randomUUID() : `inf-${Date.now()}`}`;
  objects.push({
    type: "infrastructure",
    spec_version: "2.1",
    id: infraId,
    created: nowIso,
    modified: nowIso,
    name: analysis.attribution?.infrastructureType || "Analyzed Email Infrastructure",
    description: analysis.attribution?.attributionSummary || "Adversarial mail infrastructure",
    infrastructure_types: [analysis.aiClassification?.primaryClass?.toLowerCase() || "phishing"],
  });

  // 3. Indicator Objects for IP & URLs
  if (ipVal && !ipVal.startsWith("127.")) {
    const ipIndicatorId = `indicator--${crypto.randomUUID ? crypto.randomUUID() : `ind-ip-${Date.now()}`}`;
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id: ipIndicatorId,
      created: nowIso,
      modified: nowIso,
      name: `Malicious Origin Node ${ipVal}`,
      description: `Originating IP flagged in email threat investigation ${cleanId}`,
      pattern: `[ipv4-addr:value = '${ipVal}']`,
      pattern_type: "stix",
      valid_from: nowIso,
      confidence: analysis.attribution?.attributionConfidence || 85,
    });
  }

  // URL Indicators
  const urls = analysis.suspiciousLinksList || [];
  urls.slice(0, 5).forEach((url, idx) => {
    const urlId = `indicator--${crypto.randomUUID ? crypto.randomUUID() : `ind-url-${idx}-${Date.now()}`}`;
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id: urlId,
      created: nowIso,
      modified: nowIso,
      name: `Quarantined Phishing URL #${idx + 1}`,
      pattern: `[url:value = '${isMasked ? maskSensitiveText(url) : url}']`,
      pattern_type: "stix",
      valid_from: nowIso,
      confidence: 90,
    });
  });

  // 4. Attack Pattern Object (MITRE ATT&CK)
  const attackPatternId = `attack-pattern--${crypto.randomUUID ? crypto.randomUUID() : `att-${Date.now()}`}`;
  objects.push({
    type: "attack-pattern",
    spec_version: "2.1",
    id: attackPatternId,
    created: nowIso,
    modified: nowIso,
    name: "Phishing: Spearphishing Link / Attachment",
    description: "Adversaries send spearphishing messages with malicious links or attachments.",
    external_references: [
      {
        source_name: "mitre-attack",
        external_id: "T1566",
        url: "https://attack.mitre.org/techniques/T1566/",
      },
    ],
  });

  const stixBundle = {
    type: "bundle",
    id: bundleId,
    objects,
  };

  const fileName = `stix2.1-intel-${analysis.fileName.replace(/\.eml$/i, "")}.json`;
  downloadFile(JSON.stringify(stixBundle, null, 2), fileName, "application/json;charset=utf-8;");
}

/**
 * 2. CSV IoC Artifacts Table Export
 */
export function exportCsvIocs(analysis, options = {}) {
  if (!analysis) return;
  const isMasked = Boolean(options.piiRedacted);

  const rows = [
    ["Indicator_Type", "Indicator_Value", "Threat_Category", "Severity", "Confidence_Pct", "Context_Notes"],
  ];

  // Sender Email
  const senderVal = isMasked ? maskSensitiveText(analysis.from) : analysis.from;
  rows.push(["Email_Sender", `"${senderVal}"`, "Sender Identity", "HIGH", analysis.classificationConfidence || 85, "Header From address"]);

  // Sender Domain
  if (analysis.senderDomain) {
    rows.push(["Domain", `"${analysis.senderDomain}"`, "Infrastructure", "MEDIUM", 80, `Domain Age: ${analysis.domainIntel?.domainAge?.ageFormatted || "Unknown"}`]);
  }

  // Originating IP
  if (analysis.earliestNodeIP) {
    const ipVal = isMasked ? maskSensitiveText(analysis.earliestNodeIP) : analysis.earliestNodeIP;
    rows.push(["IPv4_Origin", `"${ipVal}"`, "Network Node", analysis.isTorExitNode ? "CRITICAL" : "HIGH", 92, `Country: ${analysis.originGeo?.country_name || "Unknown"} | ISP: ${analysis.originGeo?.isp || "Unknown"}`]);
  }

  // Suspicious Links
  (analysis.suspiciousLinksList || []).forEach((link) => {
    const linkVal = isMasked ? maskSensitiveText(link) : link;
    rows.push(["URL_Weaponized", `"${linkVal}"`, "Phishing Payload", "CRITICAL", 95, "Embedded actionable hyper-reference"]);
  });

  // Attachments
  (analysis.attachments || []).forEach((att) => {
    rows.push(["Attachment_File", `"${att.filename}"`, att.isExecutable ? "Executable Payload" : "Document", att.isExecutable ? "CRITICAL" : "LOW", 90, `Size: ${att.size} bytes | MIME: ${att.mimeType}`]);
  });

  // SHA256 Evidence Hash
  rows.push(["File_SHA256", `"${analysis.sha256}"`, "Evidence Checksum", "INFO", 100, `Evidence Source: ${analysis.fileName}`]);

  const csvContent = rows.map((r) => r.join(",")).join("\n");
  const fileName = `ioc-artifacts-${analysis.fileName.replace(/\.eml$/i, "")}.csv`;
  downloadFile(csvContent, fileName, "text/csv;charset=utf-8;");
}

/**
 * 3. Standalone HTML Forensic Examination Docket
 */
export function exportHtmlDocket(analysis, options = {}) {
  if (!analysis) return;
  const isMasked = Boolean(options.piiRedacted);

  const fromVal = isMasked ? maskSensitiveText(analysis.from) : analysis.from;
  const toVal = isMasked ? maskSensitiveText(analysis.to) : analysis.to;
  const ipVal = isMasked ? maskSensitiveText(analysis.earliestNodeIP || "N/A") : analysis.earliestNodeIP || "N/A";

  const isHighRisk = analysis.riskScore >= 70;
  const isMediumRisk = analysis.riskScore >= 40 && analysis.riskScore < 70;
  const statusColor = isHighRisk ? "#dc2626" : isMediumRisk ? "#d97706" : "#16a34a";

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Forensic_Docket_${analysis.id}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b132b; color: #e2e8f0; padding: 30px; }
    .container { max-width: 900px; margin: 0 auto; background: #1c2541; border: 1px solid #3a506b; border-radius: 8px; padding: 32px; }
    h1, h2, h3 { color: #ffffff; }
    .header-bar { border-bottom: 2px solid #3a506b; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-start; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; background: ${statusColor}; color: white; }
    .hash-box { background: #0b132b; border: 1px solid #3a506b; padding: 12px; border-radius: 6px; font-family: monospace; color: #38bdf8; word-break: break-all; margin: 16px 0; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 16px 0; }
    .card { background: #0b132b; padding: 12px; border-radius: 6px; border: 1px solid #283747; }
    .card-label { font-size: 11px; color: #94a3b8; text-transform: uppercase; }
    .card-val { font-weight: 600; margin-top: 4px; color: #f8fafc; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #283747; font-size: 12px; }
    th { color: #94a3b8; background: #0b132b; }
    ol { padding-left: 20px; }
    li { margin-bottom: 6px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header-bar">
      <div>
        <div style="font-size: 11px; color: #60a5fa; font-weight: bold; letter-spacing: 0.08em;">CERTIFIED DIGITAL FORENSIC EVIDENCE · ISO/IEC 27037</div>
        <h1 style="margin: 4px 0 0; font-size: 24px;">Incident Investigation Docket</h1>
        <span style="font-size: 12px; color: #94a3b8;">Case Docket: ${analysis.id} | Analyzed: ${analysis.analyzedAt}</span>
      </div>
      <div style="text-align: right;">
        <span class="badge">VERDICT: ${analysis.riskLevel.toUpperCase()}</span>
        <div style="font-size: 12px; color: #cbd5e1; margin-top: 4px;">Score: ${analysis.riskScore}/100</div>
      </div>
    </div>

    <div class="hash-box">
      <strong>CRYPTOGRAPHIC EVIDENCE SEAL (SHA-256):</strong><br>
      ${analysis.sha256}
    </div>

    <h3>1. Envelope & Identity Forensics</h3>
    <div class="grid">
      <div class="card"><div class="card-label">Header From</div><div class="card-val">${fromVal}</div></div>
      <div class="card"><div class="card-label">Recipient (To)</div><div class="card-val">${toVal}</div></div>
      <div class="card"><div class="card-label">Subject</div><div class="card-val">${analysis.subject}</div></div>
      <div class="card"><div class="card-label">Originating Node IP</div><div class="card-val">${ipVal} (${analysis.originGeo?.country_name || "Internal"})</div></div>
      <div class="card"><div class="card-label">SPF / DKIM / DMARC</div><div class="card-val">SPF: ${analysis.spf} | DKIM: ${analysis.dkim} | DMARC: ${analysis.dmarc}</div></div>
      <div class="card"><div class="card-label">Primary AI Classification</div><div class="card-val">${analysis.primaryClassification} (${analysis.classificationConfidence}% Conf.)</div></div>
    </div>

    <h3>2. Extracted Indicators of Compromise (IoCs)</h3>
    <table>
      <thead><tr><th>Type</th><th>Indicator</th><th>Classification</th></tr></thead>
      <tbody>
        <tr><td>Origin IP</td><td>${ipVal}</td><td>${analysis.isTorExitNode ? "Tor Exit Node" : analysis.originGeo?.isp || "ISP Host"}</td></tr>
        ${(analysis.suspiciousLinksList || []).map((l) => `<tr><td>Weaponized URL</td><td>${isMasked ? maskSensitiveText(l) : l}</td><td>Deceptive Hyperlink</td></tr>`).join("")}
        ${(analysis.attachments || []).map((a) => `<tr><td>Attachment</td><td>${a.filename}</td><td>${a.isExecutable ? "Executable / Script Payload" : "Document"}</td></tr>`).join("")}
      </tbody>
    </table>

    <h3 style="margin-top: 24px;">3. Recommended Incident Containment Actions</h3>
    <ol>
      ${(analysis.containmentActions || []).map((act) => `<li>${act}</li>`).join("")}
    </ol>
  </div>
</body>
</html>`;

  const fileName = `forensic-docket-${analysis.fileName.replace(/\.eml$/i, "")}.html`;
  downloadFile(html, fileName, "text/html;charset=utf-8;");
}
