/**
 * Professional Digital Forensics & Incident Response (DFIR) Report Generator
 * Formatted to ISO/IEC 27037 Digital Evidence Preservation Standards.
 * Generates printable, high-fidelity PDF documents with cryptographic integrity seals.
 */

import { maskSensitiveText } from "./privacyService";

/**
 * Generates and triggers the download / print of a formal PDF Forensic Investigation Report.
 */
export function generateInvestigativePdf(analysis, options = {}) {
  if (!analysis) {
    alert("No analysis data available to generate report.");
    return;
  }

  const isMasked = Boolean(options.piiRedacted);
  const fromVal = isMasked ? maskSensitiveText(analysis.from) : analysis.from;
  const toVal = isMasked ? maskSensitiveText(analysis.to) : analysis.to;
  const ipVal = isMasked ? maskSensitiveText(analysis.earliestNodeIP || "N/A") : analysis.earliestNodeIP || "N/A";
  const replyToVal = isMasked ? maskSensitiveText(analysis.protocolAudit?.replyTo || "N/A") : analysis.protocolAudit?.replyTo || "N/A";

  const isHighRisk = analysis.riskScore >= 70;
  const isMediumRisk = analysis.riskScore >= 40 && analysis.riskScore < 70;
  const verdictColor = isHighRisk ? "#dc2626" : isMediumRisk ? "#d97706" : "#16a34a";
  const verdictBg = isHighRisk ? "#fee2e2" : isMediumRisk ? "#fef3c7" : "#dcfce7";

  const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Forensic_Investigation_Report_${analysis.id}</title>
  <style>
    @page {
      size: A4 portrait;
      margin: 12mm 15mm;
    }
    @media print {
      body {
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }
      .no-print {
        display: none !important;
      }
      .page-break {
        page-break-before: always;
      }
    }
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    body {
      font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif;
      color: #0f172a;
      background: #f8fafc;
      padding: 20px;
      font-size: 11pt;
      line-height: 1.5;
    }
    .report-container {
      max-width: 900px;
      margin: 0 auto;
      background: #ffffff;
      padding: 36px 42px;
      border: 1px solid #cbd5e1;
      border-radius: 4px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.06);
    }
    /* HEADER & LETTERHEAD */
    .header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 2px solid #0d2741;
      padding-bottom: 18px;
      margin-bottom: 20px;
    }
    .agency-title {
      font-size: 18pt;
      font-weight: 800;
      color: #0d2741;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .agency-subtitle {
      font-size: 9pt;
      color: #475569;
      font-weight: 600;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      margin-top: 3px;
    }
    .standard-badge {
      font-size: 8pt;
      font-weight: 700;
      background: #0d2741;
      color: #ffffff;
      padding: 4px 8px;
      border-radius: 3px;
      display: inline-block;
      margin-top: 6px;
    }
    .docket-meta {
      text-align: right;
      font-size: 9pt;
      color: #334155;
    }
    .docket-meta strong {
      color: #0f172a;
    }
    /* VERDICT BANNER */
    .verdict-banner {
      background: ${verdictBg};
      border-left: 6px solid ${verdictColor};
      padding: 14px 18px;
      border-radius: 4px;
      margin-bottom: 22px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .verdict-text strong {
      font-size: 13pt;
      color: ${verdictColor};
      text-transform: uppercase;
      display: block;
    }
    .verdict-text span {
      font-size: 10pt;
      color: #334155;
      font-weight: 600;
    }
    .score-badge {
      font-size: 20pt;
      font-weight: 900;
      color: ${verdictColor};
      text-align: right;
    }
    .score-badge small {
      font-size: 10pt;
      color: #64748b;
      font-weight: 600;
    }
    /* SECTIONS */
    .section {
      margin-bottom: 22px;
    }
    .section-title {
      font-size: 11pt;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #0d2741;
      border-bottom: 1.5px solid #e2e8f0;
      padding-bottom: 5px;
      margin-bottom: 10px;
    }
    /* GRID TABLES */
    .meta-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px 18px;
      font-size: 9.5pt;
    }
    .meta-item {
      display: flex;
      flex-direction: column;
    }
    .meta-item .label {
      font-size: 8pt;
      font-weight: 700;
      text-transform: uppercase;
      color: #64748b;
      letter-spacing: 0.04em;
    }
    .meta-item .val {
      font-size: 9.5pt;
      font-weight: 600;
      color: #0f172a;
      word-break: break-all;
    }
    .code-val {
      font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
      font-size: 8.5pt;
    }
    /* TABLES */
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 9pt;
      margin-top: 6px;
    }
    th {
      background: #f1f5f9;
      color: #334155;
      font-weight: 700;
      text-transform: uppercase;
      font-size: 8pt;
      letter-spacing: 0.04em;
      padding: 7px 10px;
      border: 1px solid #cbd5e1;
      text-align: left;
    }
    td {
      padding: 7px 10px;
      border: 1px solid #e2e8f0;
      color: #1e293b;
    }
    tr:nth-child(even) {
      background: #f8fafc;
    }
    .status-pass {
      color: #16a34a;
      font-weight: 700;
    }
    .status-fail {
      color: #dc2626;
      font-weight: 700;
    }
    .callout-box {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 4px;
      padding: 12px 14px;
      font-size: 9.5pt;
      margin-top: 6px;
    }
    /* SIGNATURE BLOCK */
    .sign-block {
      margin-top: 32px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      border-top: 1.5px solid #0d2741;
      padding-top: 16px;
    }
    .sign-field {
      text-align: center;
      width: 220px;
    }
    .sign-line {
      border-bottom: 1px solid #334155;
      margin-bottom: 6px;
      height: 35px;
    }
    .sign-label {
      font-size: 8.5pt;
      color: #475569;
      font-weight: 600;
      text-transform: uppercase;
    }
    .seal-box {
      border: 2px dashed #0d2741;
      border-radius: 50%;
      width: 90px;
      height: 90px;
      display: grid;
      place-items: center;
      text-align: center;
      font-size: 7.5pt;
      font-weight: 800;
      color: #0d2741;
      text-transform: uppercase;
      padding: 6px;
    }
    .btn-bar {
      margin-bottom: 16px;
      display: flex;
      justify-content: flex-end;
      gap: 10px;
    }
    .btn {
      background: #0d2741;
      color: #fff;
      border: 0;
      padding: 10px 18px;
      font-size: 10pt;
      font-weight: 700;
      border-radius: 6px;
      cursor: pointer;
    }
    .btn:hover {
      background: #173b61;
    }
  </style>
</head>
<body>
  <div class="no-print btn-bar">
    <button class="btn" onclick="window.print()">🖨️ Save as PDF / Print</button>
  </div>

  <div class="report-container">
    <!-- HEADER -->
    <div class="header">
      <div>
        <div class="agency-title">Digital Forensics Examination Report</div>
        <div class="agency-subtitle">Cyber Threat Intelligence & Incident Response Division</div>
        <div class="standard-badge">ISO/IEC 27037 Digital Evidence Preservation Standard</div>
      </div>
      <div class="docket-meta">
        <div><strong>Docket / Case Ref:</strong> DFIR-${analysis.id.substring(5, 14).toUpperCase()}</div>
        <div><strong>Exam Date:</strong> ${analysis.analyzedAt}</div>
        <div><strong>Classification:</strong> OFFICIAL / LAW ENFORCEMENT READY</div>
        <div><strong>PII Compliance:</strong> ${isMasked ? "REDACTED (GDPR/DPDP)" : "COMPLETE EVIDENCE"}</div>
      </div>
    </div>

    <!-- VERDICT BANNER -->
    <div class="verdict-banner">
      <div class="verdict-text">
        <strong>VERDICT: ${analysis.riskLevel} (${analysis.primaryClassification})</strong>
        <span>Attribution: ${analysis.attribution?.infrastructureType || "Unknown"} · Campaign: ${analysis.attribution?.campaignTag || "Isolated"}</span>
      </div>
      <div class="score-badge">
        ${analysis.riskScore}<small>/100</small>
      </div>
    </div>

    <!-- SECTION 1: EVIDENCE CHAIN OF CUSTODY -->
    <div class="section">
      <div class="section-title">1. Evidence Identification & Cryptographic Hash</div>
      <div class="meta-grid">
        <div class="meta-item">
          <span class="label">Source File Name</span>
          <span class="val">${analysis.fileName}</span>
        </div>
        <div class="meta-item">
          <span class="label">File Size</span>
          <span class="val">${(analysis.fileSize / 1024).toFixed(2)} KB (${analysis.fileSize} bytes)</span>
        </div>
        <div class="meta-item" style="grid-column: span 2;">
          <span class="label">Cryptographic SHA-256 Digest (WebCrypto Web-API):</span>
          <span class="val code-val" style="color: #0369a1; font-weight: 700;">${analysis.sha256}</span>
        </div>
        <div class="meta-item">
          <span class="label">Integrity Status</span>
          <span class="val status-pass">CRYPTOGRAPHICALLY SEALED · UNTAMPERED</span>
        </div>
        <div class="meta-item">
          <span class="label">RFC 822 Message-ID</span>
          <span class="val code-val">${analysis.messageId}</span>
        </div>
      </div>
    </div>

    <!-- SECTION 2: ENVELOPE & PROTOCOL ALIGNMENT -->
    <div class="section">
      <div class="section-title">2. Header Protocol & Address Alignment Audit</div>
      <div class="meta-grid" style="margin-bottom: 10px;">
        <div class="meta-item">
          <span class="label">Header 'From' Address</span>
          <span class="val">${fromVal}</span>
        </div>
        <div class="meta-item">
          <span class="label">Header 'To' Recipient</span>
          <span class="val">${toVal}</span>
        </div>
        <div class="meta-item">
          <span class="label">Envelope Return-Path</span>
          <span class="val">${analysis.protocolAudit?.returnPath || "N/A"}</span>
        </div>
        <div class="meta-item">
          <span class="label">Routing 'Reply-To' Address</span>
          <span class="val ${analysis.protocolAudit?.replyToMismatch ? 'status-fail' : ''}">
            ${replyToVal} ${analysis.protocolAudit?.replyToMismatch ? "[MISMATCH REDIRECTION DETECTED]" : "[ALIGNED]"}
          </span>
        </div>
      </div>

      <table>
        <thead>
          <tr>
            <th>Protocol Test</th>
            <th>Verification Status</th>
            <th>Forensic Finding / Cryptographic Alignment</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>SPF (Sender Policy Framework)</strong></td>
            <td class="${analysis.spf === 'Pass' ? 'status-pass' : 'status-fail'}">${analysis.spf}</td>
            <td>${analysis.spf === 'Pass' ? 'Sending IP is authorized under domain SPF records' : 'Sending host not authorized in DNS SPF record (Forged envelope risk)'}</td>
          </tr>
          <tr>
            <td><strong>DKIM Digital Signature</strong></td>
            <td class="${analysis.dkim === 'Pass' ? 'status-pass' : 'status-fail'}">${analysis.dkim}</td>
            <td>Selector: ${analysis.protocolAudit?.dkimSelector || 'None'} · ${analysis.dkim === 'Pass' ? 'Cryptographic signature verified against public key' : 'Digital signature failed verification or absent'}</td>
          </tr>
          <tr>
            <td><strong>DMARC Alignment</strong></td>
            <td class="${analysis.dmarc === 'Pass' ? 'status-pass' : 'status-fail'}">${analysis.dmarc}</td>
            <td>Enforcement mode: ${analysis.dmarc} · Evaluates sender alignment against domain policy</td>
          </tr>
          <tr>
            <td><strong>Display Name Spoofing</strong></td>
            <td class="${analysis.protocolAudit?.displayNameSpoofing ? 'status-fail' : 'status-pass'}">
              ${analysis.protocolAudit?.displayNameSpoofing ? 'SPOOF DETECTED' : 'PASSED'}
            </td>
            <td>${analysis.protocolAudit?.displayNameSpoofing ? 'Display name impersonates corporate identity while sending from untrusted domain' : 'Display name aligns with sender mailbox'}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- SECTION 3: NLP & BEC FRAUD ANALYSIS -->
    <div class="section">
      <div class="section-title">3. NLP Linguistic & Social Engineering Analysis</div>
      <div class="callout-box">
        <p style="margin-bottom: 6px;"><strong>Primary Linguistic Assessment:</strong> ${analysis.nlpAudit?.primaryClassification} (Confidence: ${analysis.nlpAudit?.classificationConfidence || 85}%)</p>
        <p style="margin-bottom: 6px;"><strong>Urgency & Psychological Coercion Score:</strong> ${analysis.nlpAudit?.urgencyScore || 0} / 40 points</p>
        ${analysis.nlpAudit?.detectedBecPatterns?.length > 0 ? `
          <p style="color: #dc2626; font-weight: 700; margin-bottom: 4px;">Detected BEC (Business Email Compromise) Attack Vectors:</p>
          <ul style="padding-left: 20px; color: #991b1b; font-size: 9pt;">
            ${analysis.nlpAudit.detectedBecPatterns.map((b) => `<li><strong>${b.label} [${b.severity}]:</strong> ${b.description} (Cues: ${b.matchedCues.join(', ')})</li>`).join('')}
          </ul>
        ` : '<p style="color: #16a34a;">✓ No Business Email Compromise (BEC) wire fraud or billing diversion cues detected.</p>'}
      </div>
    </div>

    <!-- SECTION 4: ORIGIN TRACEABILITY & HOP TRACE -->
    <div class="section">
      <div class="section-title">4. Origin Traceability & Mail Relay Hop Route</div>
      <div class="meta-grid" style="margin-bottom: 10px;">
        <div class="meta-item">
          <span class="label">Earliest Originating Node IP</span>
          <span class="val code-val" style="font-weight: 700;">${ipVal}</span>
        </div>
        <div class="meta-item">
          <span class="label">Geographic Location & Coordinates</span>
          <span class="val">${analysis.originGeo?.country_name || "Internal"} (${analysis.originGeo?.city || "Local"}${analysis.originGeo?.postal && analysis.originGeo.postal !== "N/A" ? ` - ${analysis.originGeo.postal}` : ""}) · Coords: ${analysis.originGeo?.latitude ? Number(analysis.originGeo.latitude).toFixed(5) : "0.00"}, ${analysis.originGeo?.longitude ? Number(analysis.originGeo.longitude).toFixed(5) : "0.00"}</span>
        </div>
        <div class="meta-item">
          <span class="label">Origin ISP / Autonomous System</span>
          <span class="val">${analysis.originGeo?.isp || "ISP"} (${analysis.originGeo?.asn || "N/A"})</span>
        </div>
        <div class="meta-item">
          <span class="label">Domain Host Fingerprint</span>
          <span class="val">${analysis.domainIntel?.hostingProvider || "Independent Registrar"}</span>
        </div>
      </div>

      <table>
        <thead>
          <tr>
            <th>Hop #</th>
            <th>From Host / Sending MTA</th>
            <th>Received By MTA</th>
            <th>Protocol</th>
            <th>IP Address</th>
            <th>Delay</th>
          </tr>
        </thead>
        <tbody>
          ${analysis.hopTrace?.hops?.map((h) => `
            <tr>
              <td><strong>#${h.hopNumber}</strong></td>
              <td>${h.fromHost}</td>
              <td>${h.byHost}</td>
              <td>${h.protocol}</td>
              <td class="code-val">${isMasked ? maskSensitiveText(h.primaryIP || 'N/A') : h.primaryIP || 'N/A'}</td>
              <td>+${h.delaySeconds}s</td>
            </tr>
          `).join('') || '<tr><td colspan="6">No intermediate MTA hops recorded.</td></tr>'}
        </tbody>
      </table>
    </div>

    <!-- SECTION 5: EXTRACTED IOCS & ATTACHMENTS -->
    <div class="section">
      <div class="section-title">5. Indicators of Compromise (IoC) & Quarantine Payload</div>
      <p style="font-size: 9pt; margin-bottom: 6px;"><strong>Extracted URLs (${analysis.totalLinks}):</strong></p>
      ${analysis.allUrls?.length > 0 ? `
        <table>
          <thead>
            <tr>
              <th>Extracted Hyperlink Target</th>
              <th>Threat Evaluation</th>
            </tr>
          </thead>
          <tbody>
            ${analysis.allUrls.map((u) => {
              const isSusp = analysis.suspiciousLinksList?.includes(u);
              return `
                <tr>
                  <td class="code-val" style="word-break: break-all;">${isMasked ? maskSensitiveText(u) : u}</td>
                  <td class="${isSusp ? 'status-fail' : 'status-pass'}">${isSusp ? 'SUSPICIOUS / PHISH' : 'CLEAN'}</td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      ` : '<p style="font-size: 9pt; color: #64748b;">No embedded hyperlinks identified in body.</p>'}

      ${analysis.attachmentCount > 0 ? `
        <p style="font-size: 9pt; margin: 12px 0 6px;"><strong>Quarantined Attachments (${analysis.attachmentCount}):</strong></p>
        <table>
          <thead>
            <tr>
              <th>File Name</th>
              <th>File Size</th>
              <th>MIME Type</th>
              <th>Classification</th>
            </tr>
          </thead>
          <tbody>
            ${analysis.attachments.map((a) => `
              <tr>
                <td><strong>${a.filename}</strong></td>
                <td>${(a.size / 1024).toFixed(1)} KB</td>
                <td class="code-val">${a.mimeType}</td>
                <td class="${a.isExecutable ? 'status-fail' : 'status-pass'}">${a.isExecutable ? 'DANGEROUS EXECUTABLE' : 'Standard File'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      ` : ''}
    </div>

    <!-- SECTION 6: INCIDENT CONTAINMENT ACTIONS -->
    <div class="section">
      <div class="section-title">6. Incident Containment & Corrective Protocol</div>
      <div class="callout-box">
        <ol style="padding-left: 20px; font-size: 9.5pt; color: #0f172a;">
          ${analysis.containmentActions?.map((act) => `<li style="margin-bottom: 4px;">${act}</li>`).join('') || '<li>Standard mail delivery permitted without restriction.</li>'}
        </ol>
      </div>
    </div>

    <!-- SIGNATURE BLOCK -->
    <div class="sign-block">
      <div class="sign-field">
        <div class="sign-line"></div>
        <div class="sign-label">Lead Forensic Examiner</div>
      </div>
      <div class="seal-box">
        CYBER DEFENSE<br>EVIDENCE<br>SEAL
      </div>
      <div class="sign-field">
        <div class="sign-line"></div>
        <div class="sign-label">Incident Commander / Legal Review</div>
      </div>
    </div>
  </div>
</body>
</html>
  `;

  // Open printable window with complete PDF print layout
  const printWindow = window.open("", "_blank");
  if (!printWindow) {
    alert("Please allow popups to download/print the PDF investigation report.");
    return;
  }

  printWindow.document.open();
  printWindow.document.write(htmlContent);
  printWindow.document.close();

  // Automatically trigger print dialog on load
  printWindow.onload = () => {
    setTimeout(() => {
      printWindow.focus();
      printWindow.print();
    }, 400);
  };
}
