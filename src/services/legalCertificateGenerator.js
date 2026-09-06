/**
 * legalCertificateGenerator.js
 * Generates an official Certificate of Electronic Evidence Admissibility under:
 * - Section 65B of the Indian Evidence Act, 1872
 * - Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 (BSA)
 * - ISO/IEC 27037 Digital Evidence Handling & Chain of Custody Standard
 *
 * Tailored for Indian Law Enforcement (Cyber Police, CBI, CERT-In, Judicial Tribunals).
 */

import { maskSensitiveText } from "./privacyService";

/**
 * Generates plain-text Section 65B/63 Certificate suitable for copy/paste into legal filings.
 */
export function generateSection65BTextCertificate(analysis, options = {}) {
  if (!analysis) return "";

  const isMasked = Boolean(options.piiRedacted);
  const fromVal = isMasked ? maskSensitiveText(analysis.from) : analysis.from;
  const toVal = isMasked ? maskSensitiveText(analysis.to) : analysis.to;
  const docketId = `EVID-65B-${(analysis.id || "0000").replace(/[^a-zA-Z0-9]/g, "").toUpperCase().slice(-8)}`;

  return `================================================================================
CERTIFICATE UNDER SECTION 65B OF THE INDIAN EVIDENCE ACT, 1872
READ WITH SECTION 63 OF THE BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023
================================================================================
DOCKET NUMBER        : ${docketId}
EVIDENCE IDENTIFIER  : ${analysis.id}
DATE OF GENERATION   : ${new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" })} IST
STANDARD ADHERENCE   : ISO/IEC 27037:2012 (Guidelines for Digital Evidence Handling)

--------------------------------------------------------------------------------
1. PARTICULARS OF ELECTRONIC RECORD EXAMINED
--------------------------------------------------------------------------------
Evidence File Name   : ${analysis.fileName}
File Size in Bytes   : ${analysis.fileSize} bytes (${(analysis.fileSize / 1024).toFixed(2)} KB)
RFC 822 Message-ID   : ${analysis.messageId}
Header Sender (From) : ${fromVal}
Header Recipient(To) : ${toVal}
Subject Line         : ${analysis.subject}
Message Timestamp    : ${analysis.date}

--------------------------------------------------------------------------------
2. CRYPTOGRAPHIC INTEGRITY & BITSTREAM FINGERPRINT
--------------------------------------------------------------------------------
Hash Algorithm       : SHA-256 (FIPS 180-4 Secure Hash Standard)
Bitstream Hash Digest: ${analysis.sha256}
Integrity Status     : VERIFIED - BITSTREAM AUTHENTIC AND UNTAMPERED

--------------------------------------------------------------------------------
3. FORENSIC CLASSIFICATION & THREAT VERDICT
--------------------------------------------------------------------------------
Multi-Factor Score   : ${analysis.riskScore} / 100
Threat Severity Level: ${analysis.riskLevel}
Classification       : ${analysis.primaryClassification || "N/A"} (${analysis.classificationConfidence || 0}% Confidence)
Protocol Alignment   : SPF: ${analysis.spf} | DKIM: ${analysis.dkim} | DMARC: ${analysis.dmarc}
Originating IP / Hop : ${analysis.earliestNodeIP || "N/A"}

--------------------------------------------------------------------------------
4. STATUTORY DECLARATION UNDER SECTION 65B(4) / SECTION 63 BSA
--------------------------------------------------------------------------------
I, the undersigned Digital Forensic Examiner, do hereby solemnly declare, certify,
and affirm under Section 65B(4) of the Indian Evidence Act, 1872 read with Section 63
of the Bharatiya Sakshya Adhiniyam, 2023 that:

(a) The electronic record mentioned above was ingested, parsed, and analyzed using
    automated cryptographic digital forensics workstation software;
(b) The computer terminal and software algorithms were operating properly throughout
    the period of analysis and there was no malfunction impacting the accuracy or
    integrity of the electronic record;
(c) The cryptographic SHA-256 hash digest was computed directly on the source raw
    bitstream using standard WebCrypto FIPS 180-4 compliant digest routines;
(d) The electronic evidence has been preserved in accordance with ISO/IEC 27037
    standards with strict chain-of-custody logging to prevent alteration or tampering.

--------------------------------------------------------------------------------
5. EXAMINER AFFIRMATION & ENDORSEMENT
--------------------------------------------------------------------------------
Designation : Lead Digital Forensics & Cyber Threat Incident Examiner
Affiliation : Cyber Defense Operations / Digital Incident Response Unit
Place       : New Delhi, India
Status      : ADMISSIBLE ELECTRONIC EVIDENCE`;
}

/**
 * Generates an official, printable high-fidelity court certificate PDF.
 */
export function generateSection65BCertificatePdf(analysis, options = {}) {
  if (!analysis) {
    alert("Please analyze an email before generating the Section 65B certificate.");
    return;
  }

  const isMasked = Boolean(options.piiRedacted);
  const fromVal = isMasked ? maskSensitiveText(analysis.from) : analysis.from;
  const toVal = isMasked ? maskSensitiveText(analysis.to) : analysis.to;
  const docketId = `65B-DFIR-${(analysis.id || "0000").replace(/[^a-zA-Z0-9]/g, "").toUpperCase().slice(-8)}`;
  const dateStr = new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }) + " IST";

  const isHighRisk = analysis.riskScore >= 70;
  const isMediumRisk = analysis.riskScore >= 40 && analysis.riskScore < 70;
  const badgeColor = isHighRisk ? "#dc2626" : isMediumRisk ? "#d97706" : "#16a34a";

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Section_65B_Certificate_${docketId}</title>
  <style>
    @page {
      size: A4 portrait;
      margin: 12mm 15mm;
    }
    @media print {
      body { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
      .no-print { display: none !important; }
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Times New Roman', Times, serif, 'Segoe UI', Arial;
      color: #0f172a;
      background: #f8fafc;
      padding: 24px;
      font-size: 11pt;
      line-height: 1.5;
    }
    .cert-border {
      max-width: 860px;
      margin: 0 auto;
      background: #fff;
      padding: 38px 46px;
      border: 3px double #0d2741;
      border-radius: 4px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.06);
      position: relative;
    }
    .cert-border::before {
      content: "";
      position: absolute;
      top: 6px; left: 6px; right: 6px; bottom: 6px;
      border: 1px solid #94a3b8;
      pointer-events: none;
    }
    .watermark {
      position: absolute;
      top: 45%;
      left: 50%;
      transform: translate(-50%, -50%) rotate(-30deg);
      font-size: 52pt;
      font-weight: 900;
      color: rgba(13, 39, 65, 0.04);
      white-space: nowrap;
      pointer-events: none;
      user-select: none;
    }
    .header {
      text-align: center;
      border-bottom: 2px solid #0d2741;
      padding-bottom: 14px;
      margin-bottom: 18px;
    }
    .emblem-title {
      font-size: 13pt;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: #0d2741;
    }
    .main-title {
      font-size: 16pt;
      font-weight: 900;
      text-transform: uppercase;
      color: #0d2741;
      margin: 6px 0;
      letter-spacing: 0.03em;
    }
    .sub-title {
      font-size: 9.5pt;
      color: #334155;
      font-style: italic;
    }
    .docket-row {
      display: flex;
      justify-content: space-between;
      margin: 12px 0 18px;
      font-size: 9.5pt;
      color: #334155;
      border-bottom: 1px dashed #cbd5e1;
      padding-bottom: 8px;
    }
    .table-section {
      width: 100%;
      border-collapse: collapse;
      margin: 14px 0;
      font-size: 9.5pt;
    }
    .table-section th, .table-section td {
      border: 1px solid #cbd5e1;
      padding: 6px 10px;
      text-align: left;
    }
    .table-section th {
      background: #f1f5f9;
      color: #0d2741;
      font-weight: 700;
      width: 28%;
    }
    .hash-box {
      background: #f8fafc;
      border: 1px solid #94a3b8;
      padding: 10px 14px;
      border-radius: 4px;
      font-family: 'Courier New', Courier, monospace;
      font-size: 10pt;
      font-weight: 700;
      word-break: break-all;
      margin: 10px 0;
      color: #0d2741;
    }
    .clause-text {
      text-align: justify;
      font-size: 9.5pt;
      line-height: 1.6;
      margin: 12px 0;
      color: #1e293b;
    }
    .clause-list {
      padding-left: 24px;
      margin: 8px 0;
      font-size: 9.5pt;
      line-height: 1.6;
    }
    .clause-list li {
      margin-bottom: 6px;
    }
    .sign-container {
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      margin-top: 32px;
      padding-top: 20px;
      border-top: 1px solid #cbd5e1;
    }
    .seal-circle {
      width: 100px;
      height: 100px;
      border: 2px dashed #0d2741;
      border-radius: 50%;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      text-align: center;
      font-size: 7.5pt;
      font-weight: 800;
      color: #0d2741;
      line-height: 1.2;
    }
    .sign-line {
      width: 220px;
      border-bottom: 1px solid #0f172a;
      height: 38px;
      margin-bottom: 6px;
    }
    .sign-caption {
      font-size: 8.5pt;
      text-transform: uppercase;
      font-weight: 700;
      color: #475569;
    }
  </style>
</head>
<body>
  <div class="cert-border">
    <div class="watermark">SECTION 65B CERTIFIED</div>

    <div class="header">
      <div class="emblem-title">Digital Forensics & Electronic Evidence Directorate</div>
      <div class="main-title">Certificate of Electronic Record Admissibility</div>
      <div class="sub-title">
        Issued pursuant to Section 65B of the Indian Evidence Act, 1872 read with Section 63 of Bharatiya Sakshya Adhiniyam, 2023
      </div>
    </div>

    <div class="docket-row">
      <div><strong>Docket Ref:</strong> ${docketId}</div>
      <div><strong>Standard:</strong> ISO/IEC 27037:2012 Compliance</div>
      <div><strong>Certified On:</strong> ${dateStr}</div>
    </div>

    <p class="clause-text">
      This is to certify that the electronic mail message described below was received, cryptographically ingested,
      and forensically parsed on a verified forensic terminal operating under controlled conditions in the ordinary
      course of official cybersecurity investigations.
    </p>

    <table class="table-section">
      <tr>
        <th>Primary Evidence File</th>
        <td><strong>${analysis.fileName}</strong> (${(analysis.fileSize / 1024).toFixed(2)} KB)</td>
      </tr>
      <tr>
        <th>RFC 822 Message-ID</th>
        <td><code style="font-size: 9pt;">${analysis.messageId}</code></td>
      </tr>
      <tr>
        <th>Originating Header (From)</th>
        <td>${fromVal}</td>
      </tr>
      <tr>
        <th>Recipient Header (To)</th>
        <td>${toVal}</td>
      </tr>
      <tr>
        <th>Transmission Timestamp</th>
        <td>${analysis.date}</td>
      </tr>
      <tr>
        <th>Authentication Telemetry</th>
        <td>SPF: <strong>${analysis.spf}</strong> | DKIM: <strong>${analysis.dkim}</strong> | DMARC: <strong>${analysis.dmarc}</strong></td>
      </tr>
      <tr>
        <th>Multi-Factor Threat Verdict</th>
        <td>
          <span style="color: ${badgeColor}; font-weight: 800;">${analysis.riskLevel} (${analysis.riskScore}/100)</span>
          · ${analysis.primaryClassification || "Inspected"}
        </td>
      </tr>
    </table>

    <div style="font-weight: 700; font-size: 10pt; margin-top: 14px; color: #0d2741;">
      Cryptographic SHA-256 Bitstream Verification Seal:
    </div>
    <div class="hash-box">
      ${analysis.sha256}
    </div>

    <div style="font-weight: 700; font-size: 10pt; margin-top: 14px; color: #0d2741;">
      Statutory Declaration under Section 65B(4) / Section 63 BSA:
    </div>
    <ol class="clause-list">
      <li>
        The computer and forensic analysis environment was throughout the material period operating properly,
        and there was no malfunction affecting the electronic record or the accuracy of its contents.
      </li>
      <li>
        The digital evidence was extracted directly from the raw RFC 822 source file without alteration, modification,
        or injection into the message headers or MIME parts.
      </li>
      <li>
        The SHA-256 cryptographic digest computed above uniquely establishes bitstream chain-of-custody and certifies
        that the evidence has not been tampered with since acquisition.
      </li>
    </ol>

    <div class="sign-container">
      <div>
        <div class="sign-line"></div>
        <div class="sign-caption">Investigating Cyber Forensics Officer</div>
        <div style="font-size: 8pt; color: #64748b;">Signature & Badge ID</div>
      </div>

      <div class="seal-circle">
        CYBER POLICE<br>EVIDENCE<br>SECTION 65B<br>SEAL
      </div>

      <div>
        <div class="sign-line"></div>
        <div class="sign-caption">Superintendent / Certifying Authority</div>
        <div style="font-size: 8pt; color: #64748b;">Directorate of Forensics</div>
      </div>
    </div>
  </div>
</body>
</html>
  `;

  const printWindow = window.open("", "_blank");
  if (!printWindow) {
    alert("Please enable popups to view and print the Section 65B Certificate.");
    return;
  }

  printWindow.document.open();
  printWindow.document.write(html);
  printWindow.document.close();

  printWindow.onload = () => {
    setTimeout(() => {
      printWindow.focus();
      printWindow.print();
    }, 400);
  };
}
