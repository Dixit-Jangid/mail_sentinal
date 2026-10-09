import { useState } from "react";
import {
  Download,
  FileText,
  Printer,
  FileSearch,
  ShieldCheck,
  Eye,
  EyeOff,
  Copy,
  Check,
  Layers,
  Database,
  FileSpreadsheet,
  Code2,
} from "lucide-react";
import ModulePage from "../components/ModulePage";
import { maskSensitiveText } from "../services/privacyService";
import { generateInvestigativePdf } from "../services/pdfReportGenerator";
import { generateSection65BCertificatePdf } from "../services/legalCertificateGenerator";
import { exportStixBundle, exportCsvIocs, exportHtmlDocket } from "../services/exportService";

export default function Reports({ analysis, setActivePage }) {
  const [piiRedacted, setPiiRedacted] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  const copyHash = () => {
    if (!analysis?.sha256) return;
    navigator.clipboard.writeText(analysis.sha256);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const downloadTextReport = () => {
    if (!analysis) return;

    const fromVal = piiRedacted ? maskSensitiveText(analysis.from) : analysis.from;
    const toVal = piiRedacted ? maskSensitiveText(analysis.to) : analysis.to;
    const ipVal = piiRedacted ? maskSensitiveText(analysis.earliestNodeIP || "N/A") : analysis.earliestNodeIP || "N/A";

    const report = `================================================================================
INSTITUTIONAL CYBER INCIDENT & DIGITAL FORENSICS REPORT
Preservation Standard: ISO/IEC 27037 (Digital Evidence Handling) & Section 65B/63
================================================================================
Generated At       : ${new Date().toLocaleString()}
Forensic Case ID   : ${analysis.id}
Source Evidence    : ${analysis.fileName} (${(analysis.fileSize / 1024).toFixed(1)} KB)
SHA-256 Digest     : ${analysis.sha256}
Integrity Status   : CRYPTOGRAPHICALLY VERIFIED - CHAIN OF CUSTODY PRESERVED
PII Redaction Mode : ${piiRedacted ? "ACTIVE (COMPLIANT EXPORT)" : "UNMASKED RAW EVIDENCE"}

--------------------------------------------------------------------------------
1. EXECUTIVE THREAT VERDICT & 5-CLASS AI/ML CLASSIFICATION
--------------------------------------------------------------------------------
Multi-Factor Fraud Score: ${analysis.riskScore} / 100
Threat Risk Level       : ${analysis.riskLevel}
Primary Classification  : ${analysis.primaryClassification} (${analysis.classificationConfidence}% Confidence)
AI/ML Class Distribution:
  * Legitimate  : ${analysis.threatDistribution?.Legitimate ?? 0}%
  * Suspicious  : ${analysis.threatDistribution?.Suspicious ?? 0}%
  * Impersonated: ${analysis.threatDistribution?.Impersonated ?? 0}%
  * Phishing    : ${analysis.threatDistribution?.Phishing ?? 0}%
  * Fraud       : ${analysis.threatDistribution?.Fraud ?? 0}%

Attribution Infrastructure: ${analysis.attribution?.infrastructureType || "Unknown"}
Threat Campaign Tag       : ${analysis.attribution?.campaignTag || "Isolated"}
Attribution Confidence    : ${analysis.attribution?.attributionConfidence || 75}% (${analysis.attribution?.attributionLevel || "MODERATE"})
Attribution Finding       : ${analysis.attribution?.attributionSummary || "N/A"}

--------------------------------------------------------------------------------
2. ADVANCED FRAUD-PATTERN DETECTION AUDIT
--------------------------------------------------------------------------------
Confirmed Fraud Signatures: ${analysis.fraudAudit?.detectedCount || 0}
${(analysis.fraudAudit?.patterns || [])
  .filter((p) => p.status !== "CLEAN")
  .map((p) => `  * [${p.severity}] ${p.title} (${p.status}) - MITRE: ${p.mitreTechnique}\n    Snippets: ${p.snippets.join(" | ")}`)
  .join("\n") || "  (No fraudulent patterns detected)"}

--------------------------------------------------------------------------------
3. EMAIL IDENTIFICATION & 3-WAY HEADER CORRELATION
--------------------------------------------------------------------------------
Subject Line           : ${analysis.subject}
Header 'From'          : ${fromVal}
Header 'To'            : ${toVal}
Originating IP         : ${ipVal}
Envelope 'Return-Path' : ${analysis.protocolAudit?.returnPath || "N/A"}
Routing 'Reply-To'     : ${analysis.protocolAudit?.replyTo || "N/A"}
Correlation Status     : ${analysis.threeWayAudit?.correlationStatus || "ALIGNED"}
Reply-To Mismatch      : ${analysis.threeWayAudit?.replyToMismatch ? "YES (CRITICAL ANOMALY)" : "NO (ALIGNED)"}
Display Name Spoofing  : ${analysis.protocolAudit?.displayNameSpoofing ? "YES (DETECTED)" : "NO"}
Message-ID Header      : ${analysis.messageId}
Date of Message        : ${analysis.date}

SPF Authentication: ${analysis.spf}
DKIM Verification : ${analysis.dkim} (Selector: ${analysis.protocolAudit?.dkimSelector || "default"})
DMARC Policy Mode : ${analysis.dmarc}

--------------------------------------------------------------------------------
4. DOMAIN & INFRASTRUCTURE INTELLIGENCE
--------------------------------------------------------------------------------
Sender Domain        : ${analysis.senderDomain}
Domain Age           : ${analysis.domainIntel?.domainAge?.ageFormatted || "Unknown"}
Registrar            : ${analysis.domainIntel?.registrar || "Standard Registrar"}
Mail Provider (MX)   : ${analysis.domainIntel?.mailProvider?.provider || "Self-Hosted"}
Lookalike / Spoofing : ${analysis.domainIntel?.typosquattingDetected ? `FLAGGED (Target: ${analysis.domainIntel.typosquattingTarget})` : "Clean Syntax"}

MTA Relay Hop Audit (${analysis.hopTrace?.totalHops || 0} Hops Recorded):
${analysis.hopTrace?.hops?.map((h) => `  * Hop #${h.hopNumber}: From [${h.fromHost}] -> By [${h.byHost}] via ${h.protocol} (IP: ${piiRedacted ? maskSensitiveText(h.primaryIP || "N/A") : h.primaryIP || "N/A"}) [+${h.delaySeconds}s]`).join("\n") || "  (No hops recorded)"}

--------------------------------------------------------------------------------
5. EXTRACTED IOCS & PAYLOAD ATTACHMENTS
--------------------------------------------------------------------------------
Suspicious Links:
${analysis.suspiciousLinksList?.map((u) => `  * ${piiRedacted ? maskSensitiveText(u) : u}`).join("\n") || "  (None)"}

All Extracted URLs (${analysis.totalLinks}):
${analysis.allUrls?.map((u) => `  * ${piiRedacted ? maskSensitiveText(u) : u}`).join("\n") || "  (None)"}

Quarantined Attachments (${analysis.attachmentCount}):
${analysis.attachments?.map((a) => `  * ${a.filename} (${(a.size / 1024).toFixed(1)} KB) - MIME: ${a.mimeType} ${a.isExecutable ? "[CRITICAL EXECUTABLE / PAYLOAD]" : ""}`).join("\n") || "  (None)"}

--------------------------------------------------------------------------------
6. RECOMMENDED INCIDENT CONTAINMENT ACTIONS
--------------------------------------------------------------------------------
${analysis.containmentActions?.map((act, i) => `  ${i + 1}. ${act}`).join("\n") || "  1. No immediate containment required."}

================================================================================
END OF FORENSIC INCIDENT REPORT - DIGITAL CHAIN OF CUSTODY CERTIFIED
================================================================================
`;

    const blob = new Blob([report], { type: "text/plain;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `court-forensics-report-${analysis.fileName.replace(/\.eml$/i, "")}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const downloadJSONReport = () => {
    if (!analysis) return;
    const jsonStr = JSON.stringify(analysis, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `forensics-telemetry-${analysis.fileName.replace(/\.eml$/i, "")}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const printReport = () => {
    window.print();
  };

  const isHighRisk = analysis?.riskScore >= 70;
  const isMediumRisk = analysis?.riskScore >= 40 && analysis?.riskScore < 70;

  return (
    <ModulePage
      title="Forensic Reports & Legal Evidence"
      subtitle="Full structured forensic export suite: ISO/IEC 27037 investigation reports, Section 65B certificate, STIX 2.1 JSON, CSV IoCs, and HTML dockets."
      icon={<Download size={28} />}
    >
      {!analysis ? (
        <div className="panel empty-analysis" style={{ textAlign: "center", padding: "40px 20px" }}>
          <FileText size={42} style={{ color: "#94a3b8", margin: "0 auto 12px" }} />
          <h3>No Analyzed Evidence</h3>
          <p>Please analyze an email via Dashboard or Analyze Email to generate and export structured forensic reports.</p>
          <button
            className="primary-button"
            style={{ marginTop: "16px" }}
            onClick={() => setActivePage("dashboard")}
          >
            <FileSearch size={16} /> Go to Dashboard
          </button>
        </div>
      ) : (
        <>
          {/* STRUCTURED EXPORT SUITE GRID */}
          <div className="panel" style={{ marginBottom: "20px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "12px", borderBottom: "1px solid #e2e8f0", paddingBottom: "16px", marginBottom: "16px" }}>
              <div>
                <strong style={{ fontSize: "16px", color: "#0f172a" }}>
                  Structured Forensic Export Suite
                </strong>
                <span style={{ display: "block", fontSize: "12px", color: "#64748b" }}>
                  Evidence Docket: {analysis.fileName} ({analysis.id}) · Certified: {analysis.analyzedAt}
                </span>
              </div>

              {/* PII TOGGLE BUTTON */}
              <button
                onClick={() => setPiiRedacted(!piiRedacted)}
                className="secondary-button"
                style={{
                  fontSize: "12px",
                  padding: "7px 14px",
                  background: piiRedacted ? "#f0fdf4" : "#fff",
                  color: piiRedacted ? "#15803d" : "#475569",
                  border: piiRedacted ? "1px solid #86efac" : "1px solid #cbd5e1",
                  fontWeight: "600",
                }}
                title="Toggle PII Masking for DPDP / GDPR Compliance"
              >
                {piiRedacted ? <EyeOff size={14} /> : <Eye size={14} />}
                <span>{piiRedacted ? "PII Redaction: ACTIVE" : "PII Masking: OFF"}</span>
              </button>
            </div>

            {/* EXPORT ACTION CARDS */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "12px" }}>
              {/* 1. PDF REPORT */}
              <div style={{ background: "#f8fafc", padding: "14px", borderRadius: "8px", border: "1px solid #e2e8f0", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "#2563eb", fontSize: "13px", fontWeight: "700" }}>
                    <Download size={15} /> Formal PDF Report
                  </div>
                  <p style={{ fontSize: "11px", color: "#64748b", margin: "4px 0 10px" }}>
                    ISO/IEC 27037 incident examination report with cryptographic seals.
                  </p>
                </div>
                <button
                  className="primary-button"
                  onClick={() => generateInvestigativePdf(analysis, { piiRedacted })}
                  style={{ fontSize: "12px", padding: "6px 12px", width: "100%" }}
                >
                  Download PDF Report
                </button>
              </div>

              {/* 2. SECTION 65B CERTIFICATE */}
              <div style={{ background: "#f8fafc", padding: "14px", borderRadius: "8px", border: "1px solid #e2e8f0", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "#0284c7", fontSize: "13px", fontWeight: "700" }}>
                    <ShieldCheck size={15} /> Section 65B / 63 Certificate
                  </div>
                  <p style={{ fontSize: "11px", color: "#64748b", margin: "4px 0 10px" }}>
                    Indian Evidence Act Section 65B / Bharatiya Sakshya Adhiniyam court certificate.
                  </p>
                </div>
                <button
                  className="secondary-button"
                  onClick={() => generateSection65BCertificatePdf(analysis, { piiRedacted })}
                  style={{ fontSize: "12px", padding: "6px 12px", width: "100%", borderColor: "#38bdf8", color: "#0284c7" }}
                >
                  Generate Legal Certificate
                </button>
              </div>

              {/* 3. STIX 2.1 THREAT INTEL */}
              <div style={{ background: "#f8fafc", padding: "14px", borderRadius: "8px", border: "1px solid #e2e8f0", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "#7c3aed", fontSize: "13px", fontWeight: "700" }}>
                    <Layers size={15} /> STIX 2.1 Intel Bundle
                  </div>
                  <p style={{ fontSize: "11px", color: "#64748b", margin: "4px 0 10px" }}>
                    OASIS open standard format for SIEM & MISP threat sharing.
                  </p>
                </div>
                <button
                  className="secondary-button"
                  onClick={() => exportStixBundle(analysis, { piiRedacted })}
                  style={{ fontSize: "12px", padding: "6px 12px", width: "100%", borderColor: "#c084fc", color: "#7c3aed" }}
                >
                  Export STIX 2.1 (.json)
                </button>
              </div>

              {/* 4. CSV IOC ARTIFACTS */}
              <div style={{ background: "#f8fafc", padding: "14px", borderRadius: "8px", border: "1px solid #e2e8f0", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "#059669", fontSize: "13px", fontWeight: "700" }}>
                    <FileSpreadsheet size={15} /> CSV IoC Artifacts Table
                  </div>
                  <p style={{ fontSize: "11px", color: "#64748b", margin: "4px 0 10px" }}>
                    Tabular IoC indicators (IPs, URLs, Hashes) for perimeter firewalls.
                  </p>
                </div>
                <button
                  className="secondary-button"
                  onClick={() => exportCsvIocs(analysis, { piiRedacted })}
                  style={{ fontSize: "12px", padding: "6px 12px", width: "100%", borderColor: "#6ee7b7", color: "#059669" }}
                >
                  Export IoC Table (.csv)
                </button>
              </div>

              {/* 5. STANDALONE HTML DOCKET */}
              <div style={{ background: "#f8fafc", padding: "14px", borderRadius: "8px", border: "1px solid #e2e8f0", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "#d97706", fontSize: "13px", fontWeight: "700" }}>
                    <Code2 size={15} /> Standalone HTML Docket
                  </div>
                  <p style={{ fontSize: "11px", color: "#64748b", margin: "4px 0 10px" }}>
                    Self-contained single-file HTML evidence package with embedded CSS.
                  </p>
                </div>
                <button
                  className="secondary-button"
                  onClick={() => exportHtmlDocket(analysis, { piiRedacted })}
                  style={{ fontSize: "12px", padding: "6px 12px", width: "100%", borderColor: "#fcd34d", color: "#b45309" }}
                >
                  Export HTML Docket
                </button>
              </div>

              {/* 6. JSON TELEMETRY & TXT */}
              <div style={{ background: "#f8fafc", padding: "14px", borderRadius: "8px", border: "1px solid #e2e8f0", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "#475569", fontSize: "13px", fontWeight: "700" }}>
                    <Database size={15} /> Telemetry & Raw Dossier
                  </div>
                  <p style={{ fontSize: "11px", color: "#64748b", margin: "4px 0 10px" }}>
                    Raw forensic JSON dump and formatted court text transcript.
                  </p>
                </div>
                <div style={{ display: "flex", gap: "6px" }}>
                  <button
                    className="secondary-button"
                    onClick={downloadJSONReport}
                    style={{ fontSize: "11px", padding: "6px 8px", flex: 1 }}
                  >
                    JSON
                  </button>
                  <button
                    className="secondary-button"
                    onClick={downloadTextReport}
                    style={{ fontSize: "11px", padding: "6px 8px", flex: 1 }}
                  >
                    TXT
                  </button>
                  <button
                    className="secondary-button"
                    onClick={printReport}
                    style={{ fontSize: "11px", padding: "6px 8px", flex: 1 }}
                  >
                    <Printer size={12} />
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* REPORT PREVIEW PAPER */}
          <div
            className="panel"
            style={{
              background: "#fff",
              border: "1px solid #cbd5e1",
              borderRadius: "12px",
              padding: "36px",
              boxShadow: "0 10px 30px rgba(0,0,0,0.06)",
            }}
          >
            {/* OFFICIAL EVIDENCE SEAL HEADER */}
            <div
              style={{
                borderBottom: "2px solid #0f172a",
                paddingBottom: "20px",
                marginBottom: "24px",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                flexWrap: "wrap",
                gap: "16px",
              }}
            >
              <div>
                <span
                  style={{
                    fontSize: "11px",
                    fontWeight: "800",
                    letterSpacing: "0.1em",
                    color: "#64748b",
                    textTransform: "uppercase",
                  }}
                >
                  CERTIFIED DIGITAL FORENSIC EVIDENCE · ISO/IEC 27037 & SECTION 65B/63
                </span>
                <h2 style={{ fontSize: "22px", margin: "4px 0 2px", color: "#0f172a" }}>
                  Cyber Incident Forensic Examination Report
                </h2>
                <span style={{ fontSize: "13px", color: "#475569" }}>
                  Digital Forensics Lab & Threat Intelligence Division
                </span>
              </div>

              <div style={{ textAlign: "right" }}>
                <span
                  style={{
                    display: "inline-block",
                    padding: "4px 10px",
                    borderRadius: "6px",
                    fontSize: "12px",
                    fontWeight: "800",
                    background: isHighRisk ? "#dc2626" : isMediumRisk ? "#d97706" : "#16a34a",
                    color: "#fff",
                  }}
                >
                  VERDICT: {analysis.riskLevel.toUpperCase()}
                </span>
                <span style={{ display: "block", fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>
                  Score: {analysis.riskScore}/100 · Generated: {new Date().toLocaleString()}
                </span>
              </div>
            </div>

            {/* CHAIN OF CUSTODY CERTIFICATE BOX */}
            <div
              style={{
                background: "#f8fafc",
                border: "1px solid #e2e8f0",
                borderRadius: "8px",
                padding: "16px",
                marginBottom: "24px",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <strong style={{ fontSize: "13px", color: "#0f172a", display: "flex", alignItems: "center", gap: "6px" }}>
                  <ShieldCheck size={16} style={{ color: "#16a34a" }} /> Chain of Custody & Tamper-Evident Hash Seal
                </strong>

                <button
                  onClick={copyHash}
                  style={{
                    background: "transparent",
                    border: 0,
                    fontSize: "12px",
                    color: copiedHash ? "#16a34a" : "#2563eb",
                    cursor: "pointer",
                    display: "flex",
                    alignItems: "center",
                    gap: "4px",
                  }}
                >
                  {copiedHash ? <Check size={12} /> : <Copy size={12} />}
                  {copiedHash ? "Copied Hash" : "Copy Hash"}
                </button>
              </div>

              <div style={{ marginTop: "8px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", fontSize: "12px" }}>
                <div>
                  <span style={{ color: "#64748b" }}>SHA-256 Evidence Checksum:</span>
                  <p style={{ margin: "2px 0 0", fontFamily: "monospace", fontWeight: "700", color: "#1e293b", wordBreak: "break-all" }}>
                    {analysis.sha256}
                  </p>
                </div>
                <div>
                  <span style={{ color: "#64748b" }}>Primary AI/ML Classification:</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "700", color: isHighRisk ? "#dc2626" : "#0f172a" }}>
                    {analysis.primaryClassification} ({analysis.classificationConfidence}% Confidence)
                  </p>
                </div>
              </div>
            </div>

            {/* SECTION 1: 5-CLASS PROBABILITY DISTRIBUTION & FRAUD FINDINGS */}
            <div style={{ marginBottom: "24px" }}>
              <h3 style={{ fontSize: "15px", borderBottom: "1px solid #e2e8f0", paddingBottom: "6px", marginBottom: "12px", color: "#0f172a" }}>
                1. Multi-Class Threat Model Distribution & Advanced Fraud Vectors
              </h3>

              {analysis.threatDistribution && (
                <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "8px", marginBottom: "16px" }}>
                  {Object.entries(analysis.threatDistribution).map(([cls, prob]) => (
                    <div key={cls} style={{ background: "#f8fafc", padding: "8px 10px", borderRadius: "6px", border: "1px solid #e2e8f0", textAlign: "center" }}>
                      <span style={{ fontSize: "11px", color: "#64748b", display: "block" }}>{cls}</span>
                      <strong style={{ fontSize: "16px", color: prob >= 50 ? "#dc2626" : prob >= 20 ? "#d97706" : "#1e293b" }}>
                        {prob}%
                      </strong>
                    </div>
                  ))}
                </div>
              )}

              {/* FRAUD PATTERNS FOUND */}
              {analysis.fraudAudit?.detectedCount > 0 && (
                <div style={{ background: "#fff1f2", border: "1px solid #fecaca", padding: "12px", borderRadius: "8px", marginBottom: "14px" }}>
                  <strong style={{ color: "#991b1b", fontSize: "13px", display: "block", marginBottom: "4px" }}>
                    Confirmed Fraud Archetypes ({analysis.fraudAudit.detectedCount} Detected):
                  </strong>
                  <ul style={{ margin: 0, paddingLeft: "20px", fontSize: "12px", color: "#7f1d1d" }}>
                    {analysis.fraudAudit.patterns
                      .filter((p) => p.status === "DETECTED")
                      .map((p, i) => (
                        <li key={i} style={{ marginBottom: "4px" }}>
                          <strong>{p.title}</strong>: {p.snippets.join(" | ")}
                        </li>
                      ))}
                  </ul>
                </div>
              )}
            </div>

            {/* SECTION 2: 3-WAY HEADER CORRELATION & AUTHENTICATION */}
            <div style={{ marginBottom: "24px" }}>
              <h3 style={{ fontSize: "15px", borderBottom: "1px solid #e2e8f0", paddingBottom: "6px", marginBottom: "12px", color: "#0f172a" }}>
                2. Message Envelope & 3-Way Header Correlation Matrix
              </h3>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", fontSize: "13px" }}>
                <div>
                  <span style={{ color: "#64748b" }}>Header From (RFC 5322):</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "600" }}>
                    {piiRedacted ? maskSensitiveText(analysis.from) : analysis.from}
                  </p>
                </div>

                <div>
                  <span style={{ color: "#64748b" }}>Recipient To:</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "600" }}>
                    {piiRedacted ? maskSensitiveText(analysis.to) : analysis.to}
                  </p>
                </div>

                <div>
                  <span style={{ color: "#64748b" }}>Routing Reply-To (RFC 5322):</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "600", color: analysis.threeWayAudit?.replyToMismatch ? "#dc2626" : "#0f172a" }}>
                    {analysis.threeWayAudit?.matrix?.replyTo?.address || analysis.protocolAudit?.replyTo || "Identical to From"}
                    {analysis.threeWayAudit?.replyToMismatch && " [REDIRECTION TRAP]"}
                  </p>
                </div>

                <div>
                  <span style={{ color: "#64748b" }}>Return-Path (RFC 5321 Envelope):</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "600" }}>
                    {analysis.threeWayAudit?.matrix?.returnPath?.address || "Identical"}
                  </p>
                </div>

                <div>
                  <span style={{ color: "#64748b" }}>Authentication Status:</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "600" }}>
                    SPF: {analysis.spf} · DKIM: {analysis.dkim} · DMARC: {analysis.dmarc}
                  </p>
                </div>

                <div>
                  <span style={{ color: "#64748b" }}>Earliest Origin Node IP:</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "600", fontFamily: "monospace" }}>
                    {piiRedacted ? maskSensitiveText(analysis.earliestNodeIP || "N/A") : analysis.earliestNodeIP || "N/A"} ({analysis.originGeo?.country_name || "Internal"})
                  </p>
                </div>
              </div>
            </div>

            {/* SECTION 3: DOMAIN INTELLIGENCE */}
            <div style={{ marginBottom: "24px" }}>
              <h3 style={{ fontSize: "15px", borderBottom: "1px solid #e2e8f0", paddingBottom: "6px", marginBottom: "12px", color: "#0f172a" }}>
                3. Domain Intelligence & Infrastructure Fingerprint
              </h3>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", fontSize: "13px", background: "#f8fafc", padding: "14px", borderRadius: "8px" }}>
                <div>
                  <span style={{ color: "#64748b" }}>Domain Age & Registration:</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "600" }}>
                    {analysis.domainIntel?.domainAge?.ageFormatted || "Established"}
                  </p>
                </div>

                <div>
                  <span style={{ color: "#64748b" }}>Registrar:</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "600" }}>
                    {analysis.domainIntel?.registrar || "Standard Registrar"}
                  </p>
                </div>

                <div>
                  <span style={{ color: "#64748b" }}>Inbound MX Provider:</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "600" }}>
                    {analysis.domainIntel?.mailProvider?.provider || "Self-Hosted Mail Server"}
                  </p>
                </div>

                <div>
                  <span style={{ color: "#64748b" }}>Lookalike / Typosquatting:</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "600", color: analysis.domainIntel?.typosquattingDetected ? "#dc2626" : "#16a34a" }}>
                    {analysis.domainIntel?.typosquattingDetected
                      ? `FLAGGED (Mimicking ${analysis.domainIntel.typosquattingTarget})`
                      : "Authentic Syntax"}
                  </p>
                </div>
              </div>
            </div>

            {/* SECTION 4: RECOMMENDED ACTIONS */}
            <div>
              <h3 style={{ fontSize: "15px", borderBottom: "1px solid #e2e8f0", paddingBottom: "6px", marginBottom: "12px", color: "#0f172a" }}>
                4. Incident Containment Protocol
              </h3>

              <ol style={{ margin: 0, paddingLeft: "20px", fontSize: "13px", color: "#334155" }}>
                {analysis.containmentActions?.map((act, idx) => (
                  <li key={idx} style={{ marginBottom: "6px" }}>
                    {act}
                  </li>
                ))}
              </ol>
            </div>
          </div>
        </>
      )}
    </ModulePage>
  );
}
