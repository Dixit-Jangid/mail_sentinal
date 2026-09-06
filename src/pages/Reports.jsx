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
} from "lucide-react";
import ModulePage from "../components/ModulePage";
import { maskSensitiveText } from "../services/privacyService";
import { generateInvestigativePdf } from "../services/pdfReportGenerator";
import { generateSection65BCertificatePdf } from "../services/legalCertificateGenerator";

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
Preservation Standard: ISO/IEC 27037 (Digital Evidence Handling)
================================================================================
Generated At       : ${new Date().toLocaleString()}
Forensic Case ID   : ${analysis.id}
Source Evidence    : ${analysis.fileName} (${(analysis.fileSize / 1024).toFixed(1)} KB)
SHA-256 Digest     : ${analysis.sha256}
Integrity Status   : CRYPTOGRAPHICALLY VERIFIED - CHAIN OF CUSTODY PRESERVED
PII Redaction Mode : ${piiRedacted ? "ACTIVE (COMPLIANT EXPORT)" : "UNMASKED RAW EVIDENCE"}

--------------------------------------------------------------------------------
1. EXECUTIVE THREAT VERDICT & CLASSIFICATION
--------------------------------------------------------------------------------
Multi-Factor Fraud Score: ${analysis.riskScore} / 100
Threat Risk Level       : ${analysis.riskLevel}
Primary Classification  : ${analysis.primaryClassification} (${analysis.classificationConfidence}% Confidence)
Attribution Infrastructure: ${analysis.attribution?.infrastructureType || "Unknown"}
Threat Campaign Tag     : ${analysis.attribution?.campaignTag || "Isolated"}
Attribution Finding     : ${analysis.attribution?.attributionSummary || "N/A"}

--------------------------------------------------------------------------------
2. EMAIL IDENTIFICATION & PROTOCOL ALIGNMENT AUDIT
--------------------------------------------------------------------------------
Subject Line      : ${analysis.subject}
Header 'From'     : ${fromVal}
Header 'To'       : ${toVal}
Originating IP    : ${ipVal}
Envelope 'Return' : ${analysis.protocolAudit?.returnPath || "N/A"}
Routing 'Reply-To': ${analysis.protocolAudit?.replyTo || "N/A"}
Reply-To Mismatch : ${analysis.protocolAudit?.replyToMismatch ? "YES (CRITICAL ANOMALY)" : "NO (ALIGNED)"}
Display Spoofing  : ${analysis.protocolAudit?.displayNameSpoofing ? "YES (DETECTED)" : "NO"}
Message-ID Header : ${analysis.messageId}
Date of Message   : ${analysis.date}

SPF Authentication: ${analysis.spf}
DKIM Verification : ${analysis.dkim} (Selector: ${analysis.protocolAudit?.dkimSelector || "default"})
DMARC Policy Mode : ${analysis.dmarc}

--------------------------------------------------------------------------------
3. NLP SOCIAL ENGINEERING & BEC (BUSINESS EMAIL COMPROMISE) AUDIT
--------------------------------------------------------------------------------
Urgency Score     : ${analysis.nlpAudit?.urgencyScore || 0} / 40
BEC Severity      : ${analysis.nlpAudit?.highestBecSeverity || "NONE"}
Detected BEC Markers:
${analysis.nlpAudit?.detectedBecPatterns?.map((p) => `  * [${p.severity}] ${p.label}: ${p.matchedCues.join(", ")}`).join("\n") || "  (None detected)"}

Psychological Triggers:
${analysis.nlpAudit?.detectedTriggers?.map((t) => `  * ${t.category}: ${t.matchedCues.join(", ")}`).join("\n") || "  (None detected)"}

--------------------------------------------------------------------------------
4. ORIGIN TRACEABILITY & RELAY ROUTE HOP TRACE
--------------------------------------------------------------------------------
Earliest Origin Node IP: ${ipVal}
Origin Country / City  : ${analysis.originGeo?.country_name || "Internal"} / ${analysis.originGeo?.city || "Local"}
Origin ISP & ASN       : ${analysis.originGeo?.isp || "ISP"} (${analysis.originGeo?.asn || "N/A"})
Domain Host Provider   : ${analysis.domainIntel?.hostingProvider || "Standard"}
Typosquatting Risk     : ${analysis.domainIntel?.typosquattingDetected ? `FLAGGED (Target: ${analysis.domainIntel.typosquattingTarget})` : "Clean"}

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
    link.download = `forensics-dump-${analysis.fileName.replace(/\.eml$/i, "")}.json`;
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
      subtitle="Generate court-ready, law-enforcement standard ISO/IEC 27037 incident documentation with cryptographic chain of custody."
      icon={<Download size={28} />}
    >
      {!analysis ? (
        <div className="panel empty-analysis" style={{ textAlign: "center", padding: "40px 20px" }}>
          <FileText size={42} style={{ color: "#94a3b8", margin: "0 auto 12px" }} />
          <h3>No Analyzed Evidence</h3>
          <p>Please analyze an email to generate and export forensic reports.</p>
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
          {/* ACTION TOOLBAR */}
          <div className="panel" style={{ marginBottom: "20px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "12px" }}>
              <div>
                <strong style={{ fontSize: "15px", color: "#0f172a" }}>
                  Evidence Docket: {analysis.fileName}
                </strong>
                <span style={{ display: "block", fontSize: "12px", color: "#64748b" }}>
                  ID: {analysis.id} · Certified: {analysis.analyzedAt}
                </span>
              </div>

              <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
                {/* PII TOGGLE BUTTON */}
                <button
                  onClick={() => setPiiRedacted(!piiRedacted)}
                  className="secondary-button"
                  style={{
                    fontSize: "12px",
                    padding: "7px 12px",
                    background: piiRedacted ? "#f0fdf4" : "#fff",
                    color: piiRedacted ? "#15803d" : "#475569",
                    border: piiRedacted ? "1px solid #86efac" : "1px solid #cbd5e1",
                  }}
                  title="Toggle PII Masking for Privacy Regulations"
                >
                  {piiRedacted ? <EyeOff size={14} /> : <Eye size={14} />}
                  <span>{piiRedacted ? "PII Redaction: ON" : "PII Masking: OFF"}</span>
                </button>

                <button
                  className="secondary-button"
                  onClick={downloadTextReport}
                  style={{ fontSize: "12px", padding: "7px 12px" }}
                >
                  <Download size={14} /> Court Report (.txt)
                </button>

                <button
                  className="secondary-button"
                  onClick={downloadJSONReport}
                  style={{ fontSize: "12px", padding: "7px 12px" }}
                >
                  <FileText size={14} /> JSON Telemetry Dump
                </button>

                <button
                  className="secondary-button"
                  onClick={printReport}
                  style={{ fontSize: "12px", padding: "7px 12px" }}
                >
                  <Printer size={14} /> Print
                </button>

                <button
                  className="secondary-button"
                  onClick={() => generateSection65BCertificatePdf(analysis, { piiRedacted })}
                  style={{
                    fontSize: "12px",
                    padding: "7px 12px",
                    background: "linear-gradient(135deg, rgba(30, 58, 138, 0.15) 0%, rgba(30, 58, 138, 0.25) 100%)",
                    borderColor: "#3b82f6",
                    color: "#60a5fa",
                    fontWeight: "600",
                  }}
                  title="Generate Section 65B Indian Evidence Act / Section 63 BSA certificate"
                >
                  <ShieldCheck size={14} /> Section 65B Certificate
                </button>

                <button
                  className="primary-button"
                  onClick={() => generateInvestigativePdf(analysis, { piiRedacted })}
                  style={{ fontSize: "12px", padding: "7px 14px", display: "flex", alignItems: "center", gap: "6px" }}
                >
                  <Download size={14} /> Download PDF Report
                </button>
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
                  CERTIFIED DIGITAL FORENSIC EVIDENCE · ISO/IEC 27037
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
                  Generated: {new Date().toLocaleString()}
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
                  <span style={{ color: "#64748b" }}>Primary Classification:</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "700", color: isHighRisk ? "#dc2626" : "#0f172a" }}>
                    {analysis.primaryClassification} ({analysis.classificationConfidence}% Confidence)
                  </p>
                </div>
              </div>
            </div>

            {/* SECTION 1: METADATA */}
            <div style={{ marginBottom: "24px" }}>
              <h3 style={{ fontSize: "15px", borderBottom: "1px solid #e2e8f0", paddingBottom: "6px", marginBottom: "12px", color: "#0f172a" }}>
                1. Message Envelope & Authentication Findings
              </h3>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", fontSize: "13px" }}>
                <div>
                  <span style={{ color: "#64748b" }}>Header From:</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "600" }}>
                    {piiRedacted ? maskSensitiveText(analysis.from) : analysis.from}
                  </p>
                </div>

                <div>
                  <span style={{ color: "#64748b" }}>Recipient (To):</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "600" }}>
                    {piiRedacted ? maskSensitiveText(analysis.to) : analysis.to}
                  </p>
                </div>

                <div>
                  <span style={{ color: "#64748b" }}>Subject Line:</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "600" }}>{analysis.subject}</p>
                </div>

                <div>
                  <span style={{ color: "#64748b" }}>Routing Reply-To:</span>
                  <p style={{ margin: "2px 0 0", fontWeight: "600", color: analysis.protocolAudit?.replyToMismatch ? "#dc2626" : "#0f172a" }}>
                    {analysis.protocolAudit?.replyTo || "Identical to From"}
                    {analysis.protocolAudit?.replyToMismatch && " [MISMATCH REDIRECTION]"}
                  </p>
                </div>

                <div>
                  <span style={{ color: "#64748b" }}>Authentication Verification:</span>
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

            {/* SECTION 2: ATTRIBUTION & NLP FINDINGS */}
            <div style={{ marginBottom: "24px" }}>
              <h3 style={{ fontSize: "15px", borderBottom: "1px solid #e2e8f0", paddingBottom: "6px", marginBottom: "12px", color: "#0f172a" }}>
                2. NLP Linguistic & Attribution Analysis
              </h3>

              <div style={{ background: "#f8fafc", padding: "14px", borderRadius: "8px", fontSize: "13px", color: "#334155" }}>
                <p style={{ margin: "0 0 8px" }}>
                  <strong>Attributed Infrastructure:</strong> {analysis.attribution?.infrastructureType} (Campaign: {analysis.attribution?.campaignTag || "Isolated"})
                </p>
                <p style={{ margin: "0 0 8px" }}>
                  <strong>Assessment Summary:</strong> {analysis.attribution?.attributionSummary}
                </p>
                {analysis.nlpAudit?.detectedBecPatterns?.length > 0 && (
                  <p style={{ margin: 0, color: "#991b1b" }}>
                    <strong>BEC Threat Patterns:</strong> {analysis.nlpAudit.detectedBecPatterns.map((b) => b.label).join(", ")}
                  </p>
                )}
              </div>
            </div>

            {/* SECTION 3: RECOMMENDED ACTIONS */}
            <div>
              <h3 style={{ fontSize: "15px", borderBottom: "1px solid #e2e8f0", paddingBottom: "6px", marginBottom: "12px", color: "#0f172a" }}>
                3. Incident Containment Protocol
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
