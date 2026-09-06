import {
  AlertTriangle,
  FileSearch,
  Hash,
  Link2,
  Lock,
  Mail,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";
import ModulePage from "../components/ModulePage";
import StatCard from "../components/StatCard";

export default function ThreatIntelligence({ analysis, setActivePage }) {
  const senderDomain = analysis?.from?.includes("@")
    ? analysis.from.split("@")[1].replace(/[<>]/g, "").trim()
    : "Unknown";

  return (
    <ModulePage
      title="Threat Intelligence & Indicators of Compromise (IoC)"
      subtitle="Correlation of email indicators with threat intelligence, BEC fraud patterns, domain clusters, and attribution telemetry."
      icon={<ShieldAlert size={28} />}
    >
      <div className="stat-grid" style={{ marginBottom: "24px" }}>
        <StatCard
          icon={<AlertTriangle />}
          label="Threat Classification"
          value={analysis?.primaryClassification ? analysis.primaryClassification.split("/")[0] : analysis ? "Clean" : "None"}
          change={analysis?.classificationConfidence ? `${analysis.classificationConfidence}% Conf.` : "Model"}
          danger={analysis?.riskScore >= 70}
          warning={analysis?.riskScore >= 40 && analysis?.riskScore < 70}
          success={analysis && analysis.riskScore < 40}
        />

        <StatCard
          icon={<Link2 />}
          label="Suspicious Links"
          value={analysis?.suspiciousLinks ?? 0}
          change={analysis?.suspiciousLinks > 0 ? "Flagged URLs" : "Safe"}
          warning={analysis?.suspiciousLinks > 0}
          success={analysis && analysis.suspiciousLinks === 0}
        />

        <StatCard
          icon={<Hash />}
          label="Multi-Factor Threat Score"
          value={analysis?.riskScore ? `${analysis.riskScore}/100` : "0/100"}
          change={analysis?.riskLevel || "No scan"}
          purple
        />

        <StatCard
          icon={<Lock />}
          label="Authentication Audit"
          value={
            analysis?.spf === "Pass" && analysis?.dkim === "Pass"
              ? "Verified"
              : analysis
              ? "Failed/Degraded"
              : "Waiting"
          }
          change={analysis ? `SPF:${analysis.spf}` : "Idle"}
          success={analysis?.spf === "Pass" && analysis?.dkim === "Pass"}
          danger={analysis && (analysis.spf === "Fail" || analysis.dkim === "Fail")}
        />
      </div>

      {!analysis ? (
        <div className="panel empty-analysis" style={{ textAlign: "center", padding: "40px 20px" }}>
          <ShieldAlert size={42} style={{ color: "#94a3b8", margin: "0 auto 12px" }} />
          <h3>No Threat Intelligence Data</h3>
          <p>Scan an email via Dashboard or Analyze Email to populate IoC feeds and threat indicators.</p>
          <button
            className="primary-button"
            style={{ marginTop: "16px" }}
            onClick={() => setActivePage("dashboard")}
          >
            <FileSearch size={16} /> Go to Dashboard
          </button>
        </div>
      ) : (
        <div className="main-grid">
          {/* SENDER & DOMAIN SPOOF ANALYSIS */}
          <div className="panel" style={{ gridColumn: "1 / -1" }}>
            <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Mail size={18} /> Sender & Domain Intelligence Fingerprint
            </h3>
            <p>Verification of sender infrastructure, hosting fingerprints, and domain alignment.</p>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                gap: "16px",
                marginTop: "16px",
                background: "#f8fafc",
                padding: "16px",
                borderRadius: "8px",
              }}
            >
              <div>
                <span style={{ fontSize: "12px", color: "#64748b" }}>Sender Address & Domain:</span>
                <strong style={{ display: "block", color: "#1e293b", fontSize: "14px" }}>
                  {analysis.from} ({senderDomain})
                </strong>
              </div>

              <div>
                <span style={{ fontSize: "12px", color: "#64748b" }}>Hosting Provider:</span>
                <strong style={{ display: "block", color: "#1e293b", fontSize: "14px" }}>
                  {analysis.domainIntel?.hostingProvider || "Standard Registrar"}
                </strong>
              </div>

              <div>
                <span style={{ fontSize: "12px", color: "#64748b" }}>Typosquatting Assessment:</span>
                <strong
                  style={{
                    display: "block",
                    color: analysis.domainIntel?.typosquattingDetected ? "#dc2626" : "#16a34a",
                    fontSize: "14px",
                  }}
                >
                  {analysis.domainIntel?.typosquattingDetected
                    ? `Deceptive Impersonation (${analysis.domainIntel.typosquattingTarget})`
                    : "Legitimate Brand Syntax"}
                </strong>
              </div>

              <div>
                <span style={{ fontSize: "12px", color: "#64748b" }}>Attribution Infrastructure:</span>
                <strong style={{ display: "block", color: "#2563eb", fontSize: "14px" }}>
                  {analysis.attribution?.infrastructureType || "Analyzed Node"}
                </strong>
              </div>
            </div>
          </div>

          {/* BEC & SOCIAL ENGINEERING PATTERNS */}
          <div className="panel">
            <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Zap size={18} /> BEC Fraud Patterns & Urgency Cues
            </h3>
            <p>Detection of wire diversion, fake invoice requests, and psychological manipulation.</p>

            {analysis.nlpAudit?.detectedBecPatterns?.length === 0 && analysis.nlpAudit?.detectedTriggers?.length === 0 ? (
              <div style={{ marginTop: "16px", color: "#16a34a", display: "flex", alignItems: "center", gap: "6px" }}>
                <ShieldCheck size={16} /> No social engineering or fraudulent patterns detected.
              </div>
            ) : (
              <div style={{ display: "grid", gap: "10px", marginTop: "16px" }}>
                {analysis.nlpAudit?.detectedBecPatterns?.map((b, i) => (
                  <div key={i} style={{ background: "#fff1f2", padding: "10px 14px", borderRadius: "6px", border: "1px solid #fecaca" }}>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <strong style={{ color: "#991b1b", fontSize: "13px" }}>{b.label}</strong>
                      <span style={{ fontSize: "11px", fontWeight: "700", color: "#dc2626" }}>{b.severity}</span>
                    </div>
                    <p style={{ margin: "2px 0 0", fontSize: "12px", color: "#7f1d1d" }}>{b.description}</p>
                  </div>
                ))}

                {analysis.nlpAudit?.detectedTriggers?.map((t, i) => (
                  <div key={i} style={{ background: "#fffbeb", padding: "10px 14px", borderRadius: "6px", border: "1px solid #fde68a" }}>
                    <strong style={{ color: "#92400e", fontSize: "13px" }}>{t.category}</strong>
                    <p style={{ margin: "2px 0 0", fontSize: "12px", color: "#78350f" }}>Cues: {t.matchedCues.join(", ")}</p>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* SUSPICIOUS LINKS & ATTACHMENTS */}
          <div className="panel">
            <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Link2 size={18} /> Extracted Link IOCs & Attachments
            </h3>
            <p>Quarantined URLs and hazardous executable payloads.</p>

            {analysis.suspiciousLinksList?.length === 0 && analysis.dangerousAttachments?.length === 0 ? (
              <div style={{ marginTop: "16px", color: "#16a34a", display: "flex", alignItems: "center", gap: "6px" }}>
                <ShieldCheck size={16} /> No dangerous attachments or malicious URLs flagged.
              </div>
            ) : (
              <div style={{ marginTop: "12px", display: "grid", gap: "8px" }}>
                {analysis.dangerousAttachments?.map((a, i) => (
                  <div key={i} style={{ background: "#fee2e2", padding: "8px 12px", borderRadius: "6px", color: "#991b1b", fontSize: "12px" }}>
                    <strong>[HIGH RISK EXECUTABLE]</strong> {a.filename} ({(a.size / 1024).toFixed(1)} KB)
                  </div>
                ))}

                {analysis.suspiciousLinksList?.map((link, i) => (
                  <div key={i} style={{ background: "#fef2f2", padding: "8px 12px", borderRadius: "6px", color: "#b91c1c", fontSize: "12px", fontFamily: "monospace", wordBreak: "break-all" }}>
                    <strong>[MALICIOUS URL]</strong> {link}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </ModulePage>
  );
}
