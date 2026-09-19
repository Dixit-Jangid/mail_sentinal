import { useState } from "react";
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
  Globe2,
  Server,
  Layers,
  Share2,
  Activity,
} from "lucide-react";
import ModulePage from "../components/ModulePage";
import StatCard from "../components/StatCard";

export default function ThreatIntelligence({ analysis, setActivePage }) {
  const [selectedGraphNode, setSelectedGraphNode] = useState(null);

  const senderDomain = analysis?.from?.includes("@")
    ? analysis.from.split("@")[1].replace(/[<>]/g, "").trim()
    : "Unknown";

  const correlationNodes = analysis?.correlationGraph?.nodes || [];
  const correlationEdges = analysis?.correlationGraph?.edges || [];

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
          value={analysis?.aiClassification?.primaryClass || (analysis ? "Clean" : "None")}
          change={analysis?.classificationConfidence ? `${analysis.classificationConfidence}% Conf.` : "Model"}
          danger={analysis?.riskScore >= 70}
          warning={analysis?.riskScore >= 40 && analysis?.riskScore < 70}
          success={analysis && analysis.riskScore < 40}
        />

        <StatCard
          icon={<Layers />}
          label="Attribution Confidence"
          value={analysis?.attribution?.attributionConfidence ? `${analysis.attribution.attributionConfidence}%` : "0%"}
          change={analysis?.attribution?.attributionLevel ? `${analysis.attribution.attributionLevel} Conf.` : "Telemetry"}
          purple
        />

        <StatCard
          icon={<Hash />}
          label="Multi-Factor Threat Score"
          value={analysis?.riskScore ? `${analysis.riskScore}/100` : "0/100"}
          change={analysis?.riskLevel || "No scan"}
          danger={analysis?.riskScore >= 70}
          warning={analysis?.riskScore >= 40 && analysis?.riskScore < 70}
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
          {/* AI/ML 5-CLASS PROBABILITY DISTRIBUTION */}
          {analysis.threatDistribution && (
            <div className="panel" style={{ gridColumn: "1 / -1" }}>
              <h3 style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                <Activity size={18} style={{ color: "#2563eb" }} /> AI/ML 5-Class Threat Model Distribution
              </h3>
              <p style={{ fontSize: "12px", color: "#64748b", marginBottom: "16px" }}>
                Continuous probabilistic inference across target security classes. Softmax normalized confidence.
              </p>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: "12px" }}>
                {Object.entries(analysis.threatDistribution).map(([cls, prob]) => {
                  const isPrimary = analysis.aiClassification?.primaryClass === cls;
                  const color =
                    cls === "Legitimate" ? "#16a34a" : cls === "Suspicious" ? "#d97706" : "#dc2626";
                  return (
                    <div
                      key={cls}
                      style={{
                        background: isPrimary ? "#f8fafc" : "#ffffff",
                        border: isPrimary ? `2px solid ${color}` : "1px solid #e2e8f0",
                        padding: "12px",
                        borderRadius: "8px",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                        <span style={{ fontSize: "12px", fontWeight: isPrimary ? "800" : "600", color: "#0f172a" }}>
                          {cls}
                        </span>
                        {isPrimary && (
                          <span style={{ fontSize: "10px", background: color, color: "#fff", padding: "1px 6px", borderRadius: "4px", fontWeight: "700" }}>
                            PRIMARY
                          </span>
                        )}
                      </div>

                      <div style={{ fontSize: "20px", fontWeight: "800", color }}>
                        {prob}%
                      </div>

                      <div style={{ width: "100%", height: "6px", background: "#e2e8f0", borderRadius: "3px", marginTop: "8px", overflow: "hidden" }}>
                        <div style={{ width: `${prob}%`, height: "100%", background: color, borderRadius: "3px" }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* ADVANCED FRAUD-PATTERN AUDIT */}
          <div className="panel" style={{ gridColumn: "1 / -1" }}>
            <h3 style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
              <Zap size={18} style={{ color: "#d97706" }} /> Advanced Fraud-Pattern Signatures (5 Archetypes)
            </h3>
            <p style={{ fontSize: "12px", color: "#64748b", marginBottom: "16px" }}>
              Deep linguistic and structural detection of Wire Diversion, Fake Invoices, Credential Harvesting, Executive Impersonation, and BEC.
            </p>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "12px" }}>
              {(analysis.fraudAudit?.patterns || []).map((pat) => {
                const isDetected = pat.status === "DETECTED";
                const isSuspected = pat.status === "SUSPECTED";
                const statusColor = isDetected ? "#dc2626" : isSuspected ? "#d97706" : "#16a34a";
                const statusBg = isDetected ? "#fee2e2" : isSuspected ? "#fef3c7" : "#dcfce7";

                return (
                  <div
                    key={pat.key}
                    style={{
                      background: "#ffffff",
                      border: `1px solid ${isDetected ? "#fca5a5" : "#e2e8f0"}`,
                      borderRadius: "8px",
                      padding: "14px",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "6px" }}>
                      <strong style={{ fontSize: "13px", color: "#0f172a" }}>{pat.title}</strong>
                      <span
                        style={{
                          fontSize: "10px",
                          fontWeight: "800",
                          padding: "2px 8px",
                          borderRadius: "4px",
                          background: statusBg,
                          color: statusColor,
                        }}
                      >
                        {pat.status}
                      </span>
                    </div>

                    <p style={{ fontSize: "11px", color: "#64748b", margin: "2px 0 8px" }}>
                      {pat.description}
                    </p>

                    <div style={{ fontSize: "11px", color: "#475569", marginBottom: "6px" }}>
                      <strong>MITRE ATT&CK:</strong> {pat.mitreTechnique}
                    </div>

                    {pat.snippets?.length > 0 && (
                      <div style={{ background: "#f8fafc", padding: "6px 8px", borderRadius: "4px", fontSize: "11px", color: "#991b1b", fontStyle: "italic", borderLeft: "3px solid #dc2626" }}>
                        "{pat.snippets[0]}"
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* SENDER & DOMAIN INTELLIGENCE */}
          <div className="panel">
            <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Globe2 size={18} style={{ color: "#2563eb" }} /> Domain & WHOIS Intelligence
            </h3>
            <p style={{ fontSize: "12px", color: "#64748b" }}>Live registrar, domain age, and MX classification.</p>

            <div style={{ display: "grid", gap: "10px", marginTop: "14px", fontSize: "13px" }}>
              <div style={{ background: "#f8fafc", padding: "10px 12px", borderRadius: "6px" }}>
                <span style={{ fontSize: "11px", color: "#64748b" }}>Domain Name:</span>
                <strong style={{ display: "block", color: "#0f172a" }}>{analysis.senderDomain || "N/A"}</strong>
              </div>

              <div style={{ background: "#f8fafc", padding: "10px 12px", borderRadius: "6px" }}>
                <span style={{ fontSize: "11px", color: "#64748b" }}>Domain Age & Registration:</span>
                <strong style={{ display: "block", color: analysis.domainIntel?.domainAge?.isNewlyRegistered ? "#dc2626" : "#0f172a" }}>
                  {analysis.domainIntel?.domainAge?.ageFormatted || "Established"}
                </strong>
              </div>

              <div style={{ background: "#f8fafc", padding: "10px 12px", borderRadius: "6px" }}>
                <span style={{ fontSize: "11px", color: "#64748b" }}>Registrar:</span>
                <strong style={{ display: "block", color: "#0f172a" }}>
                  {analysis.domainIntel?.registrar || "Standard Registrar"}
                </strong>
              </div>

              <div style={{ background: "#f8fafc", padding: "10px 12px", borderRadius: "6px" }}>
                <span style={{ fontSize: "11px", color: "#64748b" }}>Inbound MX Provider:</span>
                <strong style={{ display: "block", color: "#2563eb" }}>
                  {analysis.domainIntel?.mailProvider?.provider || "Self-Hosted Mail Server"}
                </strong>
              </div>

              <div style={{ background: "#f8fafc", padding: "10px 12px", borderRadius: "6px" }}>
                <span style={{ fontSize: "11px", color: "#64748b" }}>Lookalike / Typosquatting:</span>
                <strong style={{ display: "block", color: analysis.domainIntel?.typosquattingDetected ? "#dc2626" : "#16a34a" }}>
                  {analysis.domainIntel?.typosquattingDetected
                    ? `DECEPTIVE TYPOSQUATTING (Target: ${analysis.domainIntel.typosquattingTarget})`
                    : "Legitimate Brand Syntax"}
                </strong>
              </div>
            </div>
          </div>

          {/* IDENTITY CORRELATION GRAPH & TOPOLOGY */}
          <div className="panel">
            <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Share2 size={18} style={{ color: "#7c3aed" }} /> Multi-Entity Relationship Graph
            </h3>
            <p style={{ fontSize: "12px", color: "#64748b" }}>
              Topological links connecting Sender ↔ Domain ↔ Origin IP ↔ URL IoCs ↔ Threat Campaign.
            </p>

            <div style={{ marginTop: "14px", display: "grid", gap: "8px" }}>
              {correlationNodes.map((node) => (
                <div
                  key={node.id}
                  onClick={() => setSelectedGraphNode(node)}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "10px 12px",
                    borderRadius: "6px",
                    background: "#f8fafc",
                    border: `1px solid ${node.color}40`,
                    cursor: "pointer",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <div style={{ width: "10px", height: "10px", borderRadius: "50%", background: node.color }} />
                    <strong style={{ fontSize: "13px", color: "#0f172a" }}>{node.label}</strong>
                  </div>
                  <span style={{ fontSize: "11px", color: "#64748b" }}>{node.details || node.type}</span>
                </div>
              ))}
            </div>

            {/* ATTRIBUTION SUMMARY BOX */}
            <div style={{ marginTop: "16px", background: "#f1f5f9", padding: "12px", borderRadius: "8px", fontSize: "12px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                <span style={{ color: "#64748b" }}>Attribution Confidence:</span>
                <strong style={{ color: "#2563eb" }}>{analysis.attribution?.attributionConfidence}%</strong>
              </div>
              <p style={{ margin: 0, color: "#334155" }}>
                {analysis.attribution?.attributionSummary}
              </p>
            </div>
          </div>
        </div>
      )}
    </ModulePage>
  );
}
