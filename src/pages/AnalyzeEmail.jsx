import { useState, useMemo } from "react";
import {
  Upload,
  FileText,
  ShieldCheck,
  AlertTriangle,
  Link2,
  Code,
  ShieldAlert,
  Globe2,
  Network,
  Share2,
  Eye,
  EyeOff,
  Clock,
  Server,
  Zap,
  Tag,
  ExternalLink,
  Copy,
  Check,
  Download,
  MapPin,
  Search,
} from "lucide-react";
import { analyzeEmlFile } from "../services/emailAnalyzer";
import { maskSensitiveText } from "../services/privacyService";
import { generateInvestigativePdf } from "../services/pdfReportGenerator";
import { generateSection65BCertificatePdf } from "../services/legalCertificateGenerator";
import { lookupGeoIP, buildMapLinks } from "../services/geoIpService";
import { checkExonerator, formatExoneratorDate, buildExoneratorUrl } from "../services/exoneratorService";

export default function AnalyzeEmail({
  file,
  setFile,
  analysis,
  onAnalysisComplete,
  onBack,
  settings,
}) {
  const [analyzing, setAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState("overview");
  const [piiRedacted, setPiiRedacted] = useState(false);
  const [headerSearch, setHeaderSearch] = useState("");
  const [copiedHash, setCopiedHash] = useState(false);
  const [activeGeoData, setActiveGeoData] = useState(null);
  const [selectedIpNode, setSelectedIpNode] = useState(null);
  const [manualIpSearch, setManualIpSearch] = useState("");
  const [manualIpLoading, setManualIpLoading] = useState(false);
  const [customExonIp, setCustomExonIp] = useState("");
  const [customExonDate, setCustomExonDate] = useState("");
  const [customExonResult, setCustomExonResult] = useState(null);
  const [exonLoading, setExonLoading] = useState(false);

  const handleVerifyExonerator = async (ipToTest, dateToTest) => {
    const targetIp = (ipToTest || customExonIp || analysis?.earliestNodeIP || "").trim();
    const targetDate = (dateToTest || customExonDate || analysis?.exonerator?.date || analysis?.date || "").trim();
    if (!targetIp) return;
    setExonLoading(true);
    try {
      const result = await checkExonerator(targetIp, targetDate);
      setCustomExonResult(result);
    } catch (err) {
      console.error("ExoneraTor check failed:", err);
    } finally {
      setExonLoading(false);
    }
  };

  const handleSelectIP = async (ip) => {
    if (!ip) return;
    setSelectedIpNode(ip);
    setManualIpLoading(true);
    try {
      const result = await lookupGeoIP(ip);
      setActiveGeoData(result);
    } catch (err) {
      console.error("GeoIP lookup failed:", err);
    } finally {
      setManualIpLoading(false);
    }
  };

  const handleManualSearch = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (!manualIpSearch.trim()) return;
    await handleSelectIP(manualIpSearch.trim());
  };

  const handleFileChange = (event) => {
    const selectedFile = event.target.files?.[0];
    if (!selectedFile) return;

    if (!selectedFile.name.toLowerCase().endsWith(".eml")) {
      alert("Please select a valid .eml email file.");
      return;
    }

    setFile(selectedFile);
  };

  const handleAnalyze = async () => {
    if (!file) {
      alert("Please choose an .eml file first.");
      return;
    }

    setAnalyzing(true);
    try {
      const result = await analyzeEmlFile(file, settings);
      if (onAnalysisComplete) {
        onAnalysisComplete(result);
      }
    } catch (error) {
      console.error("Email analysis failed:", error);
      alert("Unable to analyze this email file. Please ensure it is a valid .eml file.");
    } finally {
      setAnalyzing(false);
    }
  };

  const copyHash = (hash) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  // Filtered Headers for Search
  const headersList = analysis?.headers;
  const filteredHeaders = useMemo(() => {
    if (!headersList) return [];
    if (!headerSearch.trim()) return headersList;
    const query = headerSearch.toLowerCase();
    return headersList.filter(
      (h) =>
        (h.key && h.key.toLowerCase().includes(query)) ||
        (h.value && String(h.value).toLowerCase().includes(query))
    );
  }, [headersList, headerSearch]);

  const isHighRisk = analysis?.riskScore >= 70;
  const isMediumRisk = analysis?.riskScore >= 40 && analysis?.riskScore < 70;

  return (
    <div className="analyze-page" style={{ maxWidth: "1400px", margin: "0 auto" }}>
      {/* TOPBAR NAVIGATION & PII TOGGLE */}
      <div
        className="analyze-header"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "16px",
          marginBottom: "20px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
          <button className="analyze-back" onClick={onBack}>
            <span className="back-arrow">←</span>
            <span>Dashboard</span>
          </button>

          <div>
            <span
              style={{
                fontSize: "11px",
                fontWeight: "700",
                letterSpacing: "0.08em",
                color: "#64748b",
                textTransform: "uppercase",
              }}
            >
              SOC Digital Forensics Lab
            </span>
            <h1 style={{ fontSize: "22px", margin: "2px 0 0", color: "#0f172a" }}>
              AI Email Forensics & Threat Analysis
            </h1>
          </div>
        </div>

        {/* ACTION BUTTONS & PII COMPLIANCE */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
          {analysis && (
            <button
              onClick={() => generateInvestigativePdf(analysis, { piiRedacted })}
              className="primary-button"
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                padding: "8px 16px",
                fontSize: "13px",
                fontWeight: "700",
                background: "linear-gradient(135deg, #1d4ed8 0%, #1e40af 100%)",
                color: "#fff",
                borderRadius: "8px",
                border: "0",
                cursor: "pointer",
                boxShadow: "0 2px 8px rgba(29, 78, 216, 0.25)",
              }}
              title="Download formal DFIR forensic investigation report formatted to ISO/IEC 27037"
            >
              <Download size={15} />
              <span>Download PDF Report</span>
            </button>
          )}

          <button
            onClick={() => setPiiRedacted(!piiRedacted)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              padding: "8px 14px",
              borderRadius: "8px",
              fontSize: "13px",
              fontWeight: "600",
              border: piiRedacted ? "1px solid #16a34a" : "1px solid #cbd5e1",
              background: piiRedacted ? "#f0fdf4" : "#fff",
              color: piiRedacted ? "#15803d" : "#475569",
              cursor: "pointer",
            }}
            title="Toggle Privacy Redaction for DPDP/GDPR/Compliance"
          >
            {piiRedacted ? <EyeOff size={16} /> : <Eye size={16} />}
            <span>{piiRedacted ? "PII Redaction: ACTIVE" : "PII Masking: Off"}</span>
          </button>
        </div>
      </div>

      {/* REAL-TIME CRITICAL THREAT ADVISORY BANNER */}
      {analysis && (
        <div
          style={{
            marginBottom: "24px",
            borderRadius: "12px",
            padding: "18px 22px",
            border: isHighRisk
              ? "1px solid #fca5a5"
              : isMediumRisk
                ? "1px solid #fcd34d"
                : "1px solid #86efac",
            background: isHighRisk
              ? "linear-gradient(135deg, #fff1f2 0%, #ffe4e6 100%)"
              : isMediumRisk
                ? "linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%)"
                : "linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%)",
            boxShadow: "0 4px 16px rgba(0,0,0,0.04)",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
              <div
                style={{
                  width: "44px",
                  height: "44px",
                  borderRadius: "10px",
                  display: "grid",
                  placeItems: "center",
                  background: isHighRisk ? "#ef4444" : isMediumRisk ? "#f59e0b" : "#22c55e",
                  color: "#fff",
                  boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
                }}
              >
                {isHighRisk ? <ShieldAlert size={26} /> : isMediumRisk ? <AlertTriangle size={26} /> : <ShieldCheck size={26} />}
              </div>

              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                  <span
                    style={{
                      fontSize: "11px",
                      fontWeight: "800",
                      letterSpacing: "0.06em",
                      textTransform: "uppercase",
                      padding: "2px 8px",
                      borderRadius: "4px",
                      background: isHighRisk ? "#dc2626" : isMediumRisk ? "#d97706" : "#16a34a",
                      color: "#fff",
                    }}
                  >
                    {isHighRisk ? "CRITICAL THREAT DETECTED" : isMediumRisk ? "SUSPICIOUS ACTIVITY" : "VERIFIED SAFE EMAIL"}
                  </span>

                  <span
                    style={{
                      fontSize: "13px",
                      fontWeight: "700",
                      color: isHighRisk ? "#991b1b" : isMediumRisk ? "#92400e" : "#166534",
                    }}
                  >
                    Classification: {analysis.primaryClassification} ({analysis.classificationConfidence}% Confidence)
                  </span>

                  {analysis.attribution?.campaignTag && (
                    <span
                      style={{
                        fontSize: "11px",
                        fontWeight: "600",
                        padding: "2px 8px",
                        borderRadius: "20px",
                        background: "#fff",
                        border: "1px solid #cbd5e1",
                        color: "#334155",
                      }}
                    >
                      <Tag size={10} style={{ display: "inline", marginRight: "3px" }} />
                      {analysis.attribution.campaignTag}
                    </span>
                  )}
                </div>

                <p style={{ margin: "6px 0 0", fontSize: "13px", color: "#334155" }}>
                  {analysis.attribution?.attributionSummary ||
                    "Multi-factor analysis complete across NLP cues, protocol alignment, and origin infrastructure."}
                </p>
              </div>
            </div>

            {/* QUICK CONTAINMENT ACTIONS & REPORT TRIGGER */}
            <div
              style={{
                background: "rgba(255,255,255,0.7)",
                borderRadius: "8px",
                padding: "10px 14px",
                border: "1px solid rgba(0,0,0,0.06)",
                display: "flex",
                flexDirection: "column",
                gap: "6px",
              }}
            >
              <span style={{ fontSize: "11px", fontWeight: "700", color: "#475569", textTransform: "uppercase" }}>
                SOC Recommended Containment:
              </span>
              <ul style={{ margin: 0, paddingLeft: "16px", fontSize: "12px", color: "#1e293b" }}>
                {analysis.containmentActions?.slice(0, 2).map((act, i) => (
                  <li key={i}>{act}</li>
                ))}
              </ul>
              <button
                onClick={() => generateInvestigativePdf(analysis, { piiRedacted })}
                style={{
                  marginTop: "6px",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                  padding: "5px 10px",
                  borderRadius: "6px",
                  background: "#0d2741",
                  color: "#fff",
                  border: 0,
                  fontSize: "11px",
                  fontWeight: "700",
                  cursor: "pointer",
                  width: "fit-content",
                }}
              >
                <Download size={12} /> Export Official PDF Report
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TOP WORKBENCH GRID: UPLOAD & QUICK VERDICT */}
      <div className="analyze-grid" style={{ marginBottom: "24px" }}>
        {/* FILE INGESTION CARD */}
        <section className="analyze-card upload-card">
          <div className="card-heading">
            <div className="icon-box blue">
              <Upload size={22} />
            </div>
            <div>
              <h2>Email File Ingestion</h2>
              <p>Upload RFC 822 (.eml) or load incident template</p>
            </div>
          </div>

          <label className="upload-zone" style={{ minHeight: "130px", padding: "18px" }}>
            <input
              type="file"
              accept=".eml,message/rfc822"
              onChange={handleFileChange}
              hidden
            />
            <Upload size={32} style={{ color: "#3b82f6", marginBottom: "8px" }} />
            <strong style={{ fontSize: "14px" }}>
              {file ? file.name : "Drop .eml email file here"}
            </strong>
            <span style={{ fontSize: "12px", color: "#64748b" }}>
              {file
                ? `${(file.size / 1024).toFixed(1)} KB selected`
                : "or click to browse from local computer"}
            </span>
          </label>

          <div style={{ display: "flex", gap: "10px", marginTop: "12px" }}>
            <button
              className="primary-button"
              onClick={handleAnalyze}
              disabled={!file || analyzing}
              style={{ width: "100%" }}
            >
              {analyzing ? "Analyzing Forensics..." : "Analyze Email"}
            </button>
          </div>
        </section>

        {/* SECURITY VERDICT SUMMARY CARD */}
        <section className="analyze-card">
          <div className="card-heading">
            <div className="icon-box purple">
              <ShieldCheck size={22} />
            </div>
            <div>
              <h2>Forensic Triage Verdict</h2>
              <p>Risk rating & multi-factor threat indicators</p>
            </div>
          </div>

          {!analysis ? (
            <div className="empty-analysis" style={{ padding: "24px 12px" }}>
              <FileText size={40} style={{ color: "#cbd5e1", margin: "0 auto 8px" }} />
              <h3 style={{ fontSize: "15px" }}>Awaiting Analysis</h3>
              <p style={{ fontSize: "12px" }}>
                Upload an .eml email above to view comprehensive forensic triage indicators.
              </p>
            </div>
          ) : (
            <div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: "12px",
                  marginBottom: "14px",
                }}
              >
                <div
                  style={{
                    background: "#f8fafc",
                    padding: "12px",
                    borderRadius: "8px",
                    border: "1px solid #e2e8f0",
                  }}
                >
                  <span style={{ fontSize: "11px", color: "#64748b", fontWeight: "600" }}>
                    Multi-Factor Threat Score
                  </span>
                  <div style={{ display: "flex", alignItems: "baseline", gap: "6px", marginTop: "4px" }}>
                    <strong
                      style={{
                        fontSize: "26px",
                        color: isHighRisk ? "#dc2626" : isMediumRisk ? "#d97706" : "#16a34a",
                      }}
                    >
                      {analysis.riskScore}
                    </strong>
                    <span style={{ fontSize: "13px", color: "#94a3b8" }}>/ 100</span>
                    <span
                      style={{
                        fontSize: "11px",
                        fontWeight: "700",
                        padding: "2px 6px",
                        borderRadius: "4px",
                        marginLeft: "auto",
                        background: isHighRisk ? "#fee2e2" : isMediumRisk ? "#fef3c7" : "#dcfce7",
                        color: isHighRisk ? "#b91c1c" : isMediumRisk ? "#b45309" : "#15803d",
                      }}
                    >
                      {analysis.riskLevel}
                    </span>
                  </div>
                </div>

                <div
                  style={{
                    background: "#f8fafc",
                    padding: "12px",
                    borderRadius: "8px",
                    border: "1px solid #e2e8f0",
                  }}
                >
                  <span style={{ fontSize: "11px", color: "#64748b", fontWeight: "600" }}>
                    Earliest Sending Node IP
                  </span>
                  <div style={{ marginTop: "6px" }}>
                    <strong style={{ fontSize: "14px", fontFamily: "monospace", color: "#1e293b" }}>
                      {piiRedacted ? maskSensitiveText(analysis.earliestNodeIP || "N/A") : analysis.earliestNodeIP || "Private/Internal"}
                    </strong>
                    <span style={{ display: "block", fontSize: "11px", color: "#64748b", marginTop: "2px" }}>
                      {analysis.originGeo?.country_name || "Internal Subnet"} · {analysis.originGeo?.city || "Local"}
                    </span>
                  </div>
                </div>
              </div>

              {/* AUTH BADGES ROW */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(4, 1fr)",
                  gap: "8px",
                  fontSize: "11px",
                  textAlign: "center",
                }}
              >
                <div style={{ padding: "8px 4px", borderRadius: "6px", background: analysis.spf === "Pass" ? "#f0fdf4" : "#fef2f2", border: analysis.spf === "Pass" ? "1px solid #bbf7d0" : "1px solid #fecaca" }}>
                  <span style={{ color: "#64748b", display: "block" }}>SPF</span>
                  <strong style={{ color: analysis.spf === "Pass" ? "#16a34a" : "#dc2626" }}>{analysis.spf}</strong>
                </div>

                <div style={{ padding: "8px 4px", borderRadius: "6px", background: analysis.dkim === "Pass" ? "#f0fdf4" : "#fef2f2", border: analysis.dkim === "Pass" ? "1px solid #bbf7d0" : "1px solid #fecaca" }}>
                  <span style={{ color: "#64748b", display: "block" }}>DKIM</span>
                  <strong style={{ color: analysis.dkim === "Pass" ? "#16a34a" : "#dc2626" }}>{analysis.dkim}</strong>
                </div>

                <div style={{ padding: "8px 4px", borderRadius: "6px", background: analysis.dmarc === "Pass" ? "#f0fdf4" : "#fef2f2", border: analysis.dmarc === "Pass" ? "1px solid #bbf7d0" : "1px solid #fecaca" }}>
                  <span style={{ color: "#64748b", display: "block" }}>DMARC</span>
                  <strong style={{ color: analysis.dmarc === "Pass" ? "#16a34a" : "#dc2626" }}>{analysis.dmarc}</strong>
                </div>

                <div style={{ padding: "8px 4px", borderRadius: "6px", background: analysis.dangerousAttachments?.length > 0 ? "#fef2f2" : "#f8fafc", border: "1px solid #e2e8f0" }}>
                  <span style={{ color: "#64748b", display: "block" }}>Files</span>
                  <strong style={{ color: analysis.dangerousAttachments?.length > 0 ? "#dc2626" : "#334155" }}>
                    {analysis.attachmentCount} Att.
                  </strong>
                </div>
              </div>
            </div>
          )}
        </section>
      </div>

      {/* DETAILED FORENSICS TABS SECTION */}
      {analysis && (
        <section className="analyze-card details-card" style={{ padding: "20px" }}>
          {/* TAB BUTTONS */}
          <div
            style={{
              display: "flex",
              gap: "6px",
              flexWrap: "wrap",
              borderBottom: "1px solid #e2e8f0",
              paddingBottom: "12px",
              marginBottom: "20px",
            }}
          >
            {[
              { id: "overview", label: "Executive Summary", icon: FileText },
              { id: "formal_report", label: "Investigation Report", icon: FileText },
              { id: "nlp", label: `NLP & BEC Cues (${analysis.nlpAudit?.detectedTriggers?.length || 0})`, icon: Zap },
              { id: "auth", label: "Protocol & Alignment", icon: ShieldCheck },
              { id: "route", label: `Mail Hop Trace (${analysis.hopTrace?.totalHops || 0})`, icon: Network },
              { id: "exonerator", label: analysis.isTorExitNode ? "ExoneraTor (Tor Alert!)" : "ExoneraTor (Tor Forensics)", icon: ShieldAlert },
              { id: "origin", label: "Origin Radar & Geo", icon: Globe2 },
              { id: "attribution", label: "Attribution Graph", icon: Share2 },
              { id: "links", label: `IOCs & Links (${analysis.totalLinks})`, icon: Link2 },
              { id: "headers", label: `Raw Headers (${analysis.headers?.length || 0})`, icon: Code },
            ].map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                    padding: "8px 14px",
                    borderRadius: "8px",
                    fontSize: "13px",
                    fontWeight: isActive ? "700" : "500",
                    border: 0,
                    background: isActive ? "#0d2741" : "#f1f5f9",
                    color: isActive ? "#fff" : "#475569",
                    cursor: "pointer",
                    transition: "all 0.18s ease",
                  }}
                >
                  <Icon size={14} />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>

          {/* TAB 1: EXECUTIVE SUMMARY */}
          {activeTab === "overview" && (
            <div>
              <div className="details-grid" style={{ marginBottom: "20px" }}>
                <div>
                  <span>File Name</span>
                  <strong>{analysis.fileName}</strong>
                </div>

                <div>
                  <span>SHA-256 Checksum</span>
                  <strong style={{ display: "flex", alignItems: "center", gap: "6px", fontFamily: "monospace", fontSize: "11px" }}>
                    {analysis.sha256.substring(0, 18)}...
                    <button
                      onClick={() => copyHash(analysis.sha256)}
                      style={{ background: "transparent", border: 0, cursor: "pointer", color: copiedHash ? "#16a34a" : "#2563eb" }}
                      title="Copy full SHA-256 hash"
                    >
                      {copiedHash ? <Check size={12} /> : <Copy size={12} />}
                    </button>
                  </strong>
                </div>

                <div>
                  <span>Sender (From)</span>
                  <strong>{piiRedacted ? maskSensitiveText(analysis.from) : analysis.from}</strong>
                </div>

                <div>
                  <span>Recipient (To)</span>
                  <strong>{piiRedacted ? maskSensitiveText(analysis.to) : analysis.to}</strong>
                </div>

                <div>
                  <span>Subject Line</span>
                  <strong>{analysis.subject}</strong>
                </div>

                <div>
                  <span>Date & Message-ID</span>
                  <strong style={{ fontSize: "11px", wordBreak: "break-all" }}>
                    {analysis.date} · {analysis.messageId}
                  </strong>
                </div>

                <div>
                  <span>Primary Threat Class</span>
                  <strong style={{ color: isHighRisk ? "#dc2626" : isMediumRisk ? "#d97706" : "#16a34a" }}>
                    {analysis.primaryClassification}
                  </strong>
                </div>

                <div>
                  <span>Attribution Classification</span>
                  <strong>{analysis.attribution?.infrastructureType || "Unknown"}</strong>
                </div>
              </div>

              {/* HIGHLIGHTED RISK FACTORS SUMMARY */}
              <div
                style={{
                  background: "#f8fafc",
                  borderRadius: "10px",
                  border: "1px solid #e2e8f0",
                  padding: "16px",
                  marginTop: "16px",
                }}
              >
                <h3 style={{ fontSize: "15px", margin: "0 0 12px", display: "flex", alignItems: "center", gap: "8px" }}>
                  <AlertTriangle size={16} style={{ color: "#f59e0b" }} /> Key Forensic Discoveries
                </h3>

                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "12px" }}>
                  <div style={{ background: "#fff", padding: "12px", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
                    <span style={{ fontSize: "12px", color: "#64748b", fontWeight: "600" }}>Sender Alignment:</span>
                    <p style={{ margin: "4px 0 0", fontSize: "13px", color: analysis.protocolAudit?.replyToMismatch ? "#dc2626" : "#16a34a" }}>
                      {analysis.protocolAudit?.replyToMismatch
                        ? `CRITICAL: Reply-To is diverted to '${analysis.protocolAudit.replyToDomain}'.`
                        : "Reply-To matches Sender From domain."}
                    </p>
                  </div>

                  <div style={{ background: "#fff", padding: "12px", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
                    <span style={{ fontSize: "12px", color: "#64748b", fontWeight: "600" }}>Social Engineering Urgency:</span>
                    <p style={{ margin: "4px 0 0", fontSize: "13px", color: analysis.nlpAudit?.urgencyScore > 15 ? "#dc2626" : "#334155" }}>
                      {analysis.nlpAudit?.detectedTriggers?.length > 0
                        ? `${analysis.nlpAudit.detectedTriggers.length} psychological triggers detected in message body.`
                        : "Neutral tone with low coercive language."}
                    </p>
                  </div>

                  <div style={{ background: "#fff", padding: "12px", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
                    <span style={{ fontSize: "12px", color: "#64748b", fontWeight: "600" }}>Infrastructure Origin:</span>
                    <p style={{ margin: "4px 0 0", fontSize: "13px", color: "#334155" }}>
                      Earliest node: <strong>{analysis.earliestNodeIP || "N/A"}</strong> ({analysis.originGeo?.country_name || "Internal"} - {analysis.originGeo?.isp || "ISP"})
                    </p>
                  </div>

                  <div style={{ background: "#fff", padding: "12px", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
                    <span style={{ fontSize: "12px", color: "#64748b", fontWeight: "600" }}>Domain Integrity:</span>
                    <p style={{ margin: "4px 0 0", fontSize: "13px", color: analysis.domainIntel?.typosquattingDetected ? "#dc2626" : "#334155" }}>
                      {analysis.domainIntel?.typosquattingDetected
                        ? `Typosquatting alert: Deceptively impersonates brand '${analysis.domainIntel.typosquattingTarget}'.`
                        : `Host: ${analysis.domainIntel?.hostingProvider || "Standard DNS"}`}
                    </p>
                  </div>

                  <div style={{ background: analysis.isTorExitNode ? "#fef2f2" : "#fff", padding: "12px", borderRadius: "8px", border: analysis.isTorExitNode ? "1px solid #f87171" : "1px solid #e2e8f0" }}>
                    <span style={{ fontSize: "12px", color: analysis.isTorExitNode ? "#dc2626" : "#64748b", fontWeight: "700" }}>
                      Tor ExoneraTor Verification:
                    </span>
                    <p style={{ margin: "4px 0 0", fontSize: "13px", color: analysis.isTorExitNode ? "#dc2626" : "#16a34a", fontWeight: "600" }}>
                      {analysis.isTorExitNode
                        ? `CONFIRMED: Tor Exit Node on ${analysis.exonerator?.date || "Transmission Date"}!`
                        : `Verified Non-Tor Node for ${analysis.exonerator?.date || "Transmission Date"}`}
                    </p>
                    {analysis.officialExoneratorUrl && (
                      <a
                        href={analysis.officialExoneratorUrl}
                        target="_blank"
                        rel="noreferrer"
                        style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "11px", color: "#2563eb", marginTop: "4px", textDecoration: "underline" }}
                      >
                        <ExternalLink size={10} /> View Official Tor Project Docket
                      </a>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB: FORMAL INVESTIGATION REPORT (ISO/IEC 27037) */}
          {activeTab === "formal_report" && (
            <div>
              {/* REPORT TOOLBAR */}
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: "12px",
                  padding: "14px 18px",
                  background: "#0d2741",
                  borderRadius: "10px",
                  color: "#fff",
                  marginBottom: "20px",
                }}
              >
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span
                      style={{
                        fontSize: "10px",
                        fontWeight: "800",
                        letterSpacing: "0.08em",
                        background: "#22c55e",
                        color: "#0f172a",
                        padding: "2px 8px",
                        borderRadius: "4px",
                      }}
                    >
                      EVIDENTIARY AUDIT READY
                    </span>
                    <span style={{ fontSize: "12px", color: "#94a3b8" }}>
                      Docket: DFIR-{analysis.id.substring(5, 14).toUpperCase()}
                    </span>
                  </div>
                  <h3 style={{ margin: "4px 0 0", fontSize: "16px", color: "#fff" }}>
                    Digital Forensics Investigation Report (ISO/IEC 27037)
                  </h3>
                </div>

                <div style={{ display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" }}>
                  <button
                    onClick={() => setPiiRedacted(!piiRedacted)}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                      padding: "8px 14px",
                      borderRadius: "6px",
                      fontSize: "12px",
                      fontWeight: "600",
                      background: piiRedacted ? "rgba(34, 197, 94, 0.2)" : "rgba(255, 255, 255, 0.1)",
                      border: piiRedacted ? "1px solid #22c55e" : "1px solid rgba(255, 255, 255, 0.2)",
                      color: piiRedacted ? "#4ade80" : "#fff",
                      cursor: "pointer",
                    }}
                    title="Toggle PII Masking"
                  >
                    {piiRedacted ? <EyeOff size={14} /> : <Eye size={14} />}
                    <span>{piiRedacted ? "PII: REDACTED" : "PII: RAW"}</span>
                  </button>

                  <button
                    onClick={() => generateSection65BCertificatePdf(analysis, { piiRedacted })}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                      padding: "8px 14px",
                      borderRadius: "6px",
                      fontSize: "12px",
                      fontWeight: "700",
                      background: "linear-gradient(135deg, #1e3a8a 0%, #0f172a 100%)",
                      border: "1px solid #3b82f6",
                      color: "#93c5fd",
                      cursor: "pointer",
                    }}
                    title="Generate court-admissible certificate under Section 65B Indian Evidence Act / Section 63 BSA 2023"
                  >
                    <ShieldCheck size={14} /> Section 65B Certificate
                  </button>

                  <button
                    onClick={() => generateInvestigativePdf(analysis, { piiRedacted })}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                      padding: "8px 18px",
                      borderRadius: "6px",
                      fontSize: "13px",
                      fontWeight: "700",
                      background: "linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)",
                      color: "#fff",
                      border: 0,
                      cursor: "pointer",
                      boxShadow: "0 4px 14px rgba(59, 130, 246, 0.4)",
                    }}
                  >
                    <Download size={15} /> Download PDF Report
                  </button>
                </div>
              </div>

              {/* FORMAL REPORT PAPER */}
              <div
                style={{
                  background: "#ffffff",
                  border: "1px solid #cbd5e1",
                  borderRadius: "12px",
                  padding: "32px 36px",
                  boxShadow: "0 4px 20px rgba(0,0,0,0.05)",
                  color: "#0f172a",
                }}
              >
                {/* LETTERHEAD */}
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-start",
                    borderBottom: "2px solid #0d2741",
                    paddingBottom: "18px",
                    marginBottom: "22px",
                  }}
                >
                  <div>
                    <h2
                      style={{
                        margin: 0,
                        fontSize: "20px",
                        fontWeight: "900",
                        color: "#0d2741",
                        letterSpacing: "0.02em",
                        textTransform: "uppercase",
                      }}
                    >
                      Digital Forensics Examination Report
                    </h2>
                    <p
                      style={{
                        margin: "3px 0 0",
                        fontSize: "12px",
                        color: "#475569",
                        fontWeight: "600",
                        letterSpacing: "0.05em",
                        textTransform: "uppercase",
                      }}
                    >
                      Cyber Incident Response & Threat Analysis Division
                    </p>
                    <div
                      style={{
                        display: "inline-block",
                        marginTop: "8px",
                        padding: "3px 8px",
                        background: "#0d2741",
                        color: "#ffffff",
                        fontSize: "11px",
                        fontWeight: "700",
                        borderRadius: "4px",
                      }}
                    >
                      ISO/IEC 27037 DIGITAL EVIDENCE INTEGRITY STANDARD
                    </div>
                  </div>

                  <div style={{ textAlign: "right", fontSize: "12px", color: "#475569", lineHeight: "1.6" }}>
                    <div>
                      <strong style={{ color: "#0f172a" }}>Docket Ref:</strong> DFIR-{analysis.id.substring(5, 14).toUpperCase()}
                    </div>
                    <div>
                      <strong style={{ color: "#0f172a" }}>Exam Date:</strong> {analysis.analyzedAt}
                    </div>
                    <div>
                      <strong style={{ color: "#0f172a" }}>Evidence File:</strong> {analysis.fileName}
                    </div>
                    <div>
                      <strong style={{ color: "#0f172a" }}>PII Status:</strong>{" "}
                      <span style={{ color: piiRedacted ? "#16a34a" : "#dc2626", fontWeight: "700" }}>
                        {piiRedacted ? "Redacted (GDPR/DPDP Compliant)" : "Unmasked Law Enforcement Evidence"}
                      </span>
                    </div>
                  </div>
                </div>

                {/* VERDICT SUMMARY BANNER */}
                <div
                  style={{
                    background: isHighRisk ? "#fee2e2" : isMediumRisk ? "#fef3c7" : "#dcfce7",
                    borderLeft: `6px solid ${isHighRisk ? "#dc2626" : isMediumRisk ? "#d97706" : "#16a34a"}`,
                    padding: "16px 20px",
                    borderRadius: "6px",
                    marginBottom: "24px",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    flexWrap: "wrap",
                    gap: "12px",
                  }}
                >
                  <div>
                    <span
                      style={{
                        fontSize: "15px",
                        fontWeight: "800",
                        color: isHighRisk ? "#dc2626" : isMediumRisk ? "#d97706" : "#16a34a",
                        textTransform: "uppercase",
                        display: "block",
                      }}
                    >
                      VERDICT: {analysis.riskLevel} ({analysis.primaryClassification})
                    </span>
                    <p style={{ margin: "4px 0 0", fontSize: "13px", color: "#334155", fontWeight: "500" }}>
                      Attribution: <strong>{analysis.attribution?.infrastructureType || "Unknown"}</strong> · Threat Campaign:{" "}
                      <strong>{analysis.attribution?.campaignTag || "Isolated Incident"}</strong>
                    </p>
                  </div>

                  <div style={{ textAlign: "right" }}>
                    <div
                      style={{
                        fontSize: "26px",
                        fontWeight: "900",
                        color: isHighRisk ? "#dc2626" : isMediumRisk ? "#d97706" : "#16a34a",
                      }}
                    >
                      {analysis.riskScore}
                      <span style={{ fontSize: "14px", color: "#64748b", fontWeight: "600" }}>/100</span>
                    </div>
                    <span style={{ fontSize: "11px", fontWeight: "700", textTransform: "uppercase", color: "#64748b" }}>
                      Multi-Factor Threat Index
                    </span>
                  </div>
                </div>

                {/* SECTION 1: CASE EVIDENCE CUSTODY */}
                <div style={{ marginBottom: "24px" }}>
                  <h4
                    style={{
                      fontSize: "13px",
                      fontWeight: "800",
                      textTransform: "uppercase",
                      letterSpacing: "0.06em",
                      color: "#0d2741",
                      borderBottom: "1.5px solid #e2e8f0",
                      paddingBottom: "6px",
                      marginBottom: "12px",
                    }}
                  >
                    1. Chain of Custody & Evidence Metadata
                  </h4>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                      gap: "12px 18px",
                      fontSize: "12px",
                    }}
                  >
                    <div>
                      <span style={{ color: "#64748b", fontWeight: "600", display: "block" }}>Source EML File:</span>
                      <strong style={{ color: "#0f172a" }}>{analysis.fileName} ({(analysis.fileSize / 1024).toFixed(1)} KB)</strong>
                    </div>
                    <div>
                      <span style={{ color: "#64748b", fontWeight: "600", display: "block" }}>SHA-256 Digest:</span>
                      <strong style={{ fontFamily: "monospace", color: "#0f172a", wordBreak: "break-all" }}>
                        {analysis.sha256}
                      </strong>
                    </div>
                    <div>
                      <span style={{ color: "#64748b", fontWeight: "600", display: "block" }}>Sender Header (From):</span>
                      <strong style={{ color: "#0f172a" }}>
                        {piiRedacted ? maskSensitiveText(analysis.from) : analysis.from}
                      </strong>
                    </div>
                    <div>
                      <span style={{ color: "#64748b", fontWeight: "600", display: "block" }}>Recipient Header (To):</span>
                      <strong style={{ color: "#0f172a" }}>
                        {piiRedacted ? maskSensitiveText(analysis.to) : analysis.to}
                      </strong>
                    </div>
                    <div>
                      <span style={{ color: "#64748b", fontWeight: "600", display: "block" }}>Subject Line:</span>
                      <strong style={{ color: "#0f172a" }}>{analysis.subject}</strong>
                    </div>
                    <div>
                      <span style={{ color: "#64748b", fontWeight: "600", display: "block" }}>Message-ID:</span>
                      <strong style={{ fontFamily: "monospace", color: "#0f172a", wordBreak: "break-all" }}>
                        {analysis.messageId}
                      </strong>
                    </div>
                  </div>
                </div>

                {/* SECTION 2: PROTOCOL AUDIT */}
                <div style={{ marginBottom: "24px" }}>
                  <h4
                    style={{
                      fontSize: "13px",
                      fontWeight: "800",
                      textTransform: "uppercase",
                      letterSpacing: "0.06em",
                      color: "#0d2741",
                      borderBottom: "1.5px solid #e2e8f0",
                      paddingBottom: "6px",
                      marginBottom: "12px",
                    }}
                  >
                    2. Authentication & Header Integrity Audit
                  </h4>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
                    <thead>
                      <tr style={{ background: "#f8fafc", textAlign: "left" }}>
                        <th style={{ padding: "8px 10px", border: "1px solid #e2e8f0" }}>Protocol / Check</th>
                        <th style={{ padding: "8px 10px", border: "1px solid #e2e8f0" }}>Verdict</th>
                        <th style={{ padding: "8px 10px", border: "1px solid #e2e8f0" }}>Technical Finding</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td style={{ padding: "8px 10px", border: "1px solid #e2e8f0", fontWeight: "700" }}>SPF Alignment</td>
                        <td style={{ padding: "8px 10px", border: "1px solid #e2e8f0", color: analysis.spf === "Pass" ? "#16a34a" : "#dc2626", fontWeight: "700" }}>
                          {analysis.spf}
                        </td>
                        <td style={{ padding: "8px 10px", border: "1px solid #e2e8f0", color: "#334155" }}>
                          {analysis.protocolAudit?.spfDetail || "SPF record evaluation"}
                        </td>
                      </tr>
                      <tr>
                        <td style={{ padding: "8px 10px", border: "1px solid #e2e8f0", fontWeight: "700" }}>DKIM Cryptographic Signature</td>
                        <td style={{ padding: "8px 10px", border: "1px solid #e2e8f0", color: analysis.dkim === "Pass" ? "#16a34a" : "#dc2626", fontWeight: "700" }}>
                          {analysis.dkim}
                        </td>
                        <td style={{ padding: "8px 10px", border: "1px solid #e2e8f0", color: "#334155" }}>
                          {analysis.protocolAudit?.dkimDetail || "DKIM public key signature validation"}
                        </td>
                      </tr>
                      <tr>
                        <td style={{ padding: "8px 10px", border: "1px solid #e2e8f0", fontWeight: "700" }}>DMARC Policy Enforcement</td>
                        <td style={{ padding: "8px 10px", border: "1px solid #e2e8f0", color: analysis.dmarc === "Pass" ? "#16a34a" : "#dc2626", fontWeight: "700" }}>
                          {analysis.dmarc}
                        </td>
                        <td style={{ padding: "8px 10px", border: "1px solid #e2e8f0", color: "#334155" }}>
                          {analysis.protocolAudit?.dmarcDetail || "DMARC domain alignment policy"}
                        </td>
                      </tr>
                      <tr>
                        <td style={{ padding: "8px 10px", border: "1px solid #e2e8f0", fontWeight: "700" }}>Reply-To Parity</td>
                        <td style={{ padding: "8px 10px", border: "1px solid #e2e8f0", color: analysis.protocolAudit?.replyToMismatch ? "#dc2626" : "#16a34a", fontWeight: "700" }}>
                          {analysis.protocolAudit?.replyToMismatch ? "MISMATCH" : "ALIGNED"}
                        </td>
                        <td style={{ padding: "8px 10px", border: "1px solid #e2e8f0", color: "#334155" }}>
                          {analysis.protocolAudit?.replyToMismatch
                            ? `Diverts response to external domain: ${analysis.protocolAudit.replyToDomain}`
                            : "Reply-To header matches Sender domain."}
                        </td>
                      </tr>
                      <tr>
                        <td style={{ padding: "8px 10px", border: "1px solid #e2e8f0", fontWeight: "700" }}>Display Name Spoofing</td>
                        <td style={{ padding: "8px 10px", border: "1px solid #e2e8f0", color: analysis.protocolAudit?.displayNameSpoofed ? "#dc2626" : "#16a34a", fontWeight: "700" }}>
                          {analysis.protocolAudit?.displayNameSpoofed ? "DETECTED" : "CLEAR"}
                        </td>
                        <td style={{ padding: "8px 10px", border: "1px solid #e2e8f0", color: "#334155" }}>
                          {analysis.protocolAudit?.displayNameSpoofed
                            ? `Display name claims '${analysis.protocolAudit.spoofedDisplayName}' but sender address originates elsewhere.`
                            : "Display name aligns with sender mailbox identity."}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                {/* SECTION 3: NLP BEHAVIORAL & BEC AUDIT */}
                <div style={{ marginBottom: "24px" }}>
                  <h4
                    style={{
                      fontSize: "13px",
                      fontWeight: "800",
                      textTransform: "uppercase",
                      letterSpacing: "0.06em",
                      color: "#0d2741",
                      borderBottom: "1.5px solid #e2e8f0",
                      paddingBottom: "6px",
                      marginBottom: "12px",
                    }}
                  >
                    3. NLP Behavioral & Social Engineering Analysis
                  </h4>
                  <div style={{ background: "#f8fafc", padding: "14px", borderRadius: "8px", border: "1px solid #e2e8f0", fontSize: "12px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <strong>Urgency & Psychological Coercion Index:</strong>
                      <span style={{ fontWeight: "800", color: (analysis.nlpAudit?.urgencyScore || 0) > 15 ? "#dc2626" : "#16a34a" }}>
                        {analysis.nlpAudit?.urgencyScore || 0} / 40
                      </span>
                    </div>

                    <div style={{ marginBottom: "10px" }}>
                      <span style={{ color: "#64748b", fontWeight: "600" }}>Identified BEC Threat Indicators:</span>
                      {analysis.nlpAudit?.detectedBecPatterns?.length > 0 ? (
                        <ul style={{ margin: "6px 0 0", paddingLeft: "20px", color: "#b91c1c" }}>
                          {analysis.nlpAudit.detectedBecPatterns.map((bec, i) => (
                            <li key={i} style={{ marginBottom: "4px" }}>
                              <strong>{bec.label}:</strong> {bec.rationale} (Keywords: {bec.matchedCues?.join(", ")})
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p style={{ margin: "4px 0 0", color: "#166534" }}>No Business Email Compromise wire fraud patterns detected.</p>
                      )}
                    </div>

                    <div>
                      <span style={{ color: "#64748b", fontWeight: "600" }}>Psychological Urgency Triggers:</span>
                      {analysis.nlpAudit?.detectedTriggers?.length > 0 ? (
                        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginTop: "6px" }}>
                          {analysis.nlpAudit.detectedTriggers.map((t, i) => (
                            <span key={i} style={{ background: "#fee2e2", color: "#991b1b", padding: "2px 8px", borderRadius: "4px", fontSize: "11px", fontWeight: "600" }}>
                              {t.category}: {t.matchedCues?.slice(0, 3).join(", ")}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p style={{ margin: "4px 0 0", color: "#64748b" }}>Normal conversational cadence.</p>
                      )}
                    </div>
                  </div>
                </div>

                {/* SECTION 4: ORIGIN & HOP TELEMETRY */}
                <div style={{ marginBottom: "24px" }}>
                  <h4
                    style={{
                      fontSize: "13px",
                      fontWeight: "800",
                      textTransform: "uppercase",
                      letterSpacing: "0.06em",
                      color: "#0d2741",
                      borderBottom: "1.5px solid #e2e8f0",
                      paddingBottom: "6px",
                      marginBottom: "12px",
                    }}
                  >
                    4. Origin Infrastructure & Mail Hop Telemetry
                  </h4>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "10px", fontSize: "12px", marginBottom: "12px" }}>
                    <div style={{ background: "#f8fafc", padding: "10px", borderRadius: "6px", border: "1px solid #e2e8f0" }}>
                      <span style={{ color: "#64748b", display: "block" }}>Earliest Sending Node IP:</span>
                      <strong style={{ fontFamily: "monospace" }}>
                        {piiRedacted ? maskSensitiveText(analysis.earliestNodeIP || "N/A") : analysis.earliestNodeIP || "Private/Internal"}
                      </strong>
                    </div>
                    <div style={{ background: "#f8fafc", padding: "10px", borderRadius: "6px", border: "1px solid #e2e8f0" }}>
                      <span style={{ color: "#64748b", display: "block" }}>Geographic Origin:</span>
                      <strong>{analysis.originGeo?.city || "Unknown City"}, {analysis.originGeo?.country_name || "Internal"}</strong>
                    </div>
                    <div style={{ background: "#f8fafc", padding: "10px", borderRadius: "6px", border: "1px solid #e2e8f0" }}>
                      <span style={{ color: "#64748b", display: "block" }}>Hosting ISP / ASN:</span>
                      <strong>{analysis.originGeo?.isp || "Local Network"} ({analysis.originGeo?.asn || "N/A"})</strong>
                    </div>
                    <div style={{ background: "#f8fafc", padding: "10px", borderRadius: "6px", border: "1px solid #e2e8f0" }}>
                      <span style={{ color: "#64748b", display: "block" }}>MTA Hop Route Count:</span>
                      <strong>{analysis.hopTrace?.totalHops || 0} Sequential Relays</strong>
                    </div>
                  </div>

                  {analysis.hopTrace?.relayAnomalies?.length > 0 && (
                    <div style={{ background: "#fef2f2", border: "1px solid #fecaca", borderRadius: "6px", padding: "10px 14px", fontSize: "12px", color: "#991b1b" }}>
                      <strong>Routing Anomalies Detected:</strong>
                      <ul style={{ margin: "4px 0 0", paddingLeft: "18px" }}>
                        {analysis.hopTrace.relayAnomalies.map((anom, i) => (
                          <li key={i}>{anom}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* SECTION 5: CONTAINMENT & REMEDIATION */}
                <div style={{ marginBottom: "28px" }}>
                  <h4
                    style={{
                      fontSize: "13px",
                      fontWeight: "800",
                      textTransform: "uppercase",
                      letterSpacing: "0.06em",
                      color: "#0d2741",
                      borderBottom: "1.5px solid #e2e8f0",
                      paddingBottom: "6px",
                      marginBottom: "12px",
                    }}
                  >
                    5. Incident Containment & Corrective Protocol
                  </h4>
                  <div style={{ background: "#f1f5f9", padding: "14px 18px", borderRadius: "8px", border: "1px solid #cbd5e1" }}>
                    <ol style={{ margin: 0, paddingLeft: "20px", fontSize: "12px", color: "#1e293b", lineHeight: "1.7" }}>
                      {analysis.containmentActions?.map((act, i) => (
                        <li key={i} style={{ marginBottom: "4px" }}>
                          <strong>{act}</strong>
                        </li>
                      )) || <li>Standard mail delivery permitted without restriction.</li>}
                    </ol>
                  </div>
                </div>

                {/* SIGNATURE & EVIDENCE SEAL */}
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-end",
                    borderTop: "1.5px solid #0d2741",
                    paddingTop: "20px",
                    marginTop: "30px",
                  }}
                >
                  <div style={{ textAlign: "center", width: "220px" }}>
                    <div style={{ borderBottom: "1px solid #334155", height: "40px", marginBottom: "6px" }} />
                    <span style={{ fontSize: "11px", fontWeight: "700", textTransform: "uppercase", color: "#475569" }}>
                      Lead Forensic Examiner
                    </span>
                  </div>

                  <div
                    style={{
                      width: "96px",
                      height: "96px",
                      borderRadius: "50%",
                      border: "2px dashed #0d2741",
                      display: "grid",
                      placeItems: "center",
                      textAlign: "center",
                      fontSize: "9px",
                      fontWeight: "800",
                      color: "#0d2741",
                      padding: "8px",
                      textTransform: "uppercase",
                    }}
                  >
                    DIGITAL FORENSICS<br />EVIDENCE SEAL<br />ISO 27037
                  </div>

                  <div style={{ textAlign: "center", width: "220px" }}>
                    <div style={{ borderBottom: "1px solid #334155", height: "40px", marginBottom: "6px" }} />
                    <span style={{ fontSize: "11px", fontWeight: "700", textTransform: "uppercase", color: "#475569" }}>
                      Incident Commander / Legal
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: NLP & BEC SOCIAL ENGINEERING */}
          {activeTab === "nlp" && (
            <div>
              <div style={{ marginBottom: "16px" }}>
                <h3 style={{ margin: "0 0 4px", fontSize: "16px" }}>NLP Linguistic & Psychological Urgency Cues</h3>
                <p style={{ fontSize: "13px", color: "#64748b" }}>
                  Analyzes urgency constraints, executive coercion, and Business Email Compromise (BEC) deception patterns.
                </p>
              </div>

              {/* BEC PATTERNS DETECTED */}
              <div style={{ marginBottom: "20px" }}>
                <span style={{ fontSize: "12px", fontWeight: "700", color: "#475569", textTransform: "uppercase" }}>
                  BEC (Business Email Compromise) Indicators:
                </span>

                {analysis.nlpAudit?.detectedBecPatterns?.length === 0 ? (
                  <div style={{ padding: "12px", background: "#f0fdf4", borderRadius: "8px", marginTop: "8px", color: "#166534", fontSize: "13px" }}>
                    ✓ No Business Email Compromise (BEC) wire transfer or fake billing patterns detected.
                  </div>
                ) : (
                  <div style={{ display: "grid", gap: "10px", marginTop: "8px" }}>
                    {analysis.nlpAudit?.detectedBecPatterns?.map((bec, i) => (
                      <div
                        key={i}
                        style={{
                          background: "#fff1f2",
                          border: "1px solid #fecaca",
                          borderRadius: "8px",
                          padding: "14px",
                        }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <strong style={{ color: "#991b1b", fontSize: "14px" }}>{bec.label}</strong>
                          <span style={{ fontSize: "11px", fontWeight: "700", padding: "2px 8px", borderRadius: "4px", background: "#dc2626", color: "#fff" }}>
                            {bec.severity}
                          </span>
                        </div>
                        <p style={{ margin: "4px 0 8px", fontSize: "12px", color: "#7f1d1d" }}>
                          {bec.description}
                        </p>
                        <div style={{ fontSize: "12px", color: "#b91c1c" }}>
                          <strong>Matched Phrases:</strong> {bec.matchedCues.join(", ")}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* SOCIAL ENGINEERING TRIGGERS */}
              <div>
                <span style={{ fontSize: "12px", fontWeight: "700", color: "#475569", textTransform: "uppercase" }}>
                  Psychological & Manipulation Triggers:
                </span>

                {analysis.nlpAudit?.detectedTriggers?.length === 0 ? (
                  <div style={{ padding: "12px", background: "#f8fafc", borderRadius: "8px", marginTop: "8px", color: "#64748b", fontSize: "13px" }}>
                    No coercive or artificial urgency triggers found in text.
                  </div>
                ) : (
                  <div style={{ display: "grid", gap: "10px", marginTop: "8px" }}>
                    {analysis.nlpAudit?.detectedTriggers?.map((trig, i) => (
                      <div
                        key={i}
                        style={{
                          background: "#fffbeb",
                          border: "1px solid #fde68a",
                          borderRadius: "8px",
                          padding: "12px 14px",
                        }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between" }}>
                          <strong style={{ color: "#92400e", fontSize: "13px" }}>{trig.category}</strong>
                          <span style={{ fontSize: "12px", fontWeight: "600", color: "#b45309" }}>
                            Weight: +{trig.weight} pts
                          </span>
                        </div>
                        <p style={{ margin: "2px 0 6px", fontSize: "12px", color: "#78350f" }}>{trig.description}</p>
                        <div style={{ fontSize: "12px", color: "#92400e" }}>
                          <strong>Detected Cues:</strong> {trig.matchedCues.join(", ")}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: PROTOCOL & AUTHENTICATION AUDIT */}
          {activeTab === "auth" && (
            <div>
              <div style={{ marginBottom: "16px" }}>
                <h3 style={{ margin: "0 0 4px", fontSize: "16px" }}>Email Header & Protocol Verification</h3>
                <p style={{ fontSize: "13px", color: "#64748b" }}>
                  Deep cryptographic validation of SPF records, DKIM digital signatures, DMARC policies, and address alignment.
                </p>
              </div>

              {/* PROTOCOL ANOMALIES TABLE */}
              <div style={{ display: "grid", gap: "12px", marginBottom: "20px" }}>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "12px 16px",
                    borderRadius: "8px",
                    background: analysis.protocolAudit?.replyToMismatch ? "#fff1f2" : "#f0fdf4",
                    border: analysis.protocolAudit?.replyToMismatch ? "1px solid #fca5a5" : "1px solid #bbf7d0",
                  }}
                >
                  <div>
                    <strong style={{ fontSize: "13px", color: analysis.protocolAudit?.replyToMismatch ? "#991b1b" : "#166534" }}>
                      Reply-To Address Redirection Audit
                    </strong>
                    <p style={{ margin: "2px 0 0", fontSize: "12px", color: "#475569" }}>
                      {analysis.protocolAudit?.replyToMismatch
                        ? `MISMATCH: Header From '${analysis.protocolAudit.fromDomain}' routes replies to '${analysis.protocolAudit.replyToDomain}'.`
                        : "Header From matches Reply-To routing destination."}
                    </p>
                  </div>
                  <span style={{ fontSize: "12px", fontWeight: "700", color: analysis.protocolAudit?.replyToMismatch ? "#dc2626" : "#16a34a" }}>
                    {analysis.protocolAudit?.replyToMismatch ? "FAILED" : "ALIGNED"}
                  </span>
                </div>

                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "12px 16px",
                    borderRadius: "8px",
                    background: analysis.protocolAudit?.displayNameSpoofing ? "#fff1f2" : "#f0fdf4",
                    border: analysis.protocolAudit?.displayNameSpoofing ? "1px solid #fca5a5" : "1px solid #bbf7d0",
                  }}
                >
                  <div>
                    <strong style={{ fontSize: "13px", color: analysis.protocolAudit?.displayNameSpoofing ? "#991b1b" : "#166534" }}>
                      Display Name Spoofing Check
                    </strong>
                    <p style={{ margin: "2px 0 0", fontSize: "12px", color: "#475569" }}>
                      {analysis.protocolAudit?.displayNameSpoofing
                        ? `SUSPICIOUS: Display name '${analysis.protocolAudit.fromName}' attempts to spoof legitimate brand on untrusted domain.`
                        : "Display name aligns with sender origin."}
                    </p>
                  </div>
                  <span style={{ fontSize: "12px", fontWeight: "700", color: analysis.protocolAudit?.displayNameSpoofing ? "#dc2626" : "#16a34a" }}>
                    {analysis.protocolAudit?.displayNameSpoofing ? "SPOOF DETECTED" : "PASSED"}
                  </span>
                </div>

                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "12px 16px",
                    borderRadius: "8px",
                    background: analysis.spf === "Pass" ? "#f0fdf4" : "#fff1f2",
                    border: analysis.spf === "Pass" ? "1px solid #bbf7d0" : "1px solid #fca5a5",
                  }}
                >
                  <div>
                    <strong style={{ fontSize: "13px", color: analysis.spf === "Pass" ? "#166534" : "#991b1b" }}>
                      SPF (Sender Policy Framework) Alignment
                    </strong>
                    <p style={{ margin: "2px 0 0", fontSize: "12px", color: "#475569" }}>
                      Validates sending IP authorization against sender domain TXT records.
                    </p>
                  </div>
                  <span style={{ fontSize: "12px", fontWeight: "700", color: analysis.spf === "Pass" ? "#16a34a" : "#dc2626" }}>
                    {analysis.spf}
                  </span>
                </div>

                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "12px 16px",
                    borderRadius: "8px",
                    background: analysis.dkim === "Pass" ? "#f0fdf4" : "#fff1f2",
                    border: analysis.dkim === "Pass" ? "1px solid #bbf7d0" : "1px solid #fca5a5",
                  }}
                >
                  <div>
                    <strong style={{ fontSize: "13px", color: analysis.dkim === "Pass" ? "#166534" : "#991b1b" }}>
                      DKIM (DomainKeys Identified Mail) Cryptographic Signature
                    </strong>
                    <p style={{ margin: "2px 0 0", fontSize: "12px", color: "#475569" }}>
                      Selector: {analysis.protocolAudit?.dkimSelector || "Not Specified"} · Cryptographic tamper-proofing.
                    </p>
                  </div>
                  <span style={{ fontSize: "12px", fontWeight: "700", color: analysis.dkim === "Pass" ? "#16a34a" : "#dc2626" }}>
                    {analysis.dkim}
                  </span>
                </div>
              </div>

              {/* RAW AUTHENTICATION HEADER STRING */}
              <div style={{ background: "#f8fafc", padding: "14px", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
                <span style={{ fontSize: "11px", fontWeight: "700", color: "#64748b", textTransform: "uppercase" }}>
                  Authentication-Results Header Payload:
                </span>
                <pre style={{ margin: "6px 0 0", fontSize: "12px", fontFamily: "monospace", whiteSpace: "pre-wrap", color: "#1e293b" }}>
                  {analysis.authenticationResults}
                </pre>
              </div>
            </div>
          )}

          {/* TAB 4: VISUAL MAIL HOP ROUTE TRACER */}
          {activeTab === "route" && (
            <div>
              <div style={{ marginBottom: "16px" }}>
                <h3 style={{ margin: "0 0 4px", fontSize: "16px" }}>Mail Relay Hop Route & Trace Path</h3>
                <p style={{ fontSize: "13px", color: "#64748b" }}>
                  Chronological trace of intermediate Mail Transfer Agents (MTAs) from earliest origin node to destination gateway.
                </p>
              </div>

              {analysis.hopTrace?.hops?.length === 0 ? (
                <p style={{ color: "#64748b" }}>No Received hops found in email headers.</p>
              ) : (
                <div style={{ display: "grid", gap: "12px" }}>
                  {analysis.hopTrace.hops.map((hop) => {
                    const isOrigin = hop.primaryIP === analysis.earliestNodeIP;

                    return (
                      <div
                        key={hop.hopNumber}
                        style={{
                          display: "flex",
                          gap: "16px",
                          background: isOrigin ? "#eff6ff" : "#fff",
                          border: isOrigin ? "2px solid #3b82f6" : "1px solid #e2e8f0",
                          borderRadius: "10px",
                          padding: "14px 18px",
                          position: "relative",
                        }}
                      >
                        {/* HOP NUMBER BADGE */}
                        <div
                          style={{
                            width: "36px",
                            height: "36px",
                            borderRadius: "50%",
                            background: isOrigin ? "#2563eb" : "#0f172a",
                            color: "#fff",
                            display: "grid",
                            placeItems: "center",
                            fontSize: "14px",
                            fontWeight: "800",
                            flexShrink: 0,
                          }}
                        >
                          #{hop.hopNumber}
                        </div>

                        <div style={{ flex: 1 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "8px" }}>
                            <div>
                              <strong style={{ fontSize: "14px", color: "#0f172a" }}>
                                From: {hop.fromHost}
                              </strong>
                              {isOrigin && (
                                <span
                                  style={{
                                    marginLeft: "8px",
                                    padding: "2px 8px",
                                    borderRadius: "4px",
                                    background: "#2563eb",
                                    color: "#fff",
                                    fontSize: "11px",
                                    fontWeight: "700",
                                  }}
                                >
                                  EARLIEST SENDING NODE
                                </span>
                              )}
                            </div>

                            <span style={{ fontSize: "12px", color: "#64748b", display: "flex", alignItems: "center", gap: "4px" }}>
                              <Clock size={12} /> {hop.timestamp}
                            </span>
                          </div>

                          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "8px", marginTop: "8px", fontSize: "12px", color: "#475569" }}>
                            <div>
                              <strong>Received By:</strong> {hop.byHost}
                            </div>
                            <div>
                              <strong>Protocol:</strong>{" "}
                              <span style={{ padding: "1px 6px", borderRadius: "4px", background: hop.isEncrypted ? "#dcfce7" : "#f1f5f9", color: hop.isEncrypted ? "#15803d" : "#475569", fontWeight: "600" }}>
                                {hop.protocol} {hop.isEncrypted ? "(TLS Encrypted)" : "(Unencrypted)"}
                              </span>
                            </div>
                            <div>
                              <strong>IP Address:</strong>{" "}
                              <span style={{ fontFamily: "monospace" }}>
                                {piiRedacted ? maskSensitiveText(hop.primaryIP || "None") : hop.primaryIP || "None"}
                              </span>
                            </div>
                            <div>
                              <strong>Transit Delay:</strong> {hop.delaySeconds >= 0 ? `+${hop.delaySeconds}s` : `${hop.delaySeconds}s`}
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* TAB 5: ORIGIN RADAR & HIGH-ACCURACY GEOIP TELEMETRY */}
          {activeTab === "origin" && (() => {
            const currentIp = selectedIpNode || analysis.earliestNodeIP || "N/A";
            const currentGeo = activeGeoData || analysis.originGeo;
            const hasCoords = currentGeo && !currentGeo.isPrivate && currentGeo.latitude && currentGeo.longitude && currentGeo.latitude !== 0;
            const maps = hasCoords ? buildMapLinks(currentGeo.latitude, currentGeo.longitude) : null;

            return (
              <div>
                <div style={{ marginBottom: "16px", display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "10px" }}>
                  <div>
                    <h3 style={{ margin: "0 0 4px", fontSize: "16px" }}>High-Accuracy Origin Radar & Geolocation</h3>
                    <p style={{ fontSize: "13px", color: "#64748b" }}>
                      Multi-tier geospatial triangulation, interactive OpenStreetMap, ASN routing, and domain infrastructure audit.
                    </p>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span
                      style={{
                        fontSize: "11px",
                        fontWeight: "700",
                        padding: "4px 10px",
                        borderRadius: "20px",
                        background: currentGeo?.isPrivate ? "#fef3c7" : "#dcfce7",
                        color: currentGeo?.isPrivate ? "#92400e" : "#166534",
                        border: currentGeo?.isPrivate ? "1px solid #fde68a" : "1px solid #bbf7d0",
                      }}
                    >
                      {currentGeo?.accuracyStatus || (currentGeo?.isPrivate ? "RFC 1918 Private Subnet" : "Verified High-Precision GPS")}
                    </span>
                  </div>
                </div>

                {/* EMAIL DISCOVERED NODES & IP SELECTOR */}
                {analysis.allDiscoveredIPs?.length > 0 && (
                  <div
                    style={{
                      background: "#f1f5f9",
                      padding: "12px 16px",
                      borderRadius: "10px",
                      marginBottom: "16px",
                      border: "1px solid #cbd5e1",
                    }}
                  >
                    <span style={{ fontSize: "11px", fontWeight: "700", color: "#475569", textTransform: "uppercase", letterSpacing: "0.05em", display: "block", marginBottom: "8px" }}>
                      Forensic Nodes Discovered in Message ({analysis.allDiscoveredIPs.length} Total Nodes):
                    </span>

                    <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                      {analysis.allDiscoveredIPs.map((node, i) => {
                        const isSelected = (selectedIpNode === node.ip) || (!selectedIpNode && node.ip === analysis.earliestNodeIP);
                        return (
                          <button
                            key={i}
                            type="button"
                            onClick={() => handleSelectIP(node.ip)}
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "6px",
                              padding: "6px 12px",
                              borderRadius: "6px",
                              fontSize: "12px",
                              fontWeight: isSelected ? "700" : "500",
                              background: isSelected ? "#0d2741" : "#fff",
                              color: isSelected ? "#fff" : "#1e293b",
                              border: isSelected ? "1px solid #0d2741" : "1px solid #cbd5e1",
                              cursor: "pointer",
                              boxShadow: isSelected ? "0 2px 6px rgba(13,39,65,0.3)" : "none",
                              transition: "all 0.15s ease",
                            }}
                          >
                            <MapPin size={12} style={{ color: isSelected ? "#38bdf8" : "#64748b" }} />
                            <span style={{ fontFamily: "monospace" }}>{node.ip}</span>
                            <span style={{ fontSize: "10px", opacity: 0.8, background: isSelected ? "rgba(255,255,255,0.2)" : "#f1f5f9", padding: "1px 5px", borderRadius: "3px" }}>
                              {node.role.split("(")[0]}
                            </span>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* MANUAL IP GEOLOCATION SEARCH BAR */}
                <form
                  onSubmit={handleManualSearch}
                  style={{
                    display: "flex",
                    gap: "10px",
                    marginBottom: "20px",
                    background: "#fff",
                    padding: "10px 14px",
                    borderRadius: "10px",
                    border: "1px solid #cbd5e1",
                    boxShadow: "0 2px 8px rgba(0,0,0,0.03)",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", flex: 1 }}>
                    <Search size={16} style={{ color: "#64748b" }} />
                    <input
                      type="text"
                      placeholder="Deep-dive any IP address (e.g. 185.220.101.45, 122.161.45.10, 8.8.8.8)..."
                      value={manualIpSearch}
                      onChange={(e) => setManualIpSearch(e.target.value)}
                      style={{
                        flex: 1,
                        border: 0,
                        outline: "none",
                        fontSize: "13px",
                        color: "#0f172a",
                        background: "transparent",
                      }}
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={manualIpLoading || !manualIpSearch.trim()}
                    className="primary-button"
                    style={{
                      fontSize: "12px",
                      padding: "6px 14px",
                      background: "#0d2741",
                      borderRadius: "6px",
                      cursor: "pointer",
                      border: 0,
                      color: "#fff",
                      fontWeight: "700",
                    }}
                  >
                    {manualIpLoading ? "Geolocating..." : "Lookup IP"}
                  </button>
                </form>

                {/* INTERACTIVE OPENSTREETMAP DISPLAY */}
                <div style={{ marginBottom: "24px" }}>
                  {hasCoords ? (
                    <div
                      style={{
                        background: "#fff",
                        border: "1px solid #cbd5e1",
                        borderRadius: "12px",
                        overflow: "hidden",
                        boxShadow: "0 4px 14px rgba(0,0,0,0.05)",
                      }}
                    >
                      <div
                        style={{
                          padding: "12px 18px",
                          background: "#0d2741",
                          color: "#fff",
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          flexWrap: "wrap",
                          gap: "10px",
                        }}
                      >
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <span style={{ fontSize: "16px" }}>{currentGeo.country_flag || "📍"}</span>
                          <strong style={{ fontSize: "14px" }}>
                            {currentGeo.city}, {currentGeo.region ? `${currentGeo.region}, ` : ""}{currentGeo.country_name}
                          </strong>
                          <span style={{ fontSize: "12px", color: "#94a3b8", fontFamily: "monospace" }}>
                            [{Number(currentGeo.latitude).toFixed(5)}, {Number(currentGeo.longitude).toFixed(5)}]
                          </span>
                        </div>

                        <div style={{ display: "flex", gap: "8px" }}>
                          <a
                            href={maps?.googleMapsUrl || `https://www.google.com/maps?q=${currentGeo.latitude},${currentGeo.longitude}`}
                            target="_blank"
                            rel="noreferrer"
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "4px",
                              fontSize: "11px",
                              fontWeight: "600",
                              background: "rgba(255,255,255,0.15)",
                              color: "#fff",
                              padding: "4px 10px",
                              borderRadius: "4px",
                              textDecoration: "none",
                            }}
                          >
                            <ExternalLink size={12} /> Google Maps
                          </a>

                          <a
                            href={maps?.openStreetMapUrl || `https://www.openstreetmap.org/?mlat=${currentGeo.latitude}&mlon=${currentGeo.longitude}`}
                            target="_blank"
                            rel="noreferrer"
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "4px",
                              fontSize: "11px",
                              fontWeight: "600",
                              background: "rgba(255,255,255,0.15)",
                              color: "#fff",
                              padding: "4px 10px",
                              borderRadius: "4px",
                              textDecoration: "none",
                            }}
                          >
                            <ExternalLink size={12} /> OpenStreetMap
                          </a>
                        </div>
                      </div>

                      {/* LIVE MAP IFRAME */}
                      <div style={{ position: "relative", width: "100%", height: "360px", background: "#e2e8f0" }}>
                        <iframe
                          title="Interactive Origin Geolocation Map"
                          width="100%"
                          height="100%"
                          style={{ border: 0 }}
                          loading="lazy"
                          src={currentGeo.mapEmbedUrl || maps?.mapEmbedUrl}
                        />
                      </div>
                    </div>
                  ) : currentGeo?.isPrivate ? (
                    <div
                      style={{
                        background: "#fffbeb",
                        border: "1px solid #fde68a",
                        borderRadius: "10px",
                        padding: "18px 22px",
                        color: "#92400e",
                        display: "flex",
                        alignItems: "flex-start",
                        gap: "12px",
                      }}
                    >
                      <ShieldAlert size={24} style={{ color: "#d97706", flexShrink: 0, marginTop: "2px" }} />
                      <div>
                        <strong style={{ fontSize: "14px", display: "block", marginBottom: "4px" }}>
                          Internal Network Node ({currentIp})
                        </strong>
                        <p style={{ margin: 0, fontSize: "13px", lineHeight: "1.5" }}>
                          This node resides in a private, non-routable local network space (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16).
                          Internal IP packets originate behind a NAT boundary and do not have geographic GPS coordinates on the global internet.
                          Select an external MTA relay node from the list above to view the public routing entry point.
                        </p>
                      </div>
                    </div>
                  ) : (
                    <div
                      style={{
                        background: "#f8fafc",
                        border: "1px solid #e2e8f0",
                        borderRadius: "10px",
                        padding: "24px",
                        textAlign: "center",
                        color: "#64748b",
                      }}
                    >
                      <Globe2 size={32} style={{ color: "#94a3b8", margin: "0 auto 8px" }} />
                      <strong style={{ display: "block", color: "#1e293b", fontSize: "14px" }}>
                        Location Telemetry Pending
                      </strong>
                      <p style={{ margin: "4px 0 0", fontSize: "12px" }}>
                        Resolving geographic coordinates for node {currentIp}...
                      </p>
                    </div>
                  )}
                </div>

                {/* 3-CARD FORENSIC TELEMETRY GRID */}
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: "16px" }}>
                  {/* CARD 1: GEOGRAPHIC PINPOINT */}
                  <div style={{ background: "#f8fafc", padding: "18px", borderRadius: "10px", border: "1px solid #e2e8f0" }}>
                    <h4 style={{ margin: "0 0 14px", fontSize: "14px", display: "flex", alignItems: "center", gap: "8px", color: "#0d2741" }}>
                      <Globe2 size={16} style={{ color: "#2563eb" }} /> Geographic Pinpoint
                    </h4>

                    <div style={{ display: "grid", gap: "10px", fontSize: "13px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>Target IP Address:</span>
                        <strong style={{ fontFamily: "monospace", color: "#0f172a" }}>
                          {piiRedacted ? maskSensitiveText(currentIp) : currentIp}
                        </strong>
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>Country:</span>
                        <strong>
                          {currentGeo?.country_flag ? `${currentGeo.country_flag} ` : ""}
                          {currentGeo?.country_name || "Unknown"} ({currentGeo?.country_code || "UN"})
                        </strong>
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>City & Region:</span>
                        <strong>
                          {currentGeo?.city || "Unknown City"}{currentGeo?.region ? `, ${currentGeo.region}` : ""}
                        </strong>
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>Postal / ZIP Code:</span>
                        <strong style={{ fontFamily: "monospace" }}>{currentGeo?.postal || "N/A"}</strong>
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>GPS Coordinates:</span>
                        <strong style={{ fontFamily: "monospace", color: "#1e40af" }}>
                          {currentGeo?.latitude ? Number(currentGeo.latitude).toFixed(6) : "0.000000"}°,{" "}
                          {currentGeo?.longitude ? Number(currentGeo.longitude).toFixed(6) : "0.000000"}°
                        </strong>
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>Timezone:</span>
                        <strong>{currentGeo?.timezone || "UTC"}</strong>
                      </div>
                    </div>
                  </div>

                  {/* CARD 2: NETWORK INFRASTRUCTURE & ASN */}
                  <div style={{ background: "#f8fafc", padding: "18px", borderRadius: "10px", border: "1px solid #e2e8f0" }}>
                    <h4 style={{ margin: "0 0 14px", fontSize: "14px", display: "flex", alignItems: "center", gap: "8px", color: "#0d2741" }}>
                      <Network size={16} style={{ color: "#0891b2" }} /> Autonomous System & Routing
                    </h4>

                    <div style={{ display: "grid", gap: "10px", fontSize: "13px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>ISP / Carrier:</span>
                        <strong style={{ color: "#0f172a", textAlign: "right" }}>{currentGeo?.isp || "Local Network"}</strong>
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>Organization / Host:</span>
                        <strong style={{ color: "#0f172a", textAlign: "right" }}>{currentGeo?.org || "Network Node"}</strong>
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>Autonomous System:</span>
                        <strong style={{ fontFamily: "monospace", color: "#0369a1" }}>{currentGeo?.asn || "N/A"}</strong>
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>Routing Classification:</span>
                        <strong style={{ color: currentGeo?.isPrivate ? "#b45309" : "#15803d" }}>
                          {currentGeo?.isPrivate ? "RFC 1918 (Private Subnet)" : "Public Routable (Global Internet)"}
                        </strong>
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>Telemetry Engine:</span>
                        <strong style={{ color: "#0d2741" }}>{currentGeo?.sourceProvider || "ipwho.is High-Precision"}</strong>
                      </div>
                    </div>
                  </div>

                  {/* CARD 3: DOMAIN & WHOIS INTELLIGENCE */}
                  <div style={{ background: "#f8fafc", padding: "18px", borderRadius: "10px", border: "1px solid #e2e8f0" }}>
                    <h4 style={{ margin: "0 0 14px", fontSize: "14px", display: "flex", alignItems: "center", gap: "8px", color: "#0d2741" }}>
                      <Server size={16} style={{ color: "#8b5cf6" }} /> Domain & WHOIS Intelligence
                    </h4>

                    <div style={{ display: "grid", gap: "10px", fontSize: "13px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>Sender Domain:</span>
                        <strong>{analysis.senderDomain || "None"}</strong>
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>Hosting Provider:</span>
                        <strong>{analysis.domainIntel?.hostingProvider || "Independent Registrar"}</strong>
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>Typosquatting Risk:</span>
                        <strong style={{ color: analysis.domainIntel?.typosquattingDetected ? "#dc2626" : "#16a34a" }}>
                          {analysis.domainIntel?.typosquattingDetected
                            ? `Flagged (${analysis.domainIntel.typosquattingTarget})`
                            : "Clean Domain"}
                        </strong>
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>Mail Exchanger (MX):</span>
                        <strong>
                          {analysis.domainIntel?.mxRecords?.length > 0
                            ? `${analysis.domainIntel.mxRecords.length} MX Record(s)`
                            : "No MX Records"}
                        </strong>
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <span style={{ color: "#64748b" }}>Domain Reputation:</span>
                        <strong style={{ color: analysis.domainIntel?.reputationScore > 70 ? "#16a34a" : "#dc2626" }}>
                          {analysis.domainIntel?.reputationScore || 50} / 100
                        </strong>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            );
          })()}

          {/* TAB 6: ATTRIBUTION & RELATIONSHIP GRAPH */}
          {activeTab === "attribution" && (
            <div>
              <div style={{ marginBottom: "16px" }}>
                <h3 style={{ margin: "0 0 4px", fontSize: "16px" }}>Identity Attribution & Relationship Topology</h3>
                <p style={{ fontSize: "13px", color: "#64748b" }}>
                  Correlated relationship graph between sender alias, envelope domain, origin node IP, and threat payloads.
                </p>
              </div>

              {/* ATTRIBUTION BOX */}
              <div
                style={{
                  background: "#f0fdf4",
                  border: "1px solid #bbf7d0",
                  borderRadius: "8px",
                  padding: "16px",
                  marginBottom: "20px",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <strong style={{ color: "#166534", fontSize: "15px" }}>
                    Source Infrastructure: {analysis.attribution?.infrastructureType}
                  </strong>
                  <span style={{ background: "#16a34a", color: "#fff", padding: "3px 10px", borderRadius: "12px", fontSize: "12px", fontWeight: "700" }}>
                    {analysis.attribution?.attributionConfidence}% Confidence
                  </span>
                </div>
                <p style={{ margin: "6px 0 0", color: "#14532d", fontSize: "13px" }}>
                  {analysis.attribution?.attributionSummary}
                </p>
              </div>

              {/* VISUAL TOPOLOGY GRAPH (INTERACTIVE SVG CANVAS) */}
              <div
                style={{
                  background: "#0d2741",
                  borderRadius: "12px",
                  padding: "24px",
                  color: "#fff",
                  minHeight: "360px",
                  position: "relative",
                  overflow: "hidden",
                }}
              >
                <div style={{ position: "absolute", top: "14px", left: "18px", fontSize: "12px", color: "#94a3b8" }}>
                  <Share2 size={14} style={{ display: "inline", marginRight: "4px" }} />
                  Threat Relationship Topology Graph
                </div>

                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-around",
                    alignItems: "center",
                    flexWrap: "wrap",
                    gap: "24px",
                    marginTop: "30px",
                  }}
                >
                  {analysis.correlationGraph?.nodes?.map((node) => (
                    <div
                      key={node.id}
                      style={{
                        background: "rgba(255, 255, 255, 0.08)",
                        border: `2px solid ${node.color}`,
                        borderRadius: "10px",
                        padding: "14px 18px",
                        textAlign: "center",
                        minWidth: "150px",
                        boxShadow: `0 4px 16px ${node.color}33`,
                        backdropFilter: "blur(6px)",
                      }}
                    >
                      <div
                        style={{
                          width: "36px",
                          height: "36px",
                          borderRadius: "50%",
                          background: node.color,
                          color: "#fff",
                          display: "grid",
                          placeItems: "center",
                          margin: "0 auto 8px",
                        }}
                      >
                        <Network size={18} />
                      </div>
                      <span style={{ fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.08em", color: "#94a3b8" }}>
                        {node.type}
                      </span>
                      <strong style={{ display: "block", fontSize: "12px", color: "#fff", marginTop: "2px", wordBreak: "break-all" }}>
                        {piiRedacted ? maskSensitiveText(node.label) : node.label}
                      </strong>
                    </div>
                  ))}
                </div>

                {/* GRAPH EDGES SUMMARY */}
                <div style={{ marginTop: "32px", borderTop: "1px solid rgba(255,255,255,0.1)", paddingTop: "14px" }}>
                  <span style={{ fontSize: "11px", color: "#94a3b8", textTransform: "uppercase" }}>Linked IOC Associations:</span>
                  <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginTop: "8px" }}>
                    {analysis.correlationGraph?.edges?.map((edge, i) => (
                      <span
                        key={i}
                        style={{
                          background: "rgba(255,255,255,0.06)",
                          padding: "4px 10px",
                          borderRadius: "20px",
                          fontSize: "11px",
                          color: "#cbd5e1",
                        }}
                      >
                        {edge.from} ➔ {edge.to} ({edge.label})
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: IOCS, LINKS & ATTACHMENTS */}
          {activeTab === "links" && (
            <div>
              <div style={{ marginBottom: "16px" }}>
                <h3 style={{ margin: "0 0 4px", fontSize: "16px" }}>Extracted Indicators of Compromise (IoC) & Payloads</h3>
                <p style={{ fontSize: "13px", color: "#64748b" }}>
                  Deceptive hyperlinks, obfuscated redirect URLs, and quarantined file attachments.
                </p>
              </div>

              {/* ATTACHMENTS AUDIT */}
              {analysis.attachmentCount > 0 && (
                <div style={{ marginBottom: "24px" }}>
                  <span style={{ fontSize: "12px", fontWeight: "700", color: "#475569", textTransform: "uppercase" }}>
                    Attached Payload Files ({analysis.attachmentCount}):
                  </span>

                  <div style={{ display: "grid", gap: "10px", marginTop: "8px" }}>
                    {analysis.attachments?.map((att, i) => (
                      <div
                        key={i}
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          padding: "12px 16px",
                          borderRadius: "8px",
                          background: att.isExecutable ? "#fff1f2" : "#f8fafc",
                          border: att.isExecutable ? "1px solid #fca5a5" : "1px solid #e2e8f0",
                        }}
                      >
                        <div>
                          <strong style={{ fontSize: "13px", color: att.isExecutable ? "#dc2626" : "#0f172a" }}>
                            {att.filename}
                          </strong>
                          <span style={{ display: "block", fontSize: "11px", color: "#64748b", marginTop: "2px" }}>
                            {(att.size / 1024).toFixed(1)} KB · MIME: {att.mimeType}
                          </span>
                        </div>

                        <span
                          style={{
                            fontSize: "11px",
                            fontWeight: "700",
                            padding: "3px 8px",
                            borderRadius: "4px",
                            background: att.isExecutable ? "#dc2626" : "#e2e8f0",
                            color: att.isExecutable ? "#fff" : "#475569",
                          }}
                        >
                          {att.isExecutable ? "DANGEROUS PAYLOAD" : "Standard File"}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* URLS TABLE */}
              <div>
                <span style={{ fontSize: "12px", fontWeight: "700", color: "#475569", textTransform: "uppercase" }}>
                  Hyperlinks Found ({analysis.totalLinks}):
                </span>

                {analysis.allUrls?.length === 0 ? (
                  <p style={{ fontSize: "13px", color: "#64748b", marginTop: "8px" }}>No URLs extracted from email body.</p>
                ) : (
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px", marginTop: "8px" }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid #e2e8f0", textAlign: "left" }}>
                        <th style={{ padding: "8px 6px" }}>Extracted URL</th>
                        <th style={{ padding: "8px 6px", width: "140px" }}>Verdict</th>
                      </tr>
                    </thead>
                    <tbody>
                      {analysis.allUrls?.map((url, idx) => {
                        const isSuspicious = analysis.suspiciousLinksList?.includes(url);
                        return (
                          <tr key={idx} style={{ borderBottom: "1px solid #f1f5f9" }}>
                            <td style={{ padding: "10px 6px", fontFamily: "monospace", fontSize: "12px", wordBreak: "break-all" }}>
                              {piiRedacted ? maskSensitiveText(url) : url}
                            </td>
                            <td style={{ padding: "10px 6px" }}>
                              <span
                                style={{
                                  padding: "3px 8px",
                                  borderRadius: "4px",
                                  fontSize: "11px",
                                  fontWeight: "700",
                                  background: isSuspicious ? "#fee2e2" : "#dcfce7",
                                  color: isSuspicious ? "#b91c1c" : "#15803d",
                                }}
                              >
                                {isSuspicious ? "SUSPICIOUS / PHISH" : "Clean"}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          )}

          {/* TAB 8: RAW HEADERS & BODY */}
          {activeTab === "headers" && (
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", flexWrap: "wrap", gap: "10px" }}>
                <div>
                  <h3 style={{ margin: "0 0 2px", fontSize: "16px" }}>MIME RFC 822 Raw Headers & Decoded Body</h3>
                  <span style={{ fontSize: "12px", color: "#64748b" }}>
                    {analysis.headers?.length} headers parsed from email envelope
                  </span>
                </div>

                <input
                  type="text"
                  placeholder="Filter headers by key or value..."
                  value={headerSearch}
                  onChange={(e) => setHeaderSearch(e.target.value)}
                  style={{
                    padding: "6px 12px",
                    borderRadius: "6px",
                    border: "1px solid #cbd5e1",
                    fontSize: "13px",
                    minWidth: "240px",
                  }}
                />
              </div>

              <div style={{ maxHeight: "360px", overflowY: "auto", border: "1px solid #e2e8f0", borderRadius: "8px" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", fontFamily: "monospace" }}>
                  <thead style={{ position: "sticky", top: 0, background: "#f8fafc" }}>
                    <tr style={{ borderBottom: "1px solid #e2e8f0", textAlign: "left" }}>
                      <th style={{ padding: "8px 10px", width: "220px", color: "#475569" }}>Header Field</th>
                      <th style={{ padding: "8px 10px", color: "#475569" }}>Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredHeaders.map((h, idx) => (
                      <tr key={idx} style={{ borderBottom: "1px solid #f1f5f9" }}>
                        <td style={{ padding: "6px 10px", fontWeight: "700", color: "#334155" }}>{h.key}</td>
                        <td style={{ padding: "6px 10px", color: "#64748b", wordBreak: "break-all" }}>
                          {piiRedacted ? maskSensitiveText(String(h.value)) : String(h.value)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* EXTRACTED BODY TEXT */}
              <div style={{ marginTop: "20px" }}>
                <span style={{ fontSize: "12px", fontWeight: "700", color: "#475569", textTransform: "uppercase" }}>
                  Extracted Body Plaintext:
                </span>
                <pre
                  style={{
                    marginTop: "6px",
                    background: "#f8fafc",
                    padding: "14px",
                    borderRadius: "8px",
                    border: "1px solid #e2e8f0",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                    fontSize: "12px",
                    maxHeight: "260px",
                    overflowY: "auto",
                    color: "#1e293b",
                  }}
                >
                  {piiRedacted ? maskSensitiveText(analysis.bodyPreview) : analysis.bodyPreview}
                </pre>
              </div>
            </div>
          )}

          {/* TAB: EXONERATOR (THE TOR PROJECT RELAY & EXIT NODE FORENSICS) */}
          {activeTab === "exonerator" && (
            <div>
              {/* STATUS BANNER */}
              {(() => {
                const currentExon = customExonResult || analysis.exonerator || {};
                const isTor = Boolean(currentExon.isTorExitNode);
                const currentIp = currentExon.ip || analysis.earliestNodeIP || "N/A";
                const currentDate = currentExon.date || formatExoneratorDate(analysis.date);
                const docketUrl = currentExon.officialExoneratorUrl || buildExoneratorUrl(currentIp, currentDate);

                return (
                  <div>
                    <div
                      style={{
                        padding: "16px 20px",
                        borderRadius: "10px",
                        background: isTor ? "linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%)" : "linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%)",
                        border: isTor ? "1px solid #f87171" : "1px solid #86efac",
                        display: "flex",
                        alignItems: "center",
                        gap: "16px",
                        marginBottom: "20px",
                      }}
                    >
                      <div
                        style={{
                          width: "48px",
                          height: "48px",
                          borderRadius: "10px",
                          background: isTor ? "#ef4444" : "#22c55e",
                          color: "#fff",
                          display: "grid",
                          placeItems: "center",
                          flexShrink: 0,
                          boxShadow: "0 4px 10px rgba(0,0,0,0.12)",
                        }}
                      >
                        {isTor ? <ShieldAlert size={26} /> : <ShieldCheck size={26} />}
                      </div>

                      <div style={{ flex: 1 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
                          <span
                            style={{
                              fontSize: "11px",
                              fontWeight: "800",
                              letterSpacing: "0.06em",
                              textTransform: "uppercase",
                              padding: "3px 9px",
                              borderRadius: "4px",
                              background: isTor ? "#dc2626" : "#16a34a",
                              color: "#fff",
                            }}
                          >
                            {isTor ? "CONFIRMED TOR EXIT NODE" : "NEGATIVE — CLEAN NON-TOR RELAY"}
                          </span>
                          <span style={{ fontSize: "13px", fontWeight: "700", color: isTor ? "#991b1b" : "#166534" }}>
                            Confidence: {currentExon.confidence || "TorDNSEL Verified"}
                          </span>
                        </div>
                        <p style={{ margin: "6px 0 0", fontSize: "13px", color: "#1e293b", lineHeight: "1.5" }}>
                          {currentExon.summary || (isTor
                            ? `IP ${currentIp} was verified operating as an active Tor exit node on ${currentDate}. Transmission was routed through onion encryption.`
                            : `IP ${currentIp} showed no active Tor exit records on ${currentDate}.`)}
                        </p>
                      </div>

                      <a
                        href={docketUrl}
                        target="_blank"
                        rel="noreferrer"
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "8px",
                          padding: "10px 16px",
                          background: isTor ? "#991b1b" : "#0d2741",
                          color: "#fff",
                          borderRadius: "8px",
                          textDecoration: "none",
                          fontSize: "12px",
                          fontWeight: "700",
                          whiteSpace: "nowrap",
                          boxShadow: "0 2px 6px rgba(0,0,0,0.15)",
                        }}
                      >
                        <ExternalLink size={14} /> View Official ExoneraTor Docket
                      </a>
                    </div>

                    {/* METRICS GRID */}
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "14px", marginBottom: "24px" }}>
                      <div style={{ background: "#f8fafc", padding: "14px", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
                        <span style={{ fontSize: "11px", color: "#64748b", fontWeight: "700", textTransform: "uppercase" }}>Investigated IP Address</span>
                        <strong style={{ display: "block", fontSize: "15px", color: "#0f172a", marginTop: "4px", fontFamily: "monospace" }}>
                          {currentIp}
                        </strong>
                      </div>

                      <div style={{ background: "#f8fafc", padding: "14px", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
                        <span style={{ fontSize: "11px", color: "#64748b", fontWeight: "700", textTransform: "uppercase" }}>Evaluated Transmission Date</span>
                        <strong style={{ display: "block", fontSize: "15px", color: "#0f172a", marginTop: "4px" }}>
                          {currentDate}
                        </strong>
                      </div>

                      <div style={{ background: "#f8fafc", padding: "14px", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
                        <span style={{ fontSize: "11px", color: "#64748b", fontWeight: "700", textTransform: "uppercase" }}>Relay Classification</span>
                        <strong style={{ display: "block", fontSize: "15px", color: isTor ? "#dc2626" : "#16a34a", marginTop: "4px" }}>
                          {currentExon.relayType || (isTor ? "Tor Exit Node" : "Standard Host")}
                        </strong>
                      </div>

                      <div style={{ background: "#f8fafc", padding: "14px", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
                        <span style={{ fontSize: "11px", color: "#64748b", fontWeight: "700", textTransform: "uppercase" }}>Evidence Verification Source</span>
                        <strong style={{ display: "block", fontSize: "15px", color: "#0f172a", marginTop: "4px" }}>
                          {currentExon.source || "TorDNSEL + ExoneraTor"}
                        </strong>
                      </div>
                    </div>

                    {/* INTERACTIVE HISTORICAL RE-QUERY TOOL */}
                    <div
                      style={{
                        background: "#fff",
                        border: "1px solid #cbd5e1",
                        borderRadius: "10px",
                        padding: "20px",
                        marginBottom: "24px",
                        boxShadow: "0 1px 3px rgba(0,0,0,0.05)",
                      }}
                    >
                      <h3 style={{ margin: "0 0 8px", fontSize: "15px", color: "#0f172a", display: "flex", alignItems: "center", gap: "8px" }}>
                        <Search size={16} /> Forensic ExoneraTor Historical Inspector
                      </h3>
                      <p style={{ margin: "0 0 16px", fontSize: "13px", color: "#64748b" }}>
                        Test any IP address against any specific calendar date to verify historical Tor network participation at the exact time of message dispatch.
                      </p>

                      <div style={{ display: "flex", gap: "12px", flexWrap: "wrap", alignItems: "flex-end" }}>
                        <div style={{ flex: "1 1 200px" }}>
                          <label style={{ display: "block", fontSize: "12px", fontWeight: "700", color: "#475569", marginBottom: "4px" }}>
                            Target IP Address:
                          </label>
                          <input
                            type="text"
                            placeholder="e.g. 185.220.101.25"
                            defaultValue={currentIp}
                            onChange={(e) => setCustomExonIp(e.target.value)}
                            style={{
                              width: "100%",
                              padding: "8px 12px",
                              borderRadius: "6px",
                              border: "1px solid #cbd5e1",
                              fontSize: "13px",
                              boxSizing: "border-box",
                            }}
                          />
                        </div>

                        <div style={{ flex: "1 1 160px" }}>
                          <label style={{ display: "block", fontSize: "12px", fontWeight: "700", color: "#475569", marginBottom: "4px" }}>
                            Transmission Date:
                          </label>
                          <input
                            type="date"
                            defaultValue={currentDate}
                            onChange={(e) => setCustomExonDate(e.target.value)}
                            style={{
                              width: "100%",
                              padding: "8px 12px",
                              borderRadius: "6px",
                              border: "1px solid #cbd5e1",
                              fontSize: "13px",
                              boxSizing: "border-box",
                            }}
                          />
                        </div>

                        <button
                          onClick={() => handleVerifyExonerator()}
                          disabled={exonLoading}
                          style={{
                            padding: "9px 18px",
                            background: "#0d2741",
                            color: "#fff",
                            border: 0,
                            borderRadius: "6px",
                            fontSize: "13px",
                            fontWeight: "700",
                            cursor: exonLoading ? "wait" : "pointer",
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "8px",
                          }}
                        >
                          {exonLoading ? "Querying Tor Authorities..." : "Verify on ExoneraTor"}
                        </button>
                      </div>

                      {/* HOP SHORTCUTS IF MULTIPLE HOPS EXIST */}
                      {analysis.hopTrace?.hops?.length > 0 && (
                        <div style={{ marginTop: "16px", paddingTop: "14px", borderTop: "1px solid #f1f5f9" }}>
                          <span style={{ fontSize: "11px", fontWeight: "700", color: "#64748b", textTransform: "uppercase" }}>
                            Quick Query from Email Received Hops:
                          </span>
                          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginTop: "8px" }}>
                            {analysis.hopTrace.hops.map((hop, idx) => (
                              <button
                                key={idx}
                                onClick={() => handleVerifyExonerator(hop.ip, currentDate)}
                                style={{
                                  padding: "4px 10px",
                                  borderRadius: "4px",
                                  border: "1px solid #cbd5e1",
                                  background: "#f8fafc",
                                  fontSize: "11px",
                                  fontFamily: "monospace",
                                  cursor: "pointer",
                                }}
                              >
                                Hop {hop.hopIndex || idx + 1}: {hop.ip}
                              </button>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* JUDICIAL DOCKET REFERENCE */}
                    <div style={{ background: "#f8fafc", borderRadius: "8px", border: "1px solid #e2e8f0", padding: "16px" }}>
                      <span style={{ fontSize: "11px", fontWeight: "700", color: "#475569", textTransform: "uppercase" }}>
                        Judicial Evidence Admissibility (Section 65B IEA / Section 63 BSA):
                      </span>
                      <p style={{ margin: "6px 0 10px", fontSize: "12px", color: "#334155", lineHeight: "1.5" }}>
                        ExoneraTor queries are based on consensus network status documents published hourly by The Tor Project's Directory Authorities.
                        This electronic certification is integrated directly into generated Section 65B court evidence dossiers for criminal prosecution and cyber tribunal proceedings.
                      </p>
                      <div style={{ fontSize: "12px", fontFamily: "monospace", color: "#1e40af", wordBreak: "break-all" }}>
                        Docket URI: <a href={docketUrl} target="_blank" rel="noreferrer" style={{ textDecoration: "underline" }}>{docketUrl}</a>
                      </div>
                    </div>
                  </div>
                );
              })()}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
