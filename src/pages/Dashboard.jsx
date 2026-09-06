import {
  Activity,
  AlertTriangle,
  Database,
  Download,
  FileSearch,
  LockKeyhole,
  Mail,
  Server,
  ShieldAlert,
  ShieldCheck,
  UploadCloud,
  XCircle,
  Zap,
} from "lucide-react";
import StatCard from "../components/StatCard";
import PanelHeader from "../components/PanelHeader";
import RiskGauge from "../components/RiskGauge";
import SummaryRow from "../components/SummaryRow";
import AuthBadge from "../components/AuthBadge";
import Indicator from "../components/Indicator";
import LedgerRow from "../components/LedgerRow";
import RiskRemediesSection from "../components/RiskRemediesSection";

export default function Dashboard({
  file,
  analysis,
  dragging,
  setDragging,
  handleDrop,
  handleFile,
  setFile,
  analyzeFile,
  analyzing,
  setActivePage,
}) {
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="breadcrumb">
            Workspace <span>/</span> Dashboard
          </div>
          <h2>Email threat intelligence at a glance</h2>
          <p>
            Analyze suspicious messages, investigate indicators, and preserve
            forensic evidence.
          </p>
        </div>

        <button
          className="primary-button"
          onClick={() => setActivePage("reports")}
        >
          <Download size={16} />
          Generate Report
        </button>
      </div>

      <div className="stat-grid">
        <StatCard
          icon={<Mail />}
          label="Emails analyzed"
          value={analysis ? "1" : "0"}
          change={analysis ? "Current" : "Ready"}
        />

        <StatCard
          icon={<ShieldAlert />}
          label="Threats detected"
          value={analysis?.phishingDetected ? "1" : "0"}
          change={analysis ? (analysis.phishingDetected ? "Flagged" : "Clean") : "None"}
          danger={analysis?.phishingDetected}
          success={analysis && !analysis?.phishingDetected}
        />

        <StatCard
          icon={<AlertTriangle />}
          label="High-risk emails"
          value={analysis?.riskLevel === "High Risk" ? "1" : "0"}
          change={analysis ? analysis.riskLevel : "No scan"}
          danger={analysis?.riskLevel === "High Risk"}
          warning={analysis?.riskLevel === "Medium Risk"}
          success={analysis?.riskLevel === "Low Risk"}
        />

        <StatCard
          icon={<ShieldCheck />}
          label="Threats blocked"
          value={analysis?.riskLevel === "High Risk" ? "1" : "0"}
          change="Auto-Policy"
          success
        />

        <StatCard
          icon={<Zap />}
          label="Analysis status"
          value={analyzing ? "Scanning" : analysis ? "Ready" : "Idle"}
          change={analyzing ? "Processing" : analysis ? "Completed" : "Waiting"}
          purple
        />
      </div>

      <div className="main-grid">
        {/* UPLOAD PANEL */}
        <section className="panel upload-panel">
          <PanelHeader
            title="Analyze Email"
            subtitle="Upload an .eml file for forensic analysis"
            icon={<FileSearch size={18} />}
          />

          <div
            className={`dropzone ${dragging ? "dragging" : ""}`}
            onDragOver={(event) => {
              event.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
          >
            <div className="upload-icon">
              <UploadCloud size={25} />
            </div>

            <strong>{file ? file.name : "Drop your email file here"}</strong>

            <span>
              {file
                ? `${(file.size / 1024).toFixed(1)} KB selected`
                : "or choose a file from your computer"}
            </span>

            <div className="dropzone-actions-row">
              <label className="secondary-button">
                <UploadCloud size={15} />
                Choose .eml file
                <input
                  type="file"
                  accept=".eml,message/rfc822"
                  onChange={(event) => handleFile(event.target.files?.[0])}
                />
              </label>
            </div>

            <small style={{ marginTop: "10px", display: "block" }}>Maximum file size: 25 MB · RFC 822 / MIME format</small>
          </div>

          {file && (
            <div className="selected-file">
              <div className="file-icon">
                <Mail size={17} />
              </div>

              <div>
                <strong>{file.name}</strong>
                <span>Ready for analysis</span>
              </div>

              <button
                className="icon-button small"
                onClick={() => setFile(null)}
                aria-label="Remove file"
              >
                <XCircle size={17} />
              </button>
            </div>
          )}

          {file && (
            <button
              className="primary-button"
              style={{ marginTop: "16px", width: "100%" }}
              onClick={analyzeFile}
              disabled={analyzing}
            >
              <FileSearch size={16} />
              {analyzing ? "Analyzing Email..." : "Analyze Email"}
            </button>
          )}
        </section>

        {/* RISK PANEL */}
        <section className="panel risk-panel">
          <PanelHeader
            title="Threat Risk Score"
            subtitle="Current email assessment"
            icon={<ShieldAlert size={18} />}
          />
          <RiskGauge analysis={analysis} />
        </section>

        {/* SUMMARY PANEL */}
        <section className="panel summary-panel">
          <PanelHeader
            title="Email Summary"
            subtitle="Extracted message metadata"
            icon={<Mail size={18} />}
          />

          {!analysis ? (
            <div className="empty-analysis">
              <Mail size={38} />
              <h3>No email analyzed</h3>
              <p>Upload an .eml file to view its metadata.</p>
            </div>
          ) : (
            <>
              <div className="summary-list">
                <SummaryRow label="From" value={analysis.from} />
                <SummaryRow label="To" value={analysis.to} />
                <SummaryRow label="Subject" value={analysis.subject} />
                <SummaryRow label="Received" value={analysis.date} />
              </div>

              <div className="auth-grid">
                <AuthBadge
                  label="SPF"
                  status={analysis.spf}
                  danger={analysis.spf === "Fail"}
                />
                <AuthBadge
                  label="DKIM"
                  status={analysis.dkim}
                  danger={analysis.dkim === "Fail"}
                />
                <AuthBadge
                  label="DMARC"
                  status={analysis.dmarc}
                  danger={analysis.dmarc === "Fail"}
                />
              </div>
            </>
          )}
        </section>

        {/* THREAT INDICATORS */}
        <section className="panel indicators-panel">
          <PanelHeader
            title="Threat Indicators"
            subtitle="Signals contributing to the risk score"
            icon={<ShieldAlert size={18} />}
          />

          {!analysis ? (
            <p>Analyze an email to generate indicators.</p>
          ) : (
            <div className="indicator-list">
              {analysis.primaryClassification && (
                <Indicator
                  label="Classification"
                  value={analysis.primaryClassification.split("/")[0]}
                  danger={analysis.riskScore >= 70}
                  warning={analysis.riskScore >= 40 && analysis.riskScore < 70}
                />
              )}
              {analysis.nlpAudit?.detectedBecPatterns?.length > 0 && (
                <Indicator
                  label="BEC Vector"
                  value={analysis.nlpAudit.detectedBecPatterns[0]?.label}
                  danger
                />
              )}
              <Indicator
                label="Urgency triggers"
                value={
                  analysis.nlpAudit?.detectedTriggers?.length > 0
                    ? `${analysis.nlpAudit.detectedTriggers.length} Triggers`
                    : "Normal"
                }
                danger={analysis.nlpAudit?.detectedTriggers?.length > 1}
                warning={analysis.nlpAudit?.detectedTriggers?.length === 1}
              />
              <Indicator
                label="Phishing keywords"
                value={
                  analysis.phishingDetected
                    ? `${analysis.detectedKeywords.length} Detected`
                    : "None"
                }
                danger={analysis.phishingDetected}
              />
              <Indicator
                label="Suspicious links"
                value={
                  analysis.suspiciousLinks > 0
                    ? `${analysis.suspiciousLinks} found`
                    : "None"
                }
                danger={analysis.suspiciousLinks > 0}
              />
              <Indicator
                label="Total links"
                value={`${analysis.totalLinks}`}
              />
              <Indicator
                label="Attachments"
                value={`${analysis.attachmentCount}`}
                danger={analysis.dangerousAttachments?.length > 0}
              />
            </div>
          )}
        </section>

        {/* FORENSIC LEDGER PREVIEW */}
        <section className="panel ledger-panel">
          <PanelHeader
            title="Forensic Ledger"
            subtitle="Evidence timeline & SHA-256 integrity"
            icon={<LockKeyhole size={18} />}
          />

          {!analysis ? (
            <p>No forensic event recorded yet.</p>
          ) : (
            <div className="ledger-list">
              {analysis.timeline?.map((item, idx) => (
                <LedgerRow
                  key={idx}
                  title={item.step}
                  detail={item.detail || item.hash}
                  time={item.time}
                />
              ))}
            </div>
          )}
        </section>
      </div>

      {/* THREAT RISK FACTORS & REMEDIATION PLAYBOOK SECTION */}
      <RiskRemediesSection
        analysis={analysis}
        setActivePage={setActivePage}
      />

      <div className="bottom-strip">
        <div>
          <Server size={16} />
          <span>Analysis API</span>
          <strong>Operational</strong>
        </div>

        <div>
          <Database size={16} />
          <span>Forensic storage</span>
          <strong>Ready</strong>
        </div>

        <div>
          <LockKeyhole size={16} />
          <span>Evidence integrity</span>
          <strong>{analysis?.sha256 ? "SHA-256 Verified" : "Ready"}</strong>
        </div>

        <div>
          <Activity size={16} />
          <span>Analysis status</span>
          <strong>{analyzing ? "Processing" : analysis ? "Completed" : "Waiting"}</strong>
        </div>
      </div>
    </>
  );
}
