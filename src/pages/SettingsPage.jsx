import { Settings, Sliders, CheckCircle2, RotateCcw, Shield, Lock, EyeOff, FileCheck } from "lucide-react";
import ModulePage from "../components/ModulePage";
import { DEFAULT_SETTINGS } from "../services/emailAnalyzer";
import { RETENTION_POLICIES, COMPLIANCE_FRAMEWORKS } from "../services/privacyService";

export default function SettingsPage({ settings, setSettings }) {
  const handleChange = (key, value) => {
    setSettings((prev) => ({
      ...prev,
      [key]: value,
    }));
  };

  const resetDefaults = () => {
    setSettings(DEFAULT_SETTINGS);
  };

  return (
    <ModulePage
      title="Platform Settings & Compliance Controls"
      subtitle="Configure threat detection sensitivity, authentication strictness, risk thresholds, retention policies, and privacy controls."
      icon={<Settings size={28} />}
    >
      <div className="main-grid">
        {/* DETECTION ENGINES */}
        <div className="panel">
          <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Sliders size={18} /> Threat Detection Engines
          </h3>
          <p>Toggle individual heuristic analysis modules.</p>

          <div style={{ marginTop: "20px", display: "grid", gap: "16px" }}>
            <label style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={settings.detectKeywords}
                onChange={(e) => handleChange("detectKeywords", e.target.checked)}
                style={{ width: "18px", height: "18px" }}
              />
              <div>
                <strong>Phishing & Fraud Keyword Scanner</strong>
                <span style={{ display: "block", fontSize: "12px", color: "#64748b" }}>
                  Detect urgent calls-to-action, credential requests, and financial rerouting keywords.
                </span>
              </div>
            </label>

            <label style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={settings.detectSuspiciousLinks}
                onChange={(e) => handleChange("detectSuspiciousLinks", e.target.checked)}
                style={{ width: "18px", height: "18px" }}
              />
              <div>
                <strong>Suspicious Link & URL Shortener Detection</strong>
                <span style={{ display: "block", fontSize: "12px", color: "#64748b" }}>
                  Flag URL shorteners, raw HTTP links, and suspicious domain patterns.
                </span>
              </div>
            </label>

            <label style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={settings.checkAuthHeaders}
                onChange={(e) => handleChange("checkAuthHeaders", e.target.checked)}
                style={{ width: "18px", height: "18px" }}
              />
              <div>
                <strong>Email Authentication Audit (SPF, DKIM, DMARC)</strong>
                <span style={{ display: "block", fontSize: "12px", color: "#64748b" }}>
                  Verify authentication headers and penalize spoofed senders.
                </span>
              </div>
            </label>

            <label style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={settings.detectBecPatterns !== false}
                onChange={(e) => handleChange("detectBecPatterns", e.target.checked)}
                style={{ width: "18px", height: "18px" }}
              />
              <div>
                <strong>Advanced BEC & Fraud Pattern Classifier</strong>
                <span style={{ display: "block", fontSize: "12px", color: "#64748b" }}>
                  Detect wire diversion, fake invoice, and executive impersonation patterns.
                </span>
              </div>
            </label>
          </div>
        </div>

        {/* RISK THRESHOLDS */}
        <div className="panel">
          <h3>Risk Score Thresholds</h3>
          <p>Customize threat classification boundaries (0 - 100).</p>

          <div style={{ marginTop: "20px", display: "grid", gap: "20px" }}>
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
                <span>High Risk Threshold:</span>
                <strong>≥ {settings.riskThresholdHigh} pts</strong>
              </div>
              <input
                type="range"
                min="50"
                max="90"
                value={settings.riskThresholdHigh}
                onChange={(e) => handleChange("riskThresholdHigh", parseInt(e.target.value, 10))}
                style={{ width: "100%" }}
              />
            </div>

            <div>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
                <span>Medium Risk Threshold:</span>
                <strong>≥ {settings.riskThresholdMedium} pts</strong>
              </div>
              <input
                type="range"
                min="20"
                max="50"
                value={settings.riskThresholdMedium}
                onChange={(e) => handleChange("riskThresholdMedium", parseInt(e.target.value, 10))}
                style={{ width: "100%" }}
              />
            </div>

            <div style={{ marginTop: "10px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: "12px", color: "#16a34a", display: "flex", alignItems: "center", gap: "4px" }}>
                <CheckCircle2 size={14} /> Settings automatically applied
              </span>

              <button className="secondary-button" onClick={resetDefaults} style={{ padding: "6px 12px", fontSize: "12px" }}>
                <RotateCcw size={14} /> Reset Defaults
              </button>
            </div>
          </div>
        </div>

        {/* PRIVACY, RETENTION & COMPLIANCE CONTROLS */}
        <div className="panel" style={{ gridColumn: "1 / -1" }}>
          <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Shield size={18} style={{ color: "#2563eb" }} /> Privacy, Data Retention & Compliance Controls
          </h3>
          <p>
            Configure sensitive data masking, evidence retention policies, and compliance standards (GDPR, DPDP 2023, ISO 27701).
          </p>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", marginTop: "20px" }}>
            {/* RETENTION POLICY SELECTION */}
            <div>
              <label style={{ fontSize: "12px", fontWeight: "700", color: "#0f172a", display: "block", marginBottom: "6px" }}>
                Evidence Retention Policy
              </label>
              <select
                value={settings.retentionPolicy || "90_days"}
                onChange={(e) => handleChange("retentionPolicy", e.target.value)}
                style={{ width: "100%", padding: "8px 12px", fontSize: "13px" }}
              >
                {RETENTION_POLICIES.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.label}
                  </option>
                ))}
              </select>
              <span style={{ display: "block", fontSize: "12px", color: "#64748b", marginTop: "6px" }}>
                {RETENTION_POLICIES.find((p) => p.id === (settings.retentionPolicy || "90_days"))?.description}
              </span>

              {/* DEFAULT PII REDACTION TOGGLE */}
              <div style={{ marginTop: "18px" }}>
                <label style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={Boolean(settings.defaultPiiRedacted)}
                    onChange={(e) => handleChange("defaultPiiRedacted", e.target.checked)}
                    style={{ width: "18px", height: "18px" }}
                  />
                  <div>
                    <strong style={{ fontSize: "13px" }}>Default PII Data Masking Active</strong>
                    <span style={{ display: "block", fontSize: "12px", color: "#64748b" }}>
                      Automatically mask sender/recipient emails, IP subnets, bank accounts, and phone numbers in all generated reports.
                    </span>
                  </div>
                </label>
              </div>
            </div>

            {/* COMPLIANCE ATTESTATION FRAMEWORKS */}
            <div style={{ background: "#f8fafc", padding: "16px", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
              <strong style={{ fontSize: "13px", color: "#0f172a", display: "block", marginBottom: "10px" }}>
                Active Compliance Frameworks
              </strong>
              <div style={{ display: "grid", gap: "8px" }}>
                {COMPLIANCE_FRAMEWORKS.map((f) => (
                  <div key={f.code} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "12px" }}>
                    <div>
                      <span style={{ fontWeight: "600", color: "#1e293b" }}>{f.name}</span>
                      <span style={{ display: "block", fontSize: "11px", color: "#64748b" }}>{f.description}</span>
                    </div>
                    <span style={{ padding: "2px 8px", borderRadius: "4px", background: "#dcfce7", color: "#15803d", fontWeight: "700", fontSize: "10px", whiteSpace: "nowrap", marginLeft: "8px" }}>
                      {f.badge}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </ModulePage>
  );
}
