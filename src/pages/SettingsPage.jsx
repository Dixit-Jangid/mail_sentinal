import { Settings, Sliders, CheckCircle2, RotateCcw } from "lucide-react";
import ModulePage from "../components/ModulePage";
import { DEFAULT_SETTINGS } from "../services/emailAnalyzer";

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
      title="Platform Settings"
      subtitle="Configure threat detection sensitivity, authentication strictness, and risk thresholds."
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
                <strong>Phishing Keyword Scanner</strong>
                <span style={{ display: "block", fontSize: "12px", color: "#64748b" }}>
                  Detect urgent calls-to-action, credential requests, and financial keywords.
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
      </div>
    </ModulePage>
  );
}
