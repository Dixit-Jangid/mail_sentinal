import { AlertTriangle, ShieldCheck } from "lucide-react";

export default function RiskGauge({ analysis }) {
  const score = analysis?.riskScore ?? 0;
  const level = analysis?.riskLevel ?? "No Analysis";

  return (
    <div className="risk-gauge-wrap">
      <div className="risk-gauge">
        <div className="risk-gauge-inner">
          <strong>{score}</strong>
          <span>/ 100</span>
        </div>
      </div>

      <div
        className={`risk-label ${
          score >= 70 ? "danger" : score >= 40 ? "warning" : ""
        }`}
      >
        {score >= 70 ? (
          <AlertTriangle size={15} />
        ) : (
          <ShieldCheck size={15} />
        )}
        {level}
      </div>

      <p>
        {analysis
          ? "Risk calculated from email content, links, and authentication headers."
          : "Upload and analyze an email to calculate its threat score."}
      </p>
    </div>
  );
}
