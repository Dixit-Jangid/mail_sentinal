import { CheckCircle2 } from "lucide-react";

export default function LedgerRow({ title, detail, time }) {
  return (
    <div className="ledger-row">
      <div className="ledger-marker">
        <CheckCircle2 size={16} />
      </div>
      <div className="ledger-content">
        <strong>{title}</strong>
        {detail && <small style={{ color: "#64748b", display: "block" }}>{detail}</small>}
        <span>{time || "Completed"}</span>
      </div>
    </div>
  );
}
