import { AlertTriangle, CheckCircle2 } from "lucide-react";

export default function Indicator({ label, value, danger }) {
  return (
    <div className="indicator-row">
      <div>
        {danger ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}
        <span>{label}</span>
      </div>
      <strong>{value}</strong>
    </div>
  );
}
