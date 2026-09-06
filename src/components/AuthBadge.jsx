import { CheckCircle2, XCircle, HelpCircle } from "lucide-react";

export default function AuthBadge({ label, status, danger }) {
  const isPass = status === "Pass";
  const isFail = status === "Fail" || danger;

  return (
    <div className="auth-badge">
      <span>{label}</span>
      <strong className={isFail ? "danger-text" : isPass ? "success-text" : "muted-text"}>
        {isFail ? (
          <XCircle size={14} />
        ) : isPass ? (
          <CheckCircle2 size={14} />
        ) : (
          <HelpCircle size={14} />
        )}
        {status}
      </strong>
    </div>
  );
}
