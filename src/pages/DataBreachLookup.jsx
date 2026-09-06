import { useState, useCallback } from "react";
import {
  UserX,
  Search,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  ShieldCheck,
  KeyRound,
  Lock,
  Mail,
} from "lucide-react";
import ModulePage from "../components/ModulePage";
import { checkEmailBreaches } from "../services/breachService";

export default function DataBreachLookup({ analysis }) {
  // Extract potential emails from current analysis
  const senderEmail = analysis?.from?.includes("@")
    ? analysis.from.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/)?.[0] || ""
    : "";
  const recipientEmail = analysis?.to?.includes("@")
    ? analysis.to.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/)?.[0] || ""
    : "";

  const [emailInput, setEmailInput] = useState(senderEmail || "");
  const [loading, setLoading] = useState(false);
  const [breachResult, setBreachResult] = useState(null);
  const [error, setError] = useState(null);

  const handleCheck = useCallback(async (emailToQuery) => {
    const targetEmail = (emailToQuery || emailInput).trim();
    if (!targetEmail || !targetEmail.includes("@")) {
      setError("Please enter a valid email address (e.g. analyst@domain.com)");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const data = await checkEmailBreaches(targetEmail);
      setBreachResult(data);
    } catch (err) {
      console.error("Breach lookup failed:", err);
      setError(err.message || "Failed to query breach intelligence repository.");
    } finally {
      setLoading(false);
    }
  }, [emailInput]);

  return (
    <ModulePage
      title="Data Breach Intelligence"
      subtitle="Check if email addresses, targets, or suspicious senders have been compromised in global data breaches (Powered by HIBP telemetry)."
      icon={<UserX size={28} />}
    >
      {/* SEARCH CARD */}
      <div className="panel" style={{ marginBottom: "24px" }}>
        <h3>Breach & Credential Exposure Scanner</h3>
        <p>
          Search against billions of compromised accounts to detect if this identity’s credentials have been leaked online.
        </p>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleCheck();
          }}
          style={{ display: "flex", gap: "10px", marginTop: "16px" }}
        >
          <input
            type="email"
            placeholder="Enter email address (e.g. sender@suspicious.com or user@company.com)"
            value={emailInput}
            onChange={(e) => setEmailInput(e.target.value)}
            style={{
              flex: 1,
              padding: "12px 14px",
              borderRadius: "8px",
              border: "1px solid #d9e0ea",
              fontSize: "14px",
            }}
          />

          <button className="primary-button" type="submit" disabled={loading}>
            <Search size={16} />
            {loading ? "Scanning..." : "Check Breaches"}
          </button>
        </form>

        {error && (
          <div style={{ marginTop: "12px", color: "#dc2626", fontSize: "13px" }}>
            {error}
          </div>
        )}

        {/* QUICK TARGET CHIPS FROM ANALYZED EMAIL */}
        {(senderEmail || recipientEmail) && (
          <div style={{ marginTop: "16px" }}>
            <span style={{ fontSize: "12px", fontWeight: "700", color: "#64748b", textTransform: "uppercase" }}>
              Quick Check Analyzed Email Identities:
            </span>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "8px" }}>
              {senderEmail && (
                <button
                  type="button"
                  className="secondary-button"
                  style={{ padding: "6px 12px", fontSize: "12px" }}
                  onClick={() => {
                    setEmailInput(senderEmail);
                    handleCheck(senderEmail);
                  }}
                >
                  <Mail size={12} /> Check Sender: {senderEmail}
                </button>
              )}

              {recipientEmail && recipientEmail !== senderEmail && (
                <button
                  type="button"
                  className="secondary-button"
                  style={{ padding: "6px 12px", fontSize: "12px" }}
                  onClick={() => {
                    setEmailInput(recipientEmail);
                    handleCheck(recipientEmail);
                  }}
                >
                  <Mail size={12} /> Check Recipient: {recipientEmail}
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* RESULTS DISPLAY */}
      {breachResult && (
        <>
          {/* STATUS BANNER */}
          <div
            style={{
              padding: "20px 24px",
              borderRadius: "10px",
              marginBottom: "24px",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "16px",
              background: breachResult.pwned ? "#fee2e2" : "#dcfce7",
              border: `1px solid ${breachResult.pwned ? "#fca5a5" : "#86efac"}`,
              color: breachResult.pwned ? "#991b1b" : "#166534",
            }}
          >
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                {breachResult.pwned ? (
                  <AlertTriangle size={26} color="#dc2626" />
                ) : (
                  <ShieldCheck size={26} color="#16a34a" />
                )}
                <h3 style={{ margin: 0, fontSize: "18px", color: breachResult.pwned ? "#991b1b" : "#166534" }}>
                  {breachResult.pwned
                    ? `Oh no — pwned! ${breachResult.email} was found in ${breachResult.breachCount} data breach(es).`
                    : `Good news — no pwnage found! ${breachResult.email} has no recorded public breaches.`}
                </h3>
              </div>
              <p style={{ margin: "6px 0 0 36px", fontSize: "13px", opacity: 0.9 }}>
                {breachResult.pwned
                  ? "Passwords and sensitive credentials associated with this identity have been exposed in known cyberattacks."
                  : "This address has not been detected in any known compromised databases indexed by breach trackers."}
              </p>
            </div>

            <a
              href={breachResult.hibpUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="secondary-button"
              style={{
                background: "#ffffff",
                borderColor: breachResult.pwned ? "#fca5a5" : "#86efac",
                color: "#0f172a",
                display: "inline-flex",
                alignItems: "center",
                gap: "6px",
                padding: "8px 14px",
                fontSize: "13px",
                textDecoration: "none",
              }}
            >
              Verify on HaveIBeenPwned <ExternalLink size={14} />
            </a>
          </div>

          {/* BREACH CARDS LIST */}
          {breachResult.pwned && (
            <div className="panel" style={{ marginBottom: "24px" }}>
              <h3>Compromised Data Sources ({breachResult.breaches.length})</h3>
              <p>Details of incidents where data linked to this account was leaked.</p>

              <div style={{ display: "grid", gap: "16px", marginTop: "20px" }}>
                {breachResult.breaches.map((breach, index) => (
                  <div
                    key={index}
                    style={{
                      padding: "18px",
                      borderRadius: "8px",
                      background: "#f8fafc",
                      border: "1px solid #e2e8f0",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "10px" }}>
                      <div>
                        <strong style={{ fontSize: "16px", color: "#0f172a" }}>
                          {breach.name}
                        </strong>
                        <span style={{ display: "block", fontSize: "12px", color: "#64748b", marginTop: "2px" }}>
                          Breach Date: {breach.breachDate} · Domain: {breach.domain}
                        </span>
                      </div>

                      <span
                        style={{
                          padding: "4px 10px",
                          borderRadius: "6px",
                          fontSize: "11px",
                          fontWeight: "700",
                          background: "#fee2e2",
                          color: "#b91c1c",
                        }}
                      >
                        {breach.pwnCount ? `${breach.pwnCount.toLocaleString()} Accounts Pwned` : "Exposed"}
                      </span>
                    </div>

                    <p style={{ margin: "12px 0", fontSize: "13px", color: "#334155", lineHeight: "1.6" }}>
                      {breach.description}
                    </p>

                    <div>
                      <span style={{ fontSize: "11px", fontWeight: "700", color: "#64748b", textTransform: "uppercase" }}>
                        Compromised Data Classes:
                      </span>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "6px" }}>
                        {breach.dataClasses?.map((dc, i) => (
                          <span
                            key={i}
                            style={{
                              padding: "4px 8px",
                              borderRadius: "4px",
                              background: "#f1f5f9",
                              border: "1px solid #cbd5e1",
                              fontSize: "11px",
                              color: "#334155",
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "4px",
                            }}
                          >
                            {dc.toLowerCase().includes("password") ? (
                              <KeyRound size={11} color="#dc2626" />
                            ) : (
                              <Lock size={11} color="#64748b" />
                            )}
                            {dc}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* REMEDIATION CHECKLIST */}
          <div className="panel">
            <h3>Incident Response & Security Guidance</h3>
            <p>Recommended security countermeasures for breached identities.</p>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "16px", marginTop: "16px" }}>
              <div style={{ padding: "16px", background: "#f8fafc", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
                <strong style={{ display: "flex", alignItems: "center", gap: "6px", color: "#1e293b", fontSize: "14px" }}>
                  <KeyRound size={16} color="#2563eb" /> 1. Rotate Passwords
                </strong>
                <p style={{ fontSize: "12px", color: "#64748b", marginTop: "6px" }}>
                  Change passwords on all services where this email or password variation was used.
                </p>
              </div>

              <div style={{ padding: "16px", background: "#f8fafc", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
                <strong style={{ display: "flex", alignItems: "center", gap: "6px", color: "#1e293b", fontSize: "14px" }}>
                  <ShieldCheck size={16} color="#16a34a" /> 2. Enable 2-Factor Auth (2FA)
                </strong>
                <p style={{ fontSize: "12px", color: "#64748b", marginTop: "6px" }}>
                  Require authenticator app or hardware key verification for sign-in.
                </p>
              </div>

              <div style={{ padding: "16px", background: "#f8fafc", borderRadius: "8px", border: "1px solid #e2e8f0" }}>
                <strong style={{ display: "flex", alignItems: "center", gap: "6px", color: "#1e293b", fontSize: "14px" }}>
                  <CheckCircle2 size={16} color="#9333ea" /> 3. Password Manager
                </strong>
                <p style={{ fontSize: "12px", color: "#64748b", marginTop: "6px" }}>
                  Generate and store unique, high-entropy passwords across every portal.
                </p>
              </div>
            </div>
          </div>
        </>
      )}
    </ModulePage>
  );
}
