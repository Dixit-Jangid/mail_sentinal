import { useState } from "react";
import {
  Database,
  LockKeyhole,
  CheckCircle2,
  Copy,
  Check,
  ShieldCheck,
  FileSearch,
} from "lucide-react";
import ModulePage from "../components/ModulePage";

export default function ForensicLedger({ analysis, setActivePage }) {
  const [copied, setCopied] = useState(false);

  const copyHash = () => {
    if (!analysis?.sha256) return;
    navigator.clipboard.writeText(analysis.sha256);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <ModulePage
      title="Forensic Ledger"
      subtitle="Tamper-evident chain of custody, cryptographic evidence verification, and analysis timeline."
      icon={<Database size={28} />}
    >
      {!analysis ? (
        <div className="panel empty-analysis" style={{ textAlign: "center", padding: "40px 20px" }}>
          <LockKeyhole size={42} style={{ color: "#94a3b8", margin: "0 auto 12px" }} />
          <h3>No Forensic Ledger Entries</h3>
          <p>Analyze an email to generate a verifiable cryptographic audit trail.</p>
          <button
            className="primary-button"
            style={{ marginTop: "16px" }}
            onClick={() => setActivePage("dashboard")}
          >
            <FileSearch size={16} /> Go to Dashboard
          </button>
        </div>
      ) : (
        <>
          {/* EVIDENCE CERTIFICATE CARD */}
          <div
            className="panel"
            style={{
              marginBottom: "24px",
              background: "linear-gradient(135deg, #0d2741 0%, #173b61 100%)",
              color: "#fff",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "12px" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#60a5fa", fontSize: "12px", fontWeight: "700", textTransform: "uppercase" }}>
                  <ShieldCheck size={16} /> Cryptographic Evidence Certificate
                </div>
                <h3 style={{ color: "#fff", marginTop: "4px", fontSize: "20px" }}>{analysis.fileName}</h3>
                <span style={{ color: "#94a3b8", fontSize: "13px" }}>
                  Evidence ID: {analysis.id} · Recorded: {analysis.analyzedAt}
                </span>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span
                  style={{
                    padding: "6px 12px",
                    borderRadius: "6px",
                    background: "rgba(34, 197, 94, 0.2)",
                    border: "1px solid rgba(34, 197, 94, 0.4)",
                    color: "#4ade80",
                    fontWeight: "700",
                    fontSize: "12px",
                  }}
                >
                  INTEGRITY VERIFIED
                </span>
              </div>
            </div>

            <div style={{ marginTop: "20px", background: "rgba(0,0,0,0.25)", padding: "16px", borderRadius: "8px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                <span style={{ fontSize: "12px", color: "#94a3b8" }}>SHA-256 Fingerprint (WebCrypto Digest):</span>
                <button
                  onClick={copyHash}
                  style={{
                    background: "transparent",
                    border: 0,
                    color: copied ? "#4ade80" : "#60a5fa",
                    fontSize: "12px",
                    display: "flex",
                    alignItems: "center",
                    gap: "4px",
                    cursor: "pointer",
                  }}
                >
                  {copied ? <Check size={13} /> : <Copy size={13} />}
                  {copied ? "Copied" : "Copy Hash"}
                </button>
              </div>
              <code style={{ fontSize: "13px", color: "#38bdf8", wordBreak: "break-all", fontFamily: "monospace" }}>
                {analysis.sha256}
              </code>
            </div>
          </div>

          {/* CHAIN OF CUSTODY TIMELINE BLOCKS */}
          <div className="panel">
            <h3>Chain of Custody Blocks</h3>
            <p>Immutable sequential stages of forensic email ingestion and analysis.</p>

            <div style={{ marginTop: "20px", display: "grid", gap: "16px" }}>
              {analysis.timeline?.map((item, index) => (
                <div
                  key={index}
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: "16px",
                    padding: "16px",
                    borderRadius: "8px",
                    background: "#f8fafc",
                    border: "1px solid #e2e8f0",
                  }}
                >
                  <div
                    style={{
                      width: "36px",
                      height: "36px",
                      borderRadius: "50%",
                      background: "#dcfce7",
                      color: "#16a34a",
                      display: "grid",
                      placeItems: "center",
                      flexShrink: 0,
                      fontWeight: "700",
                    }}
                  >
                    <CheckCircle2 size={20} />
                  </div>

                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap" }}>
                      <strong style={{ fontSize: "15px", color: "#1e293b" }}>
                        Block #{index}: {item.step}
                      </strong>
                      <span style={{ fontSize: "12px", color: "#64748b" }}>{item.time}</span>
                    </div>

                    <div style={{ marginTop: "4px", fontSize: "13px", color: "#475569" }}>
                      {item.detail || item.hash}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </ModulePage>
  );
}
