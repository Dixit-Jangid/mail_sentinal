import { useState } from "react";
import {
  BarChart3,
  UploadCloud,
  FileSearch,
  CheckCircle2,
  AlertTriangle,
  Download,
  Trash2,
  Eye,
} from "lucide-react";
import ModulePage from "../components/ModulePage";
import { analyzeEmlFile } from "../services/emailAnalyzer";

export default function BulkScan({ onSelectEmail, setActivePage, settings }) {
  const [files, setFiles] = useState([]);
  const [results, setResults] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [filter, setFilter] = useState("all"); // all, high, medium, low

  const handleFilesSelected = (selectedFiles) => {
    if (!selectedFiles || selectedFiles.length === 0) return;
    const emlFiles = Array.from(selectedFiles).filter((f) =>
      f.name.toLowerCase().endsWith(".eml")
    );

    if (emlFiles.length === 0) {
      alert("Please select valid .eml email files.");
      return;
    }

    setFiles(emlFiles);
    setResults([]);
    setProgress(0);
  };

  const runBulkAnalysis = async () => {
    if (files.length === 0) return;
    setScanning(true);
    setProgress(0);

    const scannedResults = [];
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      try {
        const res = await analyzeEmlFile(file, settings);
        scannedResults.push(res);
      } catch (err) {
        console.error(`Failed to analyze ${file.name}:`, err);
        scannedResults.push({
          id: `err-${i}`,
          fileName: file.name,
          subject: "(Analysis Error)",
          from: "Unknown",
          riskScore: 0,
          riskLevel: "Error",
          phishingDetected: false,
          attachmentCount: 0,
          analyzedAt: new Date().toLocaleTimeString(),
        });
      }
      setProgress(Math.round(((i + 1) / files.length) * 100));
    }

    setResults(scannedResults);
    setScanning(false);
  };

  const clearAll = () => {
    setFiles([]);
    setResults([]);
    setProgress(0);
  };

  const exportCSV = () => {
    if (results.length === 0) return;
    const header = "File Name,Subject,From,Risk Score,Risk Level,Phishing,Suspicious Links,SPF,DKIM,DMARC,Attachments\n";
    const rows = results.map((r) =>
      `"${r.fileName}","${(r.subject || "").replace(/"/g, '""')}","${r.from}",${r.riskScore},"${r.riskLevel}",${r.phishingDetected},${r.suspiciousLinks || 0},"${r.spf || "N/A"}","${r.dkim || "N/A"}","${r.dmarc || "N/A"}",${r.attachmentCount || 0}`
    ).join("\n");

    const blob = new Blob([header + rows], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `bulk-forensics-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredResults = results.filter((r) => {
    if (filter === "high") return r.riskLevel === "High Risk";
    if (filter === "medium") return r.riskLevel === "Medium Risk";
    if (filter === "low") return r.riskLevel === "Low Risk";
    return true;
  });

  const highRiskCount = results.filter((r) => r.riskLevel === "High Risk").length;
  const threatsCount = results.filter((r) => r.phishingDetected).length;

  return (
    <ModulePage
      title="Bulk Email Scan"
      subtitle="Analyze batches of .eml messages concurrently for automated threat triage."
      icon={<BarChart3 size={28} />}
    >
      <div className="panel" style={{ marginBottom: "24px" }}>
        <h3>Batch Upload Workspace</h3>
        <p>Select multiple .eml files to queue them for batch forensic analysis.</p>

        <div style={{ display: "flex", gap: "12px", alignItems: "center", marginTop: "16px", flexWrap: "wrap" }}>
          <label className="secondary-button" style={{ display: "inline-flex", cursor: "pointer" }}>
            <UploadCloud size={16} />
            Choose Multiple .eml Files
            <input
              type="file"
              accept=".eml,message/rfc822"
              multiple
              onChange={(e) => handleFilesSelected(e.target.files)}
              hidden
            />
          </label>

          {files.length > 0 && (
            <>
              <button
                className="primary-button"
                onClick={runBulkAnalysis}
                disabled={scanning}
              >
                <FileSearch size={16} />
                {scanning ? `Scanning (${progress}%)...` : `Scan ${files.length} Email(s)`}
              </button>

              <button
                className="secondary-button"
                onClick={clearAll}
                disabled={scanning}
                style={{ color: "#ef4444" }}
              >
                <Trash2 size={16} />
                Clear
              </button>
            </>
          )}

          {results.length > 0 && (
            <button className="secondary-button" onClick={exportCSV}>
              <Download size={16} />
              Export CSV Report
            </button>
          )}
        </div>

        {files.length > 0 && (
          <div style={{ marginTop: "16px", color: "#475569", fontSize: "14px" }}>
            <strong>{files.length}</strong> file(s) selected: {files.slice(0, 3).map((f) => f.name).join(", ")}
            {files.length > 3 && ` and ${files.length - 3} more`}
          </div>
        )}

        {scanning && (
          <div style={{ marginTop: "16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", marginBottom: "4px" }}>
              <span>Progress</span>
              <span>{progress}%</span>
            </div>
            <div className="system-progress" style={{ height: "8px" }}>
              <span style={{ width: `${progress}%` }} />
            </div>
          </div>
        )}
      </div>

      {results.length > 0 && (
        <>
          <div className="stat-grid" style={{ marginBottom: "24px" }}>
            <div className="stat-card">
              <div className="stat-icon purple"><BarChart3 size={20} /></div>
              <div className="stat-copy">
                <span>Total Scanned</span>
                <strong>{results.length}</strong>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon danger"><AlertTriangle size={20} /></div>
              <div className="stat-copy">
                <span>High Risk Emails</span>
                <strong>{highRiskCount}</strong>
              </div>
              <div className="stat-change danger">{((highRiskCount / results.length) * 100).toFixed(0)}%</div>
            </div>

            <div className="stat-card">
              <div className="stat-icon warning"><AlertTriangle size={20} /></div>
              <div className="stat-copy">
                <span>Phishing Flags</span>
                <strong>{threatsCount}</strong>
              </div>
            </div>

            <div className="stat-card">
              <div className="stat-icon success"><CheckCircle2 size={20} /></div>
              <div className="stat-copy">
                <span>Clean / Low Risk</span>
                <strong>{results.length - highRiskCount}</strong>
              </div>
            </div>
          </div>

          <div className="panel">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", flexWrap: "wrap", gap: "10px" }}>
              <h3>Batch Triage Results ({filteredResults.length})</h3>
              <div style={{ display: "flex", gap: "6px" }}>
                {["all", "high", "medium", "low"].map((f) => (
                  <button
                    key={f}
                    className={`secondary-button ${filter === f ? "active-tab" : ""}`}
                    onClick={() => setFilter(f)}
                    style={{ padding: "4px 10px", fontSize: "12px", textTransform: "capitalize" }}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
                <thead>
                  <tr style={{ borderBottom: "2px solid #e2e8f0", textAlign: "left", color: "#64748b" }}>
                    <th style={{ padding: "10px 8px" }}>File Name</th>
                    <th style={{ padding: "10px 8px" }}>Subject</th>
                    <th style={{ padding: "10px 8px" }}>Sender</th>
                    <th style={{ padding: "10px 8px" }}>Threat Score</th>
                    <th style={{ padding: "10px 8px" }}>Auth (SPF/DKIM)</th>
                    <th style={{ padding: "10px 8px" }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredResults.map((res, i) => (
                    <tr key={res.id || i} style={{ borderBottom: "1px solid #f1f5f9" }}>
                      <td style={{ padding: "10px 8px", fontWeight: "600" }}>{res.fileName}</td>
                      <td style={{ padding: "10px 8px", color: "#334155" }}>{res.subject}</td>
                      <td style={{ padding: "10px 8px", color: "#64748b" }}>{res.from}</td>
                      <td style={{ padding: "10px 8px" }}>
                        <span
                          style={{
                            padding: "4px 8px",
                            borderRadius: "6px",
                            fontWeight: "700",
                            fontSize: "12px",
                            background:
                              res.riskScore >= 70
                                ? "#fee2e2"
                                : res.riskScore >= 40
                                ? "#fef3c7"
                                : "#dcfce7",
                            color:
                              res.riskScore >= 70
                                ? "#b91c1c"
                                : res.riskScore >= 40
                                ? "#b45309"
                                : "#15803d",
                          }}
                        >
                          {res.riskScore}/100 ({res.riskLevel})
                        </span>
                      </td>
                      <td style={{ padding: "10px 8px", fontSize: "11px", color: "#475569" }}>
                        SPF: {res.spf || "N/A"} | DKIM: {res.dkim || "N/A"}
                      </td>
                      <td style={{ padding: "10px 8px" }}>
                        <button
                          className="secondary-button"
                          style={{ padding: "4px 8px", fontSize: "11px" }}
                          onClick={() => {
                            if (onSelectEmail) onSelectEmail(res);
                            if (setActivePage) setActivePage("analyze");
                          }}
                        >
                          <Eye size={12} /> Inspect
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </ModulePage>
  );
}
