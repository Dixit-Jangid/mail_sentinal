import { useState, useMemo } from "react";
import {
  FolderArchive,
  Search,
  Filter,
  ShieldAlert,
  CheckCircle2,
  Clock,
  Layers,
  ArrowRight,
  Copy,
  Check,
  Tag,
  Download,
} from "lucide-react";
import ModulePage from "../components/ModulePage";

const DEFAULT_CAMPAIGNS = [
  {
    id: "CASE-2026-001",
    campaign: "Campaign #FIN-WireDiversion-Global",
    subject: "URGENT: Updated Wire Instructions for Q3 Settlement",
    sender: "cfo-office@finance-corp-global.com",
    senderDomain: "finance-corp-global.com",
    category: "BEC / Payment Diversion",
    riskScore: 92,
    riskLevel: "High Risk",
    status: "Quarantined",
    originIP: "185.220.101.45",
    date: "2026-09-04 14:22:10",
    attribution: "Financial Fraud Syndicate (BEC)",
    notes: "Attempted to reroute $142,000 vendor payment. Origin IP linked to bulletproof hosting.",
  },
  {
    id: "CASE-2026-002",
    campaign: "Campaign #Brand-Impersonation-Deception",
    subject: "Your PayPal Account Access Has Been Restricted Immediately",
    sender: "security@paypa1-support-verify.com",
    senderDomain: "paypa1-support-verify.com",
    category: "Credential Harvesting",
    riskScore: 88,
    riskLevel: "High Risk",
    status: "Active Triage",
    originIP: "194.26.29.112",
    date: "2026-09-04 11:05:41",
    attribution: "Spoofed Domain / Forged Headers",
    notes: "Typosquatted domain with deceptive anchor tags pointing to malicious landing page.",
  },
  {
    id: "CASE-2026-003",
    campaign: "Campaign #ATO-BEC-Executive",
    subject: "Quick request - Are you at your desk right now?",
    sender: "executive-ceo@company-holdings.org",
    senderDomain: "company-holdings.org",
    category: "Executive Impersonation",
    riskScore: 78,
    riskLevel: "High Risk",
    status: "Under Investigation",
    originIP: "103.251.167.22",
    date: "2026-09-03 16:45:00",
    attribution: "Compromised Legitimate Account",
    notes: "SPF/DKIM passed, but Reply-To diverted to personal webmail. Suspected Account Takeover.",
  },
  {
    id: "CASE-2026-004",
    campaign: "Campaign #O365-CredentialHarvest",
    subject: "Action Required: 3 Incoming Messages Pending Release",
    sender: "postmaster@mail-filter-notification.net",
    senderDomain: "mail-filter-notification.net",
    category: "Credential Harvesting",
    riskScore: 68,
    riskLevel: "Medium Risk",
    status: "Resolved",
    originIP: "45.142.122.90",
    date: "2026-09-02 09:12:30",
    attribution: "Phishing-as-a-Service (PhaaS) Kit",
    notes: "Phishing kit hosted on shared cloud instance. Blocked at perimeter firewall.",
  },
];

export default function CaseManagement({ analysis, setActivePage }) {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedStatus, setSelectedStatus] = useState("All");
  const [selectedCategory, setSelectedCategory] = useState("All");
  const [cases, setCases] = useState(() => {
    if (analysis) {
      const activeCase = {
        id: `CASE-${analysis.id.substring(5, 13).toUpperCase()}`,
        campaign: analysis.attribution?.campaignTag || "Campaign #Active-Investigation",
        subject: analysis.subject,
        sender: analysis.from,
        senderDomain: analysis.senderDomain,
        category: analysis.primaryClassification,
        riskScore: analysis.riskScore,
        riskLevel: analysis.riskLevel,
        status: analysis.riskScore >= 70 ? "Quarantined" : "Active Triage",
        originIP: analysis.earliestNodeIP || "198.51.100.14",
        date: analysis.analyzedAt,
        attribution: analysis.attribution?.infrastructureType || "Analyzed Sender Node",
        notes: `Analyzed via Forensics Workbench. Integrity Hash: ${analysis.sha256.substring(0, 16)}...`,
      };
      return [activeCase, ...DEFAULT_CAMPAIGNS];
    }
    return DEFAULT_CAMPAIGNS;
  });

  const [copiedId, setCopiedId] = useState(null);

  const copyIoc = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const updateCaseStatus = (caseId, newStatus) => {
    setCases((prev) =>
      prev.map((c) => (c.id === caseId ? { ...c, status: newStatus } : c))
    );
  };

  const filteredCases = useMemo(() => {
    return cases.filter((c) => {
      const matchesSearch =
        c.subject.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.campaign.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.sender.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.id.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesStatus =
        selectedStatus === "All" || c.status === selectedStatus;

      const matchesCategory =
        selectedCategory === "All" || c.category.toLowerCase().includes(selectedCategory.toLowerCase());

      return matchesSearch && matchesStatus && matchesCategory;
    });
  }, [cases, searchQuery, selectedStatus, selectedCategory]);

  const campaignStats = useMemo(() => {
    const map = {};
    cases.forEach((c) => {
      map[c.campaign] = (map[c.campaign] || 0) + 1;
    });
    return Object.entries(map);
  }, [cases]);

  return (
    <ModulePage
      title="Case Management & Campaign Explorer"
      subtitle="Group related fraudulent emails, track incident triage workflows, and correlate cross-organization threat campaigns."
      icon={<FolderArchive size={28} />}
    >
      {/* CAMPAIGN METRICS TILES */}
      <div className="stat-grid" style={{ marginBottom: "24px" }}>
        <div className="stat-card">
          <div className="stat-icon-wrapper blue">
            <Layers size={20} />
          </div>
          <div className="stat-content">
            <span className="stat-label">Active Campaigns</span>
            <strong className="stat-value">{campaignStats.length}</strong>
            <span className="stat-change success">Clustered</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon-wrapper red">
            <ShieldAlert size={20} />
          </div>
          <div className="stat-content">
            <span className="stat-label">Quarantined Cases</span>
            <strong className="stat-value">
              {cases.filter((c) => c.status === "Quarantined").length}
            </strong>
            <span className="stat-change danger">High Risk</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon-wrapper purple">
            <Clock size={20} />
          </div>
          <div className="stat-content">
            <span className="stat-label">Under Investigation</span>
            <strong className="stat-value">
              {cases.filter((c) => c.status === "Under Investigation" || c.status === "Active Triage").length}
            </strong>
            <span className="stat-change warning">In Progress</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon-wrapper green">
            <CheckCircle2 size={20} />
          </div>
          <div className="stat-content">
            <span className="stat-label">Resolved Incidents</span>
            <strong className="stat-value">
              {cases.filter((c) => c.status === "Resolved").length}
            </strong>
            <span className="stat-change success">Mitigated</span>
          </div>
        </div>
      </div>

      {/* SEARCH AND FILTER BAR */}
      <div className="panel" style={{ marginBottom: "20px" }}>
        <div style={{ display: "flex", gap: "12px", flexWrap: "wrap", alignItems: "center" }}>
          <div style={{ position: "relative", flex: 1, minWidth: "260px" }}>
            <Search
              size={18}
              style={{ position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)", color: "#94a3b8" }}
            />
            <input
              type="text"
              placeholder="Search by campaign name, subject, sender, or case ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: "100%",
                padding: "10px 14px 10px 38px",
                borderRadius: "8px",
                border: "1px solid #d9e0ea",
                fontSize: "14px",
              }}
            />
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Filter size={16} style={{ color: "#64748b" }} />
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              style={{
                padding: "10px 12px",
                borderRadius: "8px",
                border: "1px solid #d9e0ea",
                fontSize: "13px",
                background: "#fff",
              }}
            >
              <option value="All">All Statuses</option>
              <option value="Active Triage">Active Triage</option>
              <option value="Quarantined">Quarantined</option>
              <option value="Under Investigation">Under Investigation</option>
              <option value="Resolved">Resolved</option>
            </select>

            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              style={{
                padding: "10px 12px",
                borderRadius: "8px",
                border: "1px solid #d9e0ea",
                fontSize: "13px",
                background: "#fff",
              }}
            >
              <option value="All">All Categories</option>
              <option value="Payment Diversion">Payment Diversion (BEC)</option>
              <option value="Credential">Credential Harvesting</option>
              <option value="Executive">Executive Impersonation</option>
              <option value="Spoofed">Spoofed Domain</option>
            </select>
          </div>
        </div>
      </div>

      {/* CASES LIST */}
      <div className="panel">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: "17px" }}>Incident Cases ({filteredCases.length})</h3>
            <span style={{ fontSize: "12px", color: "#64748b" }}>
              Attributed threats grouped by attack patterns and campaign clusters
            </span>
          </div>

          <button
            className="secondary-button"
            style={{ fontSize: "12px", padding: "6px 12px" }}
            onClick={() => {
              const allIocs = filteredCases.map((c) => `${c.id},${c.campaign},${c.sender},${c.originIP}`).join("\n");
              const blob = new Blob([`CaseID,Campaign,Sender,OriginIP\n${allIocs}`], { type: "text/csv" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = "campaign-cases-export.csv";
              a.click();
            }}
          >
            <Download size={14} /> Export Cases CSV
          </button>
        </div>

        <div style={{ display: "grid", gap: "14px" }}>
          {filteredCases.map((c) => {
            const isHigh = c.riskScore >= 70;
            const isMedium = c.riskScore >= 40 && c.riskScore < 70;

            return (
              <div
                key={c.id}
                style={{
                  border: "1px solid #e2e8f0",
                  borderRadius: "10px",
                  padding: "16px",
                  background: "#fff",
                  transition: "box-shadow 0.2s ease",
                  display: "grid",
                  gap: "12px",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "8px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <span
                      style={{
                        padding: "4px 8px",
                        borderRadius: "6px",
                        fontSize: "11px",
                        fontWeight: "700",
                        background: "#0f172a",
                        color: "#fff",
                        fontFamily: "monospace",
                      }}
                    >
                      {c.id}
                    </span>

                    <span
                      style={{
                        padding: "4px 10px",
                        borderRadius: "20px",
                        fontSize: "12px",
                        fontWeight: "600",
                        background: "#eff6ff",
                        color: "#2563eb",
                        display: "flex",
                        alignItems: "center",
                        gap: "4px",
                      }}
                    >
                      <Tag size={12} /> {c.campaign}
                    </span>

                    <span
                      style={{
                        padding: "4px 8px",
                        borderRadius: "6px",
                        fontSize: "11px",
                        fontWeight: "700",
                        background: isHigh ? "#fee2e2" : isMedium ? "#fef3c7" : "#dcfce7",
                        color: isHigh ? "#b91c1c" : isMedium ? "#b45309" : "#15803d",
                      }}
                    >
                      Score: {c.riskScore}/100 ({c.riskLevel})
                    </span>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <label style={{ fontSize: "12px", color: "#64748b", fontWeight: "600" }}>Status:</label>
                    <select
                      value={c.status}
                      onChange={(e) => updateCaseStatus(c.id, e.target.value)}
                      style={{
                        padding: "4px 8px",
                        borderRadius: "6px",
                        fontSize: "12px",
                        fontWeight: "600",
                        border: "1px solid #cbd5e1",
                        background:
                          c.status === "Quarantined"
                            ? "#fff1f2"
                            : c.status === "Resolved"
                            ? "#f0fdf4"
                            : "#f8fafc",
                        color:
                          c.status === "Quarantined"
                            ? "#be123c"
                            : c.status === "Resolved"
                            ? "#15803d"
                            : "#334155",
                      }}
                    >
                      <option value="Active Triage">Active Triage</option>
                      <option value="Quarantined">Quarantined</option>
                      <option value="Under Investigation">Under Investigation</option>
                      <option value="Resolved">Resolved</option>
                    </select>
                  </div>
                </div>

                <div>
                  <h4 style={{ margin: "0 0 4px", fontSize: "15px", color: "#0f172a" }}>{c.subject}</h4>
                  <div style={{ display: "flex", gap: "16px", flexWrap: "wrap", fontSize: "12px", color: "#64748b" }}>
                    <span>
                      <strong>From:</strong> {c.sender}
                    </span>
                    <span>
                      <strong>Origin IP:</strong> {c.originIP}
                    </span>
                    <span>
                      <strong>Category:</strong> {c.category}
                    </span>
                    <span>
                      <strong>Logged:</strong> {c.date}
                    </span>
                  </div>
                </div>

                <div
                  style={{
                    background: "#f8fafc",
                    padding: "10px 12px",
                    borderRadius: "6px",
                    fontSize: "12px",
                    color: "#334155",
                    borderLeft: "3px solid #3b82f6",
                  }}
                >
                  <strong>Attribution Findings:</strong> {c.attribution} — {c.notes}
                </div>

                <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px" }}>
                  <button
                    onClick={() => copyIoc(`${c.sender} | IP: ${c.originIP}`, c.id)}
                    style={{
                      background: "transparent",
                      border: "1px solid #e2e8f0",
                      padding: "5px 10px",
                      borderRadius: "6px",
                      fontSize: "12px",
                      display: "flex",
                      alignItems: "center",
                      gap: "4px",
                      color: "#475569",
                    }}
                  >
                    {copiedId === c.id ? <Check size={12} style={{ color: "#16a34a" }} /> : <Copy size={12} />}
                    {copiedId === c.id ? "Copied" : "Copy IOCs"}
                  </button>

                  <button
                    onClick={() => setActivePage("reports")}
                    style={{
                      background: "#0d2741",
                      border: 0,
                      color: "#fff",
                      padding: "5px 12px",
                      borderRadius: "6px",
                      fontSize: "12px",
                      display: "flex",
                      alignItems: "center",
                      gap: "4px",
                    }}
                  >
                    View Report <ArrowRight size={12} />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </ModulePage>
  );
}
