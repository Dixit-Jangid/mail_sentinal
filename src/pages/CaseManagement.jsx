import { useState, useMemo, useEffect } from "react";
import {
  FolderArchive,
  Search,
  ShieldAlert,
  CheckCircle2,
  Layers,
  Copy,
  Check,
  User,
  FileText,
  Send,
  Lock,
} from "lucide-react";
import ModulePage from "../components/ModulePage";
import { clusterCampaigns } from "../services/attributionService";
import { recordCustodyEvent } from "../services/chainOfCustodyService";

const STORAGE_KEY = "aegismail_soc_cases";

const ANALYSTS = [
  { id: "sarah_chen", name: "Sarah Chen", role: "Senior Forensics Specialist", badge: "CCFE-892" },
  { id: "alex_vance", name: "Alex Vance", role: "SOC Tier 2 Lead", badge: "GCIH-441" },
  { id: "marcus_thorne", name: "Marcus Thorne", role: "Threat Intelligence Analyst", badge: "CTIA-108" },
  { id: "elena_rostova", name: "Elena Rostova", role: "Incident Commander", badge: "CISSP-902" },
];

const STATUS_OPTIONS = [
  "New",
  "Active Triage",
  "Under Investigation",
  "Quarantined",
  "Escalated",
  "Resolved",
  "False Positive",
];

const DEFAULT_CAMPAIGNS = [
  {
    id: "CASE-2026-001",
    campaign: "Campaign #FIN-WireDiversion-Global",
    subject: "URGENT: Updated Wire Instructions for Q3 Settlement",
    sender: "cfo-office@finance-corp-global.com",
    senderDomain: "finance-corp-global.com",
    category: "Fraud / Payment Diversion (BEC)",
    riskScore: 92,
    riskLevel: "High Risk",
    status: "Quarantined",
    assignedAnalyst: "Sarah Chen",
    analystRole: "Senior Forensics Specialist",
    originIP: "185.220.101.45",
    date: "2026-09-04 14:22:10",
    attribution: "Financial Fraud Syndicate (BEC)",
    sha256: "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
    evidence: {
      fileName: "invoice_q3_wire.eml",
      fileSize: 34812,
      iocs: ["185.220.101.45", "finance-corp-global.com", "https://settlement-portal.net/wire"],
    },
    notes: [
      { id: "n1", author: "Sarah Chen", time: "2026-09-04 14:35", text: "Attempted to reroute $142,000 vendor payment. Origin IP linked to bulletproof hosting." },
      { id: "n2", author: "Alex Vance", time: "2026-09-04 15:10", text: "Gateway quarantine rule deployed across tenant. Blocked 3 sibling messages." },
    ],
  },
  {
    id: "CASE-2026-002",
    campaign: "Campaign #Brand-Impersonation-Deception",
    subject: "Your PayPal Account Access Has Been Restricted Immediately",
    sender: "security@paypa1-support-verify.com",
    senderDomain: "paypa1-support-verify.com",
    category: "Impersonated / Credential Harvesting",
    riskScore: 88,
    riskLevel: "High Risk",
    status: "Active Triage",
    assignedAnalyst: "Alex Vance",
    analystRole: "SOC Tier 2 Lead",
    originIP: "194.26.29.112",
    date: "2026-09-04 11:05:41",
    attribution: "Spoofed Domain / Forged Headers",
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    evidence: {
      fileName: "paypal_security_alert.eml",
      fileSize: 28400,
      iocs: ["194.26.29.112", "paypa1-support-verify.com", "https://paypa1-verify-login.cc/auth"],
    },
    notes: [
      { id: "n1", author: "Alex Vance", time: "2026-09-04 11:15", text: "Typosquatted domain with deceptive anchor tags pointing to reverse-proxy phishing kit." },
    ],
  },
  {
    id: "CASE-2026-003",
    campaign: "Campaign #ATO-BEC-Executive",
    subject: "Quick request - Are you at your desk right now?",
    sender: "executive-ceo@company-holdings.org",
    senderDomain: "company-holdings.org",
    category: "Executive Impersonation (VIP Fraud)",
    riskScore: 78,
    riskLevel: "High Risk",
    status: "Under Investigation",
    assignedAnalyst: "Marcus Thorne",
    analystRole: "Threat Intelligence Analyst",
    originIP: "103.251.167.22",
    date: "2026-09-03 16:45:00",
    attribution: "Compromised Legitimate Account (ATO)",
    sha256: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    evidence: {
      fileName: "urgent_favor_ceo.eml",
      fileSize: 18220,
      iocs: ["103.251.167.22", "company-holdings.org", "ceo.personal.inbox@gmail.com"],
    },
    notes: [
      { id: "n1", author: "Marcus Thorne", time: "2026-09-03 17:00", text: "SPF/DKIM passed, but Reply-To diverted to personal webmail. Suspected compromised M365 session." },
    ],
  },
  {
    id: "CASE-2026-004",
    campaign: "Campaign #O365-CredentialHarvest",
    subject: "Action Required: 3 Incoming Messages Pending Release",
    sender: "postmaster@mail-filter-notification.net",
    senderDomain: "mail-filter-notification.net",
    category: "Phishing / Credential Harvesting",
    riskScore: 68,
    riskLevel: "Medium Risk",
    status: "Resolved",
    assignedAnalyst: "Elena Rostova",
    analystRole: "Incident Commander",
    originIP: "45.142.122.90",
    date: "2026-09-02 09:12:30",
    attribution: "Phishing-as-a-Service (PhaaS) Kit Infrastructure",
    sha256: "d5c8e231b1c31da1f1e948ff5b1742490df1b312ef57b8a7b3c2e1f482d91834",
    evidence: {
      fileName: "quarantine_release_notice.eml",
      fileSize: 22100,
      iocs: ["45.142.122.90", "mail-filter-notification.net"],
    },
    notes: [
      { id: "n1", author: "Elena Rostova", time: "2026-09-02 09:40", text: "Phishing kit hosted on shared cloud instance. Blocked at perimeter firewall and resolved." },
    ],
  },
];

export default function CaseManagement({ analysis }) {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedStatus, setSelectedStatus] = useState("All");
  const [selectedCategory, setSelectedCategory] = useState("All");
  const [activeTab, setActiveTab] = useState("cases"); // 'cases' | 'campaigns'
  const [newNoteText, setNewNoteText] = useState("");
  const [copiedId, setCopiedId] = useState(null);

  const getActiveCase = () => {
    let storedCases = [];
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) storedCases = JSON.parse(raw);
    } catch (error) {
      console.warn("Unable to restore saved case data:", error);
    }

    const baseList = storedCases.length > 0 ? storedCases : DEFAULT_CAMPAIGNS;

    if (!analysis) {
      return baseList[0] || null;
    }

    const activeCaseId = `CASE-${analysis.id.substring(5, 13).toUpperCase()}`;
    const existingIdx = baseList.findIndex((c) => c.id === activeCaseId || c.sha256 === analysis.sha256);

    const activeCaseObj = {
      id: activeCaseId,
      campaign: analysis.attribution?.campaignTag || "Campaign #Active-Investigation",
      subject: analysis.subject,
      sender: analysis.from,
      senderDomain: analysis.senderDomain,
      category: analysis.primaryClassification,
      riskScore: analysis.riskScore,
      riskLevel: analysis.riskLevel,
      status: analysis.riskScore >= 70 ? "Quarantined" : "Active Triage",
      assignedAnalyst: ANALYSTS[0].name,
      analystRole: ANALYSTS[0].role,
      originIP: analysis.earliestNodeIP || "198.51.100.14",
      date: analysis.analyzedAt,
      attribution: analysis.attribution?.infrastructureType || "Analyzed Sender Node",
      sha256: analysis.sha256,
      evidence: {
        fileName: analysis.fileName,
        fileSize: analysis.fileSize,
        iocs: [
          analysis.earliestNodeIP,
          analysis.senderDomain,
          ...(analysis.suspiciousLinksList || []),
        ].filter(Boolean),
      },
      notes: [
        {
          id: `n-${Date.now()}`,
          author: ANALYSTS[0].name,
          time: new Date().toLocaleString(),
          text: `Forensic docket opened. Multi-factor score: ${analysis.riskScore}/100. Verdict: ${analysis.riskLevel}.`,
        },
      ],
    };

    if (existingIdx >= 0) {
      return { ...baseList[existingIdx], ...activeCaseObj, notes: baseList[existingIdx].notes || activeCaseObj.notes };
    }

    return activeCaseObj;
  };

  // Initialize cases with localStorage persistence
  const [cases, setCases] = useState(() => {
    let storedCases = [];
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) storedCases = JSON.parse(raw);
    } catch (error) {
      console.warn("Unable to restore saved case data:", error);
    }

    const baseList = storedCases.length > 0 ? storedCases : DEFAULT_CAMPAIGNS;

    if (analysis) {
      const activeCaseId = `CASE-${analysis.id.substring(5, 13).toUpperCase()}`;
      const existingIdx = baseList.findIndex((c) => c.id === activeCaseId || c.sha256 === analysis.sha256);

      const activeCaseObj = {
        id: activeCaseId,
        campaign: analysis.attribution?.campaignTag || "Campaign #Active-Investigation",
        subject: analysis.subject,
        sender: analysis.from,
        senderDomain: analysis.senderDomain,
        category: analysis.primaryClassification,
        riskScore: analysis.riskScore,
        riskLevel: analysis.riskLevel,
        status: analysis.riskScore >= 70 ? "Quarantined" : "Active Triage",
        assignedAnalyst: ANALYSTS[0].name,
        analystRole: ANALYSTS[0].role,
        originIP: analysis.earliestNodeIP || "198.51.100.14",
        date: analysis.analyzedAt,
        attribution: analysis.attribution?.infrastructureType || "Analyzed Sender Node",
        sha256: analysis.sha256,
        evidence: {
          fileName: analysis.fileName,
          fileSize: analysis.fileSize,
          iocs: [
            analysis.earliestNodeIP,
            analysis.senderDomain,
            ...(analysis.suspiciousLinksList || []),
          ].filter(Boolean),
        },
        notes: [
          {
            id: `n-${Date.now()}`,
            author: ANALYSTS[0].name,
            time: new Date().toLocaleString(),
            text: `Forensic docket opened. Multi-factor score: ${analysis.riskScore}/100. Verdict: ${analysis.riskLevel}.`,
          },
        ],
      };

      if (existingIdx >= 0) {
        baseList[existingIdx] = { ...baseList[existingIdx], ...activeCaseObj, notes: baseList[existingIdx].notes || activeCaseObj.notes };
        return baseList;
      }
      return [activeCaseObj, ...baseList];
    }

    return baseList;
  });

  const [selectedCase, setSelectedCase] = useState(() => getActiveCase());

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(cases));
    } catch (error) {
      console.warn("Unable to persist cases to localStorage:", error);
    }
  }, [cases]);

  const copyIoc = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const updateCaseStatus = (caseId, newStatus) => {
    setCases((prev) =>
      prev.map((c) => (c.id === caseId ? { ...c, status: newStatus } : c))
    );
    if (selectedCase?.id === caseId) {
      setSelectedCase((prev) => ({ ...prev, status: newStatus }));
    }
    recordCustodyEvent(caseId, {
      action: "STATUS_UPDATE",
      details: `Investigation status changed to ${newStatus}.`,
      investigator: { name: selectedCase?.assignedAnalyst || "SOC Analyst" },
    });
  };

  const updateAssignedAnalyst = (caseId, analystName) => {
    const analystObj = ANALYSTS.find((a) => a.name === analystName) || { name: analystName, role: "Analyst" };
    setCases((prev) =>
      prev.map((c) =>
        c.id === caseId
          ? { ...c, assignedAnalyst: analystObj.name, analystRole: analystObj.role }
          : c
      )
    );
    if (selectedCase?.id === caseId) {
      setSelectedCase((prev) => ({ ...prev, assignedAnalyst: analystObj.name, analystRole: analystObj.role }));
    }
    recordCustodyEvent(caseId, {
      action: "REASSIGN_ANALYST",
      details: `Case assigned to ${analystObj.name} (${analystObj.role}).`,
    });
  };

  const addNoteToCase = (e) => {
    if (e) e.preventDefault();
    if (!newNoteText.trim() || !selectedCase) return;

    const newNote = {
      id: `n-${Date.now()}`,
      author: selectedCase.assignedAnalyst || "Forensics Examiner",
      time: new Date().toLocaleString(),
      text: newNoteText.trim(),
    };

    const updatedNotes = [...(selectedCase.notes || []), newNote];

    setCases((prev) =>
      prev.map((c) => (c.id === selectedCase.id ? { ...c, notes: updatedNotes } : c))
    );

    setSelectedCase((prev) => ({ ...prev, notes: updatedNotes }));
    setNewNoteText("");

    recordCustodyEvent(selectedCase.id, {
      action: "ADD_FORENSIC_NOTE",
      details: `Analyst Note: ${newNote.text.substring(0, 80)}...`,
      investigator: { name: selectedCase.assignedAnalyst },
    });
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

  const campaignClusters = useMemo(() => {
    return clusterCampaigns(cases);
  }, [cases]);

  // Find related emails sharing domain, IP, or campaign
  const relatedEmails = useMemo(() => {
    if (!selectedCase) return [];
    return cases.filter(
      (c) =>
        c.id !== selectedCase.id &&
        (c.senderDomain === selectedCase.senderDomain ||
          c.originIP === selectedCase.originIP ||
          c.campaign === selectedCase.campaign)
    );
  }, [selectedCase, cases]);

  return (
    <ModulePage
      title="Case Management & Campaign Explorer"
      subtitle="Complete incident triage docket: Case ID tracking, analyst assignment, evidence locker, notes, and campaign clustering."
      icon={<FolderArchive size={28} />}
    >
      {/* TABS HEADER */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px", flexWrap: "wrap", gap: "12px" }}>
        <div style={{ display: "flex", gap: "8px" }}>
          <button
            onClick={() => setActiveTab("cases")}
            className={activeTab === "cases" ? "primary-button" : "secondary-button"}
            style={{ fontSize: "13px", padding: "8px 16px" }}
          >
            <FolderArchive size={15} /> Incident Cases ({cases.length})
          </button>

          <button
            onClick={() => setActiveTab("campaigns")}
            className={activeTab === "campaigns" ? "primary-button" : "secondary-button"}
            style={{ fontSize: "13px", padding: "8px 16px" }}
          >
            <Layers size={15} /> Campaign Clusters ({campaignClusters.length})
          </button>
        </div>

        <div style={{ display: "flex", gap: "8px" }}>
          {analysis && (
            <button
              className="secondary-button"
              onClick={() => {
                const currentCase = cases.find((c) => c.sha256 === analysis.sha256);
                if (currentCase) setSelectedCase(currentCase);
              }}
              style={{ fontSize: "12px", padding: "7px 12px", background: "#f0fdf4", color: "#16a34a", borderColor: "#86efac" }}
            >
              <CheckCircle2 size={14} /> Active Scan Linked
            </button>
          )}
        </div>
      </div>

      {activeTab === "cases" ? (
        <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1.6fr", gap: "20px", alignItems: "start" }}>
          {/* LEFT: CASE LIST & FILTERS */}
          <div>
            {/* SEARCH & FILTERS BAR */}
            <div className="panel" style={{ marginBottom: "16px", padding: "16px" }}>
              <div style={{ position: "relative", marginBottom: "12px" }}>
                <Search size={16} style={{ position: "absolute", left: "12px", top: "11px", color: "#94a3b8" }} />
                <input
                  type="text"
                  placeholder="Search Case ID, subject, sender, or campaign..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{ width: "100%", paddingLeft: "36px", height: "38px" }}
                />
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                <div>
                  <label style={{ fontSize: "11px", color: "#64748b", fontWeight: "700", textTransform: "uppercase" }}>
                    Status Filter
                  </label>
                  <select
                    value={selectedStatus}
                    onChange={(e) => setSelectedStatus(e.target.value)}
                    style={{ width: "100%", marginTop: "4px", padding: "6px" }}
                  >
                    <option value="All">All Statuses</option>
                    {STATUS_OPTIONS.map((st) => (
                      <option key={st} value={st}>{st}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: "11px", color: "#64748b", fontWeight: "700", textTransform: "uppercase" }}>
                    Category Filter
                  </label>
                  <select
                    value={selectedCategory}
                    onChange={(e) => setSelectedCategory(e.target.value)}
                    style={{ width: "100%", marginTop: "4px", padding: "6px" }}
                  >
                    <option value="All">All Categories</option>
                    <option value="Payment Diversion">Payment Diversion (BEC)</option>
                    <option value="Credential">Credential Harvesting</option>
                    <option value="Executive">Executive Impersonation</option>
                    <option value="Invoice">Fake Invoice</option>
                  </select>
                </div>
              </div>
            </div>

            {/* CASES LIST */}
            <div style={{ display: "grid", gap: "12px" }}>
              {filteredCases.length === 0 ? (
                <div className="panel" style={{ textAlign: "center", padding: "30px 20px" }}>
                  <FolderArchive size={36} style={{ color: "#94a3b8", margin: "0 auto 8px" }} />
                  <h4>No matching cases found</h4>
                  <p style={{ fontSize: "12px", color: "#64748b" }}>Adjust your search terms or filters.</p>
                </div>
              ) : (
                filteredCases.map((item) => {
                  const isSelected = selectedCase?.id === item.id;
                  const isHighRisk = item.riskScore >= 70;

                  return (
                    <div
                      key={item.id}
                      onClick={() => setSelectedCase(item)}
                      className="panel"
                      style={{
                        padding: "16px",
                        cursor: "pointer",
                        border: isSelected ? "2px solid #2563eb" : "1px solid #e2e8f0",
                        background: isSelected ? "#f8fafc" : "#ffffff",
                        transition: "all 0.15s ease",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "6px" }}>
                        <div>
                          <span style={{ fontSize: "12px", fontWeight: "800", fontFamily: "monospace", color: "#2563eb" }}>
                            {item.id}
                          </span>
                          <span style={{ marginLeft: "8px", fontSize: "11px", color: "#64748b" }}>
                            {item.date}
                          </span>
                        </div>

                        <span
                          style={{
                            fontSize: "11px",
                            fontWeight: "700",
                            padding: "3px 8px",
                            borderRadius: "4px",
                            background:
                              item.status === "Quarantined"
                                ? "#fee2e2"
                                : item.status === "Resolved"
                                ? "#dcfce7"
                                : "#fef3c7",
                            color:
                              item.status === "Quarantined"
                                ? "#dc2626"
                                : item.status === "Resolved"
                                ? "#16a34a"
                                : "#b45309",
                          }}
                        >
                          {item.status}
                        </span>
                      </div>

                      <strong style={{ display: "block", fontSize: "14px", color: "#0f172a", marginBottom: "4px" }}>
                        {item.subject}
                      </strong>

                      <div style={{ fontSize: "12px", color: "#475569", marginBottom: "8px" }}>
                        From: {item.sender}
                      </div>

                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "8px", fontSize: "11px", color: "#64748b" }}>
                        <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                          <User size={12} /> {item.assignedAnalyst || "Unassigned"}
                        </span>

                        <span style={{ fontWeight: "700", color: isHighRisk ? "#dc2626" : "#2563eb" }}>
                          {item.riskScore}/100 ({item.riskLevel})
                        </span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* RIGHT: SELECTED CASE DETAIL DOCKET */}
          {selectedCase ? (
            <div className="panel" style={{ padding: "24px", position: "sticky", top: "20px" }}>
              {/* DOCKET HEADER */}
              <div style={{ borderBottom: "2px solid #e2e8f0", paddingBottom: "16px", marginBottom: "20px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "8px" }}>
                  <div>
                    <span style={{ fontSize: "11px", fontWeight: "800", color: "#64748b", letterSpacing: "0.08em" }}>
                      INCIDENT CASE DOCKET
                    </span>
                    <h2 style={{ fontSize: "20px", color: "#0f172a", margin: "2px 0 0" }}>
                      {selectedCase.id}
                    </h2>
                  </div>

                  <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                    <span
                      style={{
                        padding: "4px 10px",
                        borderRadius: "6px",
                        fontWeight: "800",
                        fontSize: "12px",
                        background: selectedCase.riskScore >= 70 ? "#fee2e2" : "#fef3c7",
                        color: selectedCase.riskScore >= 70 ? "#dc2626" : "#d97706",
                      }}
                    >
                      {selectedCase.riskScore}/100 · {selectedCase.riskLevel}
                    </span>
                  </div>
                </div>

                <div style={{ marginTop: "12px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                  {/* ASSIGNED ANALYST */}
                  <div>
                    <label style={{ fontSize: "11px", color: "#64748b", fontWeight: "700", textTransform: "uppercase" }}>
                      Assigned Analyst
                    </label>
                    <select
                      value={selectedCase.assignedAnalyst || ANALYSTS[0].name}
                      onChange={(e) => updateAssignedAnalyst(selectedCase.id, e.target.value)}
                      style={{ width: "100%", marginTop: "4px", padding: "6px", fontSize: "12px" }}
                    >
                      {ANALYSTS.map((a) => (
                        <option key={a.id} value={a.name}>
                          {a.name} ({a.role})
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* INVESTIGATION STATUS */}
                  <div>
                    <label style={{ fontSize: "11px", color: "#64748b", fontWeight: "700", textTransform: "uppercase" }}>
                      Investigation Status
                    </label>
                    <select
                      value={selectedCase.status}
                      onChange={(e) => updateCaseStatus(selectedCase.id, e.target.value)}
                      style={{ width: "100%", marginTop: "4px", padding: "6px", fontSize: "12px", fontWeight: "600" }}
                    >
                      {STATUS_OPTIONS.map((st) => (
                        <option key={st} value={st}>{st}</option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>

              {/* EVIDENCE LOCKER SECTION */}
              <div style={{ marginBottom: "20px" }}>
                <h4 style={{ fontSize: "13px", color: "#0f172a", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
                  <Lock size={14} style={{ color: "#2563eb" }} /> Evidence Locker & Cryptographic Integrity
                </h4>

                <div style={{ background: "#f8fafc", padding: "12px", borderRadius: "8px", fontSize: "12px" }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginBottom: "8px" }}>
                    <div>
                      <span style={{ color: "#64748b" }}>Subject:</span>
                      <strong style={{ display: "block", color: "#1e293b" }}>{selectedCase.subject}</strong>
                    </div>
                    <div>
                      <span style={{ color: "#64748b" }}>Sender (From):</span>
                      <strong style={{ display: "block", color: "#1e293b" }}>{selectedCase.sender}</strong>
                    </div>
                    <div>
                      <span style={{ color: "#64748b" }}>Origin IP:</span>
                      <strong style={{ display: "block", fontFamily: "monospace" }}>{selectedCase.originIP}</strong>
                    </div>
                    <div>
                      <span style={{ color: "#64748b" }}>Campaign Tag:</span>
                      <strong style={{ display: "block", color: "#7c3aed" }}>{selectedCase.campaign}</strong>
                    </div>
                  </div>

                  {selectedCase.sha256 && (
                    <div style={{ borderTop: "1px solid #e2e8f0", paddingTop: "8px", marginTop: "8px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ color: "#64748b" }}>SHA-256 Digest:</span>
                        <button
                          onClick={() => copyIoc(selectedCase.sha256, `hash-${selectedCase.id}`)}
                          style={{ background: "transparent", border: 0, color: copiedId === `hash-${selectedCase.id}` ? "#16a34a" : "#2563eb", cursor: "pointer", fontSize: "11px", display: "flex", alignItems: "center", gap: "2px" }}
                        >
                          {copiedId === `hash-${selectedCase.id}` ? <Check size={11} /> : <Copy size={11} />} Copy
                        </button>
                      </div>
                      <code style={{ fontSize: "11px", color: "#0369a1", wordBreak: "break-all", fontFamily: "monospace" }}>
                        {selectedCase.sha256}
                      </code>
                    </div>
                  )}

                  {/* EXTRACTED IOCS LIST */}
                  {selectedCase.evidence?.iocs?.length > 0 && (
                    <div style={{ marginTop: "10px", borderTop: "1px solid #e2e8f0", paddingTop: "8px" }}>
                      <span style={{ color: "#64748b", display: "block", marginBottom: "4px" }}>Quarantined IoCs:</span>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                        {selectedCase.evidence.iocs.map((ioc, idx) => (
                          <span
                            key={idx}
                            onClick={() => copyIoc(ioc, `ioc-${idx}`)}
                            title="Click to copy IOC"
                            style={{
                              background: "#fee2e2",
                              color: "#991b1b",
                              padding: "2px 8px",
                              borderRadius: "4px",
                              fontSize: "11px",
                              fontFamily: "monospace",
                              cursor: "pointer",
                            }}
                          >
                            {ioc} {copiedId === `ioc-${idx}` ? "✓" : ""}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* INTERACTIVE NOTES LOG */}
              <div style={{ marginBottom: "20px" }}>
                <h4 style={{ fontSize: "13px", color: "#0f172a", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
                  <FileText size={14} style={{ color: "#2563eb" }} /> Forensic Notes & Activity Trail
                </h4>

                <div style={{ maxHeight: "180px", overflowY: "auto", display: "grid", gap: "8px", marginBottom: "10px" }}>
                  {(selectedCase.notes || []).map((n) => (
                    <div key={n.id} style={{ background: "#f8fafc", padding: "10px 12px", borderRadius: "6px", border: "1px solid #e2e8f0", fontSize: "12px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", color: "#64748b", marginBottom: "3px" }}>
                        <strong style={{ color: "#1e293b" }}>{n.author}</strong>
                        <span>{n.time}</span>
                      </div>
                      <p style={{ margin: 0, color: "#334155" }}>{n.text}</p>
                    </div>
                  ))}
                </div>

                {/* ADD NOTE INPUT */}
                <form onSubmit={addNoteToCase} style={{ display: "flex", gap: "6px" }}>
                  <input
                    type="text"
                    placeholder="Add forensic investigation note..."
                    value={newNoteText}
                    onChange={(e) => setNewNoteText(e.target.value)}
                    style={{ flex: 1, padding: "8px 12px", fontSize: "12px" }}
                  />
                  <button type="submit" className="primary-button" style={{ padding: "8px 14px", fontSize: "12px" }}>
                    <Send size={13} /> Add
                  </button>
                </form>
              </div>

              {/* RELATED EMAILS & CORRELATION */}
              {relatedEmails.length > 0 && (
                <div style={{ borderTop: "1px solid #e2e8f0", paddingTop: "14px" }}>
                  <h4 style={{ fontSize: "12px", color: "#64748b", textTransform: "uppercase", marginBottom: "8px" }}>
                    Correlated Cases ({relatedEmails.length} Related)
                  </h4>
                  <div style={{ display: "grid", gap: "6px" }}>
                    {relatedEmails.slice(0, 3).map((rc) => (
                      <div
                        key={rc.id}
                        onClick={() => setSelectedCase(rc)}
                        style={{
                          background: "#f1f5f9",
                          padding: "8px 12px",
                          borderRadius: "6px",
                          cursor: "pointer",
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          fontSize: "12px",
                        }}
                      >
                        <span style={{ fontWeight: "600", color: "#2563eb" }}>{rc.id}: {rc.subject.substring(0, 32)}...</span>
                        <span style={{ color: "#64748b" }}>{rc.status}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="panel" style={{ textAlign: "center", padding: "40px" }}>
              <FolderArchive size={42} style={{ color: "#94a3b8", margin: "0 auto 12px" }} />
              <h3>Select a case to inspect docket</h3>
            </div>
          )}
        </div>
      ) : (
        /* CAMPAIGN CLUSTERING VIEW */
        <div style={{ display: "grid", gap: "16px" }}>
          {campaignClusters.map((camp) => (
            <div key={camp.campaignId} className="panel" style={{ padding: "20px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "10px", marginBottom: "12px" }}>
                <div>
                  <span style={{ fontSize: "11px", fontWeight: "800", color: "#7c3aed" }}>
                    {camp.campaignId}
                  </span>
                  <h3 style={{ fontSize: "18px", color: "#0f172a", margin: "2px 0 0" }}>
                    {camp.name}
                  </h3>
                  <span style={{ fontSize: "12px", color: "#64748b" }}>
                    First Detected: {camp.firstSeen} · Latest Activity: {camp.lastSeen}
                  </span>
                </div>

                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  <span
                    style={{
                      padding: "4px 10px",
                      borderRadius: "6px",
                      fontWeight: "800",
                      fontSize: "12px",
                      background: camp.averageRiskScore >= 70 ? "#fee2e2" : "#fef3c7",
                      color: camp.averageRiskScore >= 70 ? "#dc2626" : "#b45309",
                    }}
                  >
                    Avg Score: {camp.averageRiskScore}/100 ({camp.riskLevel})
                  </span>

                  <button
                    className="secondary-button"
                    onClick={() => {
                      camp.cases.forEach((c) => updateCaseStatus(c.id, "Quarantined"));
                    }}
                    style={{ fontSize: "12px", padding: "6px 12px", color: "#dc2626", borderColor: "#fca5a5" }}
                  >
                    <ShieldAlert size={14} /> Quarantine Campaign
                  </button>
                </div>
              </div>

              {/* SHARED INFRASTRUCTURE PILLS */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", background: "#f8fafc", padding: "12px", borderRadius: "8px", fontSize: "12px", marginBottom: "16px" }}>
                <div>
                  <span style={{ color: "#64748b", fontWeight: "600" }}>Associated Domains:</span>
                  <div style={{ marginTop: "4px", display: "flex", flexWrap: "wrap", gap: "6px" }}>
                    {camp.associatedDomains.map((d, i) => (
                      <span key={i} style={{ background: "#ede9fe", color: "#6d28d9", padding: "2px 8px", borderRadius: "4px" }}>
                        {d}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <span style={{ color: "#64748b", fontWeight: "600" }}>Correlated Origin IPs:</span>
                  <div style={{ marginTop: "4px", display: "flex", flexWrap: "wrap", gap: "6px" }}>
                    {camp.associatedIPs.map((ip, i) => (
                      <span key={i} style={{ background: "#fef3c7", color: "#b45309", padding: "2px 8px", borderRadius: "4px", fontFamily: "monospace" }}>
                        {ip}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* LINKED CASES TABLE */}
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
                <thead>
                  <tr style={{ borderBottom: "2px solid #e2e8f0", textAlign: "left", color: "#64748b" }}>
                    <th style={{ padding: "8px" }}>Case ID</th>
                    <th style={{ padding: "8px" }}>Subject</th>
                    <th style={{ padding: "8px" }}>Sender</th>
                    <th style={{ padding: "8px" }}>Status</th>
                    <th style={{ padding: "8px" }}>Analyst</th>
                    <th style={{ padding: "8px" }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {camp.cases.map((cs) => (
                    <tr key={cs.id} style={{ borderBottom: "1px solid #f1f5f9" }}>
                      <td style={{ padding: "8px", fontFamily: "monospace", fontWeight: "700", color: "#2563eb" }}>{cs.id}</td>
                      <td style={{ padding: "8px", fontWeight: "500" }}>{cs.subject}</td>
                      <td style={{ padding: "8px", color: "#64748b" }}>{cs.sender}</td>
                      <td style={{ padding: "8px" }}>
                        <span style={{ padding: "2px 8px", borderRadius: "4px", fontSize: "11px", fontWeight: "600", background: cs.status === "Quarantined" ? "#fee2e2" : "#f1f5f9", color: cs.status === "Quarantined" ? "#dc2626" : "#475569" }}>
                          {cs.status}
                        </span>
                      </td>
                      <td style={{ padding: "8px", color: "#475569" }}>{cs.assignedAnalyst || "Unassigned"}</td>
                      <td style={{ padding: "8px" }}>
                        <button
                          onClick={() => {
                            setSelectedCase(cs);
                            setActiveTab("cases");
                          }}
                          style={{ background: "transparent", border: 0, color: "#2563eb", cursor: "pointer", fontWeight: "600", fontSize: "12px" }}
                        >
                          View Docket →
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      )}
    </ModulePage>
  );
}
