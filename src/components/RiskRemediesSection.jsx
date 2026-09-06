import { useState, useMemo } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Check,
  Terminal,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  FileCode,
  Mail,
  Zap,
  RotateCcw,
  Server,
  Lock,
} from "lucide-react";
import {
  extractRiskFactorsAndRemedies,
  getBaselineRiskCatalog,
  generateRemediationMarkdown,
} from "../services/remediationService";

export default function RiskRemediesSection({
  analysis,
  setActivePage,
}) {
  const [activeFilter, setActiveFilter] = useState("all");
  const [completedRemedyIds, setCompletedRemedyIds] = useState(new Set());
  const [expandedCards, setExpandedCards] = useState(new Set(["rf-dmarc-fail", "rf-bec-financial", "rf-display-spoof", "cat-bec-wire"]));
  const [copiedCmdId, setCopiedCmdId] = useState(null);
  const [copiedReport, setCopiedReport] = useState(false);
  const [showPurgeModal, setShowPurgeModal] = useState(false);

  const hasAnalysis = Boolean(analysis);

  // Extract real risk factors if analysis exists, otherwise show baseline catalog
  const riskFactors = useMemo(() => {
    if (analysis) {
      return extractRiskFactorsAndRemedies(analysis);
    }
    return getBaselineRiskCatalog();
  }, [analysis]);

  // Total remedies across all risk factors
  const allRemedies = useMemo(() => {
    return riskFactors.flatMap((rf) => rf.remedies);
  }, [riskFactors]);

  const completedCount = useMemo(() => {
    return allRemedies.filter((rem) => completedRemedyIds.has(rem.id)).length;
  }, [allRemedies, completedRemedyIds]);

  const totalCount = allRemedies.length;
  const progressPercent = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0;

  // Filtered risk factors
  const filteredRiskFactors = useMemo(() => {
    if (activeFilter === "all") return riskFactors;
    if (activeFilter === "critical_high") {
      return riskFactors.filter((rf) => rf.severity === "CRITICAL" || rf.severity === "HIGH");
    }
    if (activeFilter === "auth") {
      return riskFactors.filter((rf) => rf.category === "Authentication & Spoofing");
    }
    if (activeFilter === "bec") {
      return riskFactors.filter((rf) => rf.category === "BEC & Social Engineering");
    }
    if (activeFilter === "payloads") {
      return riskFactors.filter((rf) => rf.category === "Malicious Links & Attachments" || rf.category === "Network & Routing");
    }
    return riskFactors;
  }, [riskFactors, activeFilter]);

  // Toggle remedy completion
  const toggleRemedy = (id) => {
    setCompletedRemedyIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  // Toggle card expansion
  const toggleCard = (id) => {
    setExpandedCards((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  // Copy command helper
  const copyCommand = (id, command) => {
    if (!command) return;
    navigator.clipboard.writeText(command);
    setCopiedCmdId(id);
    setTimeout(() => setCopiedCmdId(null), 2000);
  };

  // Copy full report
  const copyReport = () => {
    const md = generateRemediationMarkdown(analysis, riskFactors, completedRemedyIds);
    navigator.clipboard.writeText(md);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2200);
  };

  // Reset checklist
  const resetChecklist = () => {
    setCompletedRemedyIds(new Set());
  };

  const getSeverityBadgeClass = (severity) => {
    switch (severity) {
      case "CRITICAL":
        return "remedy-badge-critical";
      case "HIGH":
        return "remedy-badge-high";
      case "MEDIUM":
        return "remedy-badge-medium";
      default:
        return "remedy-badge-low";
    }
  };

  return (
    <section className="risk-remedies-container">
      {/* SECTION HEADER */}
      <div className="remedies-header-banner">
        <div className="remedies-title-group">
          <div className="remedies-icon-box">
            <ShieldAlert size={22} />
          </div>
          <div>
            <div className="remedies-kicker">
              <span>DFIR Remediation Engine</span>
              <span className="bullet-sep">•</span>
              <span>ISO/IEC 27037 Preserved</span>
              {hasAnalysis && (
                <span className="live-pill">Live Incident Decomposition</span>
              )}
            </div>
            <h3 className="remedies-main-title">
              Threat Risk Factors & Resolution Remedies
            </h3>
            <p className="remedies-subtext">
              Automated root-cause threat decomposition paired with actionable SOC containment procedures,
              DNS hardening records, and tenant purge commands.
            </p>
          </div>
        </div>

        {/* TOP CONTROLS & EXPORT */}
        <div className="remedies-top-actions">
          <button
            className={`remedies-btn remedies-btn-export ${copiedReport ? "copied" : ""}`}
            onClick={copyReport}
            title="Copy full incident containment plan formatted for Jira, ServiceNow or SIEM"
          >
            {copiedReport ? <Check size={15} /> : <Copy size={15} />}
            {copiedReport ? "Plan Copied to Clipboard!" : "Copy Incident Plan (Markdown)"}
          </button>

          {hasAnalysis && (
            <button
              className="remedies-btn remedies-btn-script"
              onClick={() => setShowPurgeModal(true)}
              title="View M365 PowerShell tenant purge script"
            >
              <Terminal size={15} />
              Tenant Purge Script
            </button>
          )}
        </div>
      </div>

      {/* ZERO-STATE GUIDANCE NOTICE (when no email is analyzed yet) */}
      {!hasAnalysis && (
        <div className="remedies-preview-notice">
          <div className="notice-left">
            <Zap size={18} className="zap-icon" />
            <div>
              <strong>Threat Risk Catalog Mode</strong>
              <p>
                Showing standard corporate email threat vectors and mitigation playbooks.
                Upload an <code>.eml</code> file above to diagnose an email in real time.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* METRIC TRACKER & FILTERS */}
      <div className="remedies-control-toolbar">
        {/* PROGRESS METER */}
        <div className="remedies-progress-meter">
          <div className="meter-label-row">
            <span className="meter-title">Containment Progress:</span>
            <span className="meter-count">
              <strong>{completedCount}</strong> of <strong>{totalCount}</strong> actions executed
              <span className={`progress-badge ${progressPercent === 100 ? "complete" : progressPercent > 0 ? "in-progress" : "zero"}`}>
                {progressPercent}% {progressPercent === 100 ? "Resolved" : progressPercent > 0 ? "Mitigating" : "Unresolved"}
              </span>
            </span>
            {completedCount > 0 && (
              <button
                className="meter-reset-btn"
                onClick={resetChecklist}
                title="Reset completion checkboxes"
              >
                <RotateCcw size={12} />
                Reset
              </button>
            )}
          </div>
          <div className="meter-track">
            <div
              className={`meter-fill ${progressPercent === 100 ? "fill-success" : ""}`}
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>

        {/* FILTER CHIPS */}
        <div className="remedies-filter-chips">
          <button
            className={`filter-chip ${activeFilter === "all" ? "active" : ""}`}
            onClick={() => setActiveFilter("all")}
          >
            All Risk Factors ({riskFactors.length})
          </button>
          <button
            className={`filter-chip ${activeFilter === "critical_high" ? "active" : ""}`}
            onClick={() => setActiveFilter("critical_high")}
          >
            Critical & High Only ({riskFactors.filter(r => r.severity === "CRITICAL" || r.severity === "HIGH").length})
          </button>
          <button
            className={`filter-chip ${activeFilter === "auth" ? "active" : ""}`}
            onClick={() => setActiveFilter("auth")}
          >
            <Lock size={12} />
            Auth & Spoofing
          </button>
          <button
            className={`filter-chip ${activeFilter === "bec" ? "active" : ""}`}
            onClick={() => setActiveFilter("bec")}
          >
            <Mail size={12} />
            BEC & Social Eng
          </button>
          <button
            className={`filter-chip ${activeFilter === "payloads" ? "active" : ""}`}
            onClick={() => setActiveFilter("payloads")}
          >
            <FileCode size={12} />
            Links & Payloads
          </button>
        </div>
      </div>

      {/* RISK FACTORS CARDS GRID / ACCORDION */}
      <div className="remedies-cards-grid">
        {filteredRiskFactors.map((rf, idx) => {
          const isExpanded = expandedCards.has(rf.id);
          const rfCompleted = rf.remedies.filter(r => completedRemedyIds.has(r.id)).length;
          const rfTotal = rf.remedies.length;
          const isFullyResolved = rfTotal > 0 && rfCompleted === rfTotal;

          return (
            <div
              key={rf.id}
              className={`remedy-card ${isFullyResolved ? "remedy-card-resolved" : ""} ${rf.severity.toLowerCase()}`}
            >
              {/* CARD HEADER */}
              <div
                className="remedy-card-header"
                onClick={() => toggleCard(rf.id)}
              >
                <div className="remedy-card-title-group">
                  <div className="remedy-badge-row">
                    <span className={`remedy-severity-badge ${getSeverityBadgeClass(rf.severity)}`}>
                      {rf.severity}
                    </span>
                    <span className="remedy-impact-badge">
                      Impact: {rf.scoreImpact}
                    </span>
                    <span className="remedy-category-tag">
                      {rf.category}
                    </span>
                    {isFullyResolved && (
                      <span className="remedy-resolved-tag">
                        <CheckCircle2 size={12} />
                        Mitigated
                      </span>
                    )}
                  </div>
                  <h4 className="remedy-factor-title">
                    {idx + 1}. {rf.title}
                  </h4>
                  <p className="remedy-factor-vector">
                    {rf.threatVector}
                  </p>
                </div>

                <div className="remedy-card-toggle">
                  <span className="remedy-actions-counter">
                    {rfCompleted}/{rfTotal} Actions Done
                  </span>
                  <button
                    className="icon-toggle-btn"
                    aria-label="Toggle details"
                  >
                    {isExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                  </button>
                </div>
              </div>

              {/* CARD BODY (EXPANDABLE) */}
              {isExpanded && (
                <div className="remedy-card-body">
                  {/* FORENSIC EVIDENCE BOX */}
                  <div className="forensic-evidence-box">
                    <div className="evidence-header">
                      <AlertTriangle size={13} />
                      <span>Observed Email Forensic Evidence:</span>
                    </div>
                    <code className="evidence-code">{rf.evidence}</code>
                  </div>

                  {/* REMEDIES ACTION LIST */}
                  <div className="remedies-list-container">
                    <h5 className="remedies-list-heading">
                      <ShieldCheck size={14} />
                      Targeted Resolution Remedies:
                    </h5>

                    <div className="remedy-items-list">
                      {rf.remedies.map((rem) => {
                        const isDone = completedRemedyIds.has(rem.id);
                        const isCmdCopied = copiedCmdId === rem.id;

                        return (
                          <div
                            key={rem.id}
                            className={`remedy-action-item ${isDone ? "item-completed" : ""}`}
                          >
                            <div className="remedy-item-top">
                              <label className="remedy-checkbox-label">
                                <input
                                  type="checkbox"
                                  checked={isDone}
                                  onChange={() => toggleRemedy(rem.id)}
                                />
                                <span className={`remedy-item-title ${isDone ? "strike" : ""}`}>
                                  {rem.title}
                                </span>
                              </label>

                              <div className="remedy-meta-tags">
                                <span className="remedy-type-tag">
                                  {rem.actionType}
                                </span>
                                <span className={`remedy-priority-tag ${rem.priority.includes("P0") ? "p0" : rem.priority.includes("P1") ? "p1" : "p2"}`}>
                                  {rem.priority}
                                </span>
                              </div>
                            </div>

                            <p className="remedy-item-desc">
                              {rem.description}
                            </p>

                            {/* EXECUTABLE COMMAND SNIPPET */}
                            {rem.command && (
                              <div className="remedy-command-box">
                                <div className="command-box-top">
                                  <span className="command-type-label">
                                    <Terminal size={12} />
                                    {rem.commandType || "Command Snippet"}
                                  </span>
                                  <button
                                    className={`command-copy-btn ${isCmdCopied ? "copied" : ""}`}
                                    onClick={() => copyCommand(rem.id, rem.command)}
                                  >
                                    {isCmdCopied ? <Check size={12} /> : <Copy size={12} />}
                                    {isCmdCopied ? "Copied" : "Copy"}
                                  </button>
                                </div>
                                <pre className="command-pre">
                                  <code>{rem.command}</code>
                                </pre>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* FOOTER ACTIONS & DEEP DIVE LINK */}
      <div className="remedies-footer-bar">
        <div className="footer-left">
          <Server size={15} />
          <span>
            Automated recommendations generated in compliance with <strong>NIST SP 800-61 Rev. 2</strong> and <strong>ISO/IEC 27037</strong> standards.
          </span>
        </div>
        {setActivePage && (
          <button
            className="remedies-deep-dive-btn"
            onClick={() => setActivePage("analyze")}
          >
            <span>Open Comprehensive Forensic Analysis</span>
            <ExternalLink size={14} />
          </button>
        )}
      </div>

      {/* MODAL: M365 TENANT INBOX PURGE SCRIPT */}
      {showPurgeModal && (
        <div className="purge-modal-backdrop" onClick={() => setShowPurgeModal(false)}>
          <div className="purge-modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title-group">
                <Terminal size={18} />
                <h3>Microsoft 365 Tenant Inbox Purge Script</h3>
              </div>
              <button
                className="icon-button small"
                onClick={() => setShowPurgeModal(false)}
              >
                ✕
              </button>
            </div>
            <p className="modal-desc">
              Execute these PowerShell commands with Exchange Administrator credentials to search all tenant mailboxes and permanently hard-delete this malicious email across all user inboxes.
            </p>
            <pre className="modal-code-block">
              <code>{`# 1. Connect to Microsoft 365 Security & Compliance PowerShell
Connect-IPPSSession -UserPrincipalName admin@yourdomain.com

# 2. Define Compliance Search for this Incident
$MessageId = "${analysis?.messageId || "<incident-msg-id@domain.com>"}"
$Subject = "${analysis?.subject?.replace(/"/g, '`"') || "Incident Subject"}"
$SearchName = "SecOps_Purge_${analysis?.id ? analysis.id.replace(/[^a-zA-Z0-9]/g, "").slice(-8) : "Incident"}"

Write-Host "[+] Creating tenant compliance search: $SearchName..." -ForegroundColor Cyan
New-ComplianceSearch -Name $SearchName -ExchangeLocation All -ContentMatchQuery "MessageId:'$MessageId' OR Subject:'$Subject'"

# 3. Start Search
Start-ComplianceSearch -Identity $SearchName
Write-Host "[+] Search initiated. Waiting for index scan completion..." -ForegroundColor Yellow

# 4. Initiate Hard-Delete Purge Action (Unrecoverable Deletion)
New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType HardDelete
Write-Host "[✓] Purge Action submitted. Message purged across tenant mailboxes." -ForegroundColor Green`}</code>
            </pre>
            <div className="modal-footer">
              <button
                className="secondary-button"
                onClick={() => setShowPurgeModal(false)}
              >
                Close
              </button>
              <button
                className="primary-button"
                onClick={() => {
                  const script = `# 1. Connect to Microsoft 365 Security & Compliance PowerShell\nConnect-IPPSSession -UserPrincipalName admin@yourdomain.com\n\n$MessageId = "${analysis?.messageId || "<incident-msg-id@domain.com>"}"\n$Subject = "${analysis?.subject?.replace(/"/g, '`"') || "Incident Subject"}"\n$SearchName = "SecOps_Purge_${Date.now()}"\n\nNew-ComplianceSearch -Name $SearchName -ExchangeLocation All -ContentMatchQuery "MessageId:'$MessageId' OR Subject:'$Subject'"\nStart-ComplianceSearch -Identity $SearchName\nNew-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType HardDelete`;
                  navigator.clipboard.writeText(script);
                  alert("PowerShell purge script copied to clipboard!");
                }}
              >
                <Copy size={15} />
                Copy PowerShell Script
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
