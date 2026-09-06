import { Bell, CheckCircle2, ChevronDown, Menu, ShieldAlert } from "lucide-react";

export default function Topbar({
  pageTitle,
  sidebarOpen,
  setSidebarOpen,
  notifications,
  setNotifications,
  recentScanCount = 0,
}) {
  return (
    <header className="topbar">
      <div className="topbar-left">
        <button
          className="icon-button mobile-menu"
          onClick={() => setSidebarOpen(!sidebarOpen)}
          aria-label="Toggle sidebar"
        >
          <Menu size={20} />
        </button>

        <div>
          <span className="eyebrow">AI-POWERED EMAIL SECURITY</span>
          <h1>{pageTitle}</h1>
        </div>
      </div>

      <div className="topbar-actions">
        <button
          className="icon-button notification-button"
          onClick={() => setNotifications(!notifications)}
          aria-label="Notifications"
        >
          <Bell size={19} />
          <span className="notification-dot" />
        </button>

        <div className="profile">
          <div className="avatar">A</div>
          <div className="profile-text">
            <strong>Analyst</strong>
            <span>Security Operations</span>
          </div>
          <ChevronDown size={15} />
        </div>
      </div>

      {notifications && (
        <div className="notification-panel">
          <strong>Notifications</strong>
          <p>
            <ShieldAlert size={15} />
            Forensic engine initialized. {recentScanCount > 0 ? `${recentScanCount} email(s) analyzed.` : "Ready for scans."}
          </p>
          <p>
            <CheckCircle2 size={15} />
            SHA-256 evidence verification: Active.
          </p>
        </div>
      )}
    </header>
  );
}
