import {
  Activity,
  Settings,
  ShieldCheck,
} from "lucide-react";
import { navItems } from "../constants/navigation";

export default function Sidebar({
  activePage,
  setActivePage,
  sidebarOpen,
}) {
  return (
    <aside className={`sidebar ${sidebarOpen ? "open" : "collapsed"}`}>
      <div className="brand" onClick={() => setActivePage("dashboard")} style={{ cursor: "pointer" }}>
        <div className="brand-mark">
          <ShieldCheck size={23} />
        </div>
        {sidebarOpen && (
          <div className="brand-copy">
            <strong>AI Email Forensics</strong>
            <span>Detect. Analyze. Protect.</span>
          </div>
        )}
      </div>

      <div className="nav-section-label">
        {sidebarOpen ? "Workspace" : "•"}
      </div>

      <nav className="sidebar-nav">
        {navItems.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            className={`nav-item ${activePage === id ? "active" : ""}`}
            onClick={() => setActivePage(id)}
            title={label}
          >
            <Icon size={18} />
            {sidebarOpen && <span>{label}</span>}
          </button>
        ))}
      </nav>

      <div className="sidebar-spacer" />

      <button
        className={`nav-item ${activePage === "settings" ? "active" : ""}`}
        onClick={() => setActivePage("settings")}
        title="Settings"
      >
        <Settings size={18} />
        {sidebarOpen && <span>Settings</span>}
      </button>

      {sidebarOpen && (
        <div className="system-card">
          <div className="system-card-top">
            <div className="status-dot">
              <Activity size={15} />
            </div>
            <span>System status</span>
          </div>
          <strong>All systems operational</strong>
          <div className="system-progress">
            <span />
          </div>
          <small>Analysis engine · Online</small>
        </div>
      )}

      <div className="sidebar-user">
        <div className="avatar">A</div>
        {sidebarOpen && (
          <div>
            <strong>Security Analyst</strong>
            <span>Analyst workspace</span>
          </div>
        )}
      </div>
    </aside>
  );
}
