import { Settings } from "lucide-react";
import { navItems } from "../constants/navigation";

export default function Sidebar({
  activePage,
  setActivePage,
  sidebarOpen,
}) {
  return (
    <aside className={`sidebar ${sidebarOpen ? "open" : "collapsed"}`}>
      <div className="brand" onClick={() => setActivePage("dashboard")} style={{ cursor: "pointer" }}>
        <img
          className="brand-mark"
          src="/mail-sentinel-logo.png"
          alt="MAIL SENTINEL logo"
        />
        {sidebarOpen && (
          <div className="brand-copy">
            <strong>MAIL SENTINEL</strong>
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

    </aside>
  );
}
