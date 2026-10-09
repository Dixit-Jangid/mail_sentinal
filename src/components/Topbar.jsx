import { LogOut, Menu } from "lucide-react";

export default function Topbar({
  pageTitle,
  sidebarOpen,
  setSidebarOpen,
  user,
  onLogout,
  authError,
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
        <div className="profile">
          <div className="avatar">{user?.name?.charAt(0)?.toUpperCase() || "U"}</div>
          <div className="profile-text">
            <strong>{user?.name}</strong>
            <span>{user?.email}</span>
          </div>
        </div>
        <button className="icon-button logout-button" onClick={onLogout} aria-label="Log out" title="Log out">
          <LogOut size={18} />
        </button>
      </div>

      {authError && <div className="topbar-auth-error" role="alert">{authError}</div>}
    </header>
  );
}
