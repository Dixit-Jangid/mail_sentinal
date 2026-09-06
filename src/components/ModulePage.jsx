export default function ModulePage({ title, subtitle, icon, children, actions }) {
  return (
    <div>
      <div className="page-heading">
        <div>
          <div className="breadcrumb">
            Workspace <span>/</span> {title}
          </div>
          <h2>{title}</h2>
          <p>{subtitle}</p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          {actions}
          {icon && <div className="panel-icon">{icon}</div>}
        </div>
      </div>
      {children}
    </div>
  );
}
