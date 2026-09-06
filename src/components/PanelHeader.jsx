export default function PanelHeader({ title, subtitle, icon }) {
  return (
    <div className="panel-header">
      <div className="panel-title-wrap">
        <div className="panel-icon">{icon}</div>
        <div>
          <h3>{title}</h3>
          <p>{subtitle}</p>
        </div>
      </div>
    </div>
  );
}
