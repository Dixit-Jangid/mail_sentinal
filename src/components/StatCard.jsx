export default function StatCard({
  icon,
  label,
  value,
  change,
  danger,
  warning,
  success,
  purple,
}) {
  const tone = danger
    ? "danger"
    : warning
    ? "warning"
    : success
    ? "success"
    : purple
    ? "purple"
    : "";

  return (
    <div className="stat-card">
      <div className={`stat-icon ${tone}`}>{icon}</div>
      <div className="stat-copy">
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
      <div className={`stat-change ${tone}`}>{change}</div>
    </div>
  );
}
