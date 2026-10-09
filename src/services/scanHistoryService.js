function getStorageKey(email) {
  if (typeof email !== "string" || !email.trim()) {
    throw new Error("A signed-in user is required to access scan history.");
  }
  return `mail_sentinel_scan_history_${encodeURIComponent(email.trim().toLowerCase())}`;
}

function isScanRecord(record) {
  return (
    record &&
    typeof record.id === "string" &&
    typeof record.analyzedAt === "string" &&
    typeof record.phishingDetected === "boolean" &&
    typeof record.riskLevel === "string" &&
    typeof record.blocked === "boolean"
  );
}

export function readScanHistory(email) {
  if (typeof window === "undefined") {
    throw new Error("Scan history is only available in a browser.");
  }

  const storedHistory = window.localStorage.getItem(getStorageKey(email));
  if (storedHistory === null) return [];

  let history;
  try {
    history = JSON.parse(storedHistory);
  } catch {
    throw new Error("Saved scan history is unreadable. Clear this site's saved data to continue.");
  }

  if (!Array.isArray(history) || !history.every(isScanRecord)) {
    throw new Error("Saved scan history has an invalid format. Clear this site's saved data to continue.");
  }
  return history;
}

export function recordScanHistory(email, analysis) {
  if (!analysis || typeof analysis.id !== "string" || !analysis.id) {
    throw new Error("The completed analysis is missing its scan ID.");
  }

  const history = readScanHistory(email);
  const record = {
    id: analysis.id,
    analyzedAt: analysis.analyzedAt || new Date().toISOString(),
    phishingDetected: Boolean(analysis.phishingDetected),
    riskLevel: typeof analysis.riskLevel === "string" ? analysis.riskLevel : "Unknown",
    blocked: analysis.riskLevel === "High Risk",
  };
  const existingIndex = history.findIndex((item) => item.id === record.id);
  if (existingIndex === -1) {
    history.push(record);
  } else {
    history[existingIndex] = record;
  }

  window.localStorage.setItem(getStorageKey(email), JSON.stringify(history));
  return history;
}
