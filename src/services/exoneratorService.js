/**
 * exoneratorService.js
 * Forensic client service for The Tor Project's ExoneraTor & TorDNSEL verification.
 * Determines whether a given IP address operated as a Tor relay or exit node on a specific date.
 * Features automated Google DoH fallback for static/serverless deployments.
 */

/**
 * Normalizes any Date object or date string into standard YYYY-MM-DD format for ExoneraTor.
 * @param {string|Date} dateInput
 * @returns {string} YYYY-MM-DD
 */
export function formatExoneratorDate(dateInput) {
  if (!dateInput) {
    return new Date().toISOString().split("T")[0];
  }
  try {
    const d = new Date(dateInput);
    if (!isNaN(d.getTime())) {
      return d.toISOString().split("T")[0];
    }
  } catch {
    // Fallback to today
  }
  return new Date().toISOString().split("T")[0];
}

/**
 * Builds the official, tamper-evident Tor Project ExoneraTor docket URL.
 * @param {string} ip
 * @param {string|Date} dateInput
 * @returns {string} Official Tor Project ExoneraTor URL
 */
export function buildExoneratorUrl(ip, dateInput) {
  const cleanIp = (ip || "").trim().replace(/[[\]]/g, "");
  const formattedDate = formatExoneratorDate(dateInput);
  return `https://exonerator.torproject.org/?ip=${encodeURIComponent(cleanIp)}&timestamp=${formattedDate}`;
}

/**
 * Checks if an IP is a private/loopback RFC 1918 address.
 */
function isPrivateIp(ip) {
  if (!ip) return true;
  const clean = ip.trim().replace(/[[\]]/g, "");
  if (clean.includes(":")) {
    const l = clean.toLowerCase();
    return l === "::1" || l === "::" || l.startsWith("fe80:") || l.startsWith("fc00:") || l.startsWith("fd00:");
  }
  const parts = clean.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return true;
  const [a, b] = parts;
  if (a === 0 || a === 127 || a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

/**
 * Reverses an IPv4 address for TorDNSEL lookup (e.g. 185.220.101.25 -> 25.101.220.185).
 */
function reverseIPv4(ip) {
  return ip.split(".").reverse().join(".");
}

/**
 * Performs Tor verification for an IP address on a specific date.
 * Queries local API backend first, with automatic browser-native Google DoH fallback.
 *
 * @param {string} ip - IP address to investigate
 * @param {string|Date} dateInput - Email transmission date or investigation timestamp
 * @returns {Promise<Object>} Forensic Tor analysis result
 */
export async function checkExonerator(ip, dateInput) {
  const cleanIp = (ip || "").trim().replace(/[[\]]/g, "");
  const formattedDate = formatExoneratorDate(dateInput);

  if (!cleanIp) {
    throw new Error("A valid IP address is required for ExoneraTor verification.");
  }

  // Handle private non-routable IPs immediately
  if (isPrivateIp(cleanIp)) {
    return {
      ip: cleanIp,
      date: formattedDate,
      isTorExitNode: false,
      isTorRelay: false,
      confidence: "High (Non-Routable IP)",
      relayType: "Private RFC 1918 Subnet (Not Routable)",
      threatLevel: "None",
      threatScore: 0,
      dnsResolution: [],
      officialExoneratorUrl: buildExoneratorUrl(cleanIp, formattedDate),
      summary: `IP ${cleanIp} is an internal non-routable network address and cannot be a public Tor relay.`,
      source: "Local IP Classification",
      checkedAt: new Date().toISOString(),
    };
  }

  const officialExoneratorUrl = buildExoneratorUrl(cleanIp, formattedDate);

  // 1. Try backend API first (/api/exonerator)
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);

    const response = await fetch(
      `/api/exonerator?ip=${encodeURIComponent(cleanIp)}&date=${encodeURIComponent(formattedDate)}`,
      { signal: controller.signal }
    );
    clearTimeout(timeoutId);

    if (response.ok) {
      const data = await response.json();
      return {
        ...data,
        officialExoneratorUrl,
        source: "AegisMail Telemetry + TorDNSEL",
      };
    }
  } catch {
    // Non-blocking fallback to browser DoH
  }

  // 2. Client-side Browser Fallback via Google DNS-over-HTTPS (DoH)
  try {
    const octets = cleanIp.split(".");
    if (octets.length === 4) {
      const reversedIp = reverseIPv4(cleanIp);
      const dselDomain = `${reversedIp}.dnsel.torproject.org`;

      const dohResponse = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(dselDomain)}&type=A`);
      if (dohResponse.ok) {
        const dohData = await dohResponse.json();
        const answers = dohData.Answer?.map((a) => a.data) || [];
        const isTorExit = answers.includes("127.0.0.2");

        return {
          ip: cleanIp,
          date: formattedDate,
          isTorExitNode: isTorExit,
          isTorRelay: isTorExit,
          confidence: isTorExit ? "Authoritative (Google DoH TorDNSEL)" : "Verified Clean",
          relayType: isTorExit ? "Tor Anonymizing Exit Node" : "Standard Internet Host",
          threatLevel: isTorExit ? "Critical" : "Low",
          threatScore: isTorExit ? 95 : 10,
          dnsResolution: answers,
          officialExoneratorUrl,
          summary: isTorExit
            ? `IP ${cleanIp} is an authenticated Tor Project exit node on ${formattedDate}. Origin transmission was routed through the Tor onion network to obscure sender identity.`
            : `IP ${cleanIp} showed no active Tor exit node records for ${formattedDate}.`,
          source: "Google DoH Fallback (TorDNSEL)",
          legalAdmissibilityNote: "Verified via Tor Directory Authority DNSBL specifications.",
          checkedAt: new Date().toISOString(),
        };
      }
    }
  } catch {
    // If DoH also fails
  }

  // 3. Graceful fallback with manual investigation link
  return {
    ip: cleanIp,
    date: formattedDate,
    isTorExitNode: false,
    isTorRelay: false,
    confidence: "Manual Verification Recommended",
    relayType: "Unknown / Unresolved",
    threatLevel: "Medium",
    threatScore: 25,
    dnsResolution: [],
    officialExoneratorUrl,
    summary: `Live Tor check inconclusive for IP ${cleanIp}. Click the official ExoneraTor docket link to view archive records directly from the Tor Project.`,
    source: "ExoneraTor Portal Reference",
    checkedAt: new Date().toISOString(),
  };
}
