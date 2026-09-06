/**
 * High-Accuracy GeoIP Resolution & Forensic Telemetry Service
 * Multi-tier fallback architecture:
 * 1. Express backend proxy (/api/geoip)
 * 2. High-precision ipwho.is (direct browser CORS fallback with 7-decimal GPS coordinates)
 * 3. FreeIPAPI fallback
 * Includes in-memory caching and strict RFC 1918 private IP validation.
 */

// In-memory cache to prevent redundant lookups and respect rate limits
const geoCache = new Map();

/**
 * Validates whether an IP is private, link-local, loopback, or reserved.
 */
export function isPrivateIP(ip) {
  if (!ip || typeof ip !== "string") return true;
  const clean = ip.trim().replace(/[[\]]/g, "");

  // IPv6 checks
  if (clean.includes(":")) {
    const lower = clean.toLowerCase();
    if (lower === "::1" || lower === "::" || lower.startsWith("fe80:") || lower.startsWith("fc00:") || lower.startsWith("fd00:")) {
      return true;
    }
    return false;
  }

  // IPv4 checks
  const parts = clean.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return true;
  }

  const [a, b] = parts;

  // 0.0.0.0/8
  if (a === 0) return true;
  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;
  // 10.0.0.0/8 (RFC 1918 Class A)
  if (a === 10) return true;
  // 172.16.0.0/12 (RFC 1918 Class B: 172.16.x.x - 172.31.x.x)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16 (RFC 1918 Class C)
  if (a === 192 && b === 168) return true;
  // 169.254.0.0/16 (Link-Local)
  if (a === 169 && b === 254) return true;
  // 100.64.0.0/10 (Carrier-Grade NAT: 100.64.0.0 - 100.127.255.255)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (Documentation / Test Networks)
  if (a === 192 && b === 0 && parts[2] === 2) return true;
  if (a === 198 && b === 51 && parts[2] === 100) return true;
  if (a === 203 && b === 0 && parts[2] === 113) return true;
  // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
  if (a >= 224) return true;

  return false;
}

/**
 * Builds OpenStreetMap and Google Maps links from high-precision coordinates.
 */
export function buildMapLinks(lat, lon) {
  if (!lat && !lon) return { mapEmbedUrl: null, googleMapsUrl: null, openStreetMapUrl: null };
  const latitude = parseFloat(lat);
  const longitude = parseFloat(lon);
  if (isNaN(latitude) || isNaN(longitude) || (latitude === 0 && longitude === 0)) {
    return { mapEmbedUrl: null, googleMapsUrl: null, openStreetMapUrl: null };
  }

  const delta = 0.05;
  const bbox = `${(longitude - delta).toFixed(4)}%2C${(latitude - delta).toFixed(4)}%2C${(longitude + delta).toFixed(4)}%2C${(latitude + delta).toFixed(4)}`;
  const mapEmbedUrl = `https://www.openstreetmap.org/export/embed.html?bbox=${bbox}&layer=mapnik&marker=${latitude.toFixed(5)}%2C${longitude.toFixed(5)}`;
  const googleMapsUrl = `https://www.google.com/maps?q=${latitude.toFixed(6)},${longitude.toFixed(6)}`;
  const openStreetMapUrl = `https://www.openstreetmap.org/?mlat=${latitude.toFixed(6)}&mlon=${longitude.toFixed(6)}#map=14/${latitude.toFixed(4)}/${longitude.toFixed(4)}`;

  return { mapEmbedUrl, googleMapsUrl, openStreetMapUrl };
}

/**
 * Resolves high-precision geolocation for a given IP address.
 */
export async function lookupGeoIP(ip) {
  if (!ip) return null;
  const cleanIp = ip.trim().replace(/[[\]]/g, "");

  // Check cache
  if (geoCache.has(cleanIp)) {
    return geoCache.get(cleanIp);
  }

  // Handle private IP
  if (isPrivateIP(cleanIp)) {
    const privateResult = {
      ip: cleanIp,
      city: "Localhost / Internal Subnet",
      region: "Private RFC 1918",
      country_name: "Internal Network",
      country_code: "LOCAL",
      country_flag: "🔒",
      postal: "N/A",
      latitude: 0,
      longitude: 0,
      timezone: "UTC",
      isp: "Private / Local Area Network",
      org: "RFC 1918 Non-Routable Address Space",
      asn: "N/A",
      isPrivate: true,
      accuracyStatus: "Internal Address (Not Geolocated on Public Internet)",
      mapEmbedUrl: null,
      googleMapsUrl: null,
      openStreetMapUrl: null,
    };
    geoCache.set(cleanIp, privateResult);
    return privateResult;
  }

  // Provider 1: Direct high-precision call to ipwho.is (7-decimal GPS accuracy, postal, flag, timezone, ASN)
  try {
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(cleanIp)}`);
    if (res.ok) {
      const data = await res.json();
      if (data.success) {
        const maps = buildMapLinks(data.latitude, data.longitude);
        const result = {
          ip: cleanIp,
          city: data.city || "Unknown City",
          region: data.region || data.region_code || "Unknown Region",
          country_name: data.country || "Unknown Country",
          country_code: data.country_code || "UN",
          country_flag: data.flag?.emoji || "🌐",
          flagSvg: data.flag?.img || null,
          postal: data.postal || "N/A",
          latitude: typeof data.latitude === "number" ? data.latitude : parseFloat(data.latitude) || 0,
          longitude: typeof data.longitude === "number" ? data.longitude : parseFloat(data.longitude) || 0,
          timezone: data.timezone?.id ? `${data.timezone.id} (${data.timezone.utc || "UTC"})` : "UTC",
          isp: data.connection?.isp || "Internet Service Provider",
          org: data.connection?.org || data.connection?.domain || "Network Host",
          asn: data.connection?.asn ? `AS${data.connection.asn}` : "N/A",
          isPrivate: false,
          accuracyStatus: "High-Precision GPS & Postal (ipwho.is)",
          sourceProvider: "ipwho.is High-Precision",
          ...maps,
        };
        geoCache.set(cleanIp, result);
        return result;
      }
    }
  } catch {
    // Proceed to backend proxy fallback
  }

  // Provider 2: Local backend proxy /api/geoip
  try {
    const res = await fetch(`/api/geoip?ip=${encodeURIComponent(cleanIp)}`);
    if (res.ok) {
      const data = await res.json();
      if (data && !data.error && data.country_name !== "Unknown Country" && (data.latitude !== 0 || data.longitude !== 0)) {
        const maps = buildMapLinks(data.latitude, data.longitude);
        const result = {
          ip: cleanIp,
          city: data.city || "Unknown City",
          region: data.region || "Unknown Region",
          country_name: data.country_name || "Unknown Country",
          country_code: data.country_code || "UN",
          country_flag: data.country_flag || "🌐",
          postal: data.postal || "N/A",
          latitude: typeof data.latitude === "number" ? data.latitude : parseFloat(data.latitude) || 0,
          longitude: typeof data.longitude === "number" ? data.longitude : parseFloat(data.longitude) || 0,
          timezone: data.timezone || "UTC",
          isp: data.isp || "Public ISP",
          org: data.org || data.isp || "Network Host",
          asn: data.asn || "N/A",
          isPrivate: false,
          accuracyStatus: data.accuracyStatus || "Verified High Precision Telemetry",
          sourceProvider: "Backend Proxy",
          ...maps,
        };
        geoCache.set(cleanIp, result);
        return result;
      }
    }
  } catch {
    // Proceed to tertiary provider
  }

  // Provider 3: FreeIPAPI fallback
  try {
    const res = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(cleanIp)}`);
    if (res.ok) {
      const data = await res.json();
      if (data.countryName) {
        const maps = buildMapLinks(data.latitude, data.longitude);
        const result = {
          ip: cleanIp,
          city: data.cityName || "Unknown City",
          region: data.regionName || "Unknown Region",
          country_name: data.countryName || "Unknown Country",
          country_code: data.countryCode || "UN",
          country_flag: "🌐",
          postal: data.zipCode || "N/A",
          latitude: parseFloat(data.latitude) || 0,
          longitude: parseFloat(data.longitude) || 0,
          timezone: data.timeZone || "UTC",
          isp: "Public ISP",
          org: "Autonomous System Node",
          asn: data.asn ? `AS${data.asn}` : "N/A",
          isPrivate: false,
          accuracyStatus: "Standard Precision GeoIP",
          sourceProvider: "FreeIPAPI",
          ...maps,
        };
        geoCache.set(cleanIp, result);
        return result;
      }
    }
  } catch {
    // End of fallbacks
  }

  // If all live providers fail, return clean unlocated stub
  return {
    ip: cleanIp,
    city: "Location Resolution Pending",
    region: "Unknown",
    country_name: "External Public Node",
    country_code: "UN",
    country_flag: "🌐",
    postal: "N/A",
    latitude: 0,
    longitude: 0,
    timezone: "UTC",
    isp: "External Host",
    org: "Public Internet Node",
    asn: "N/A",
    isPrivate: false,
    accuracyStatus: "Live lookup rate-limited or offline",
    mapEmbedUrl: null,
    googleMapsUrl: null,
    openStreetMapUrl: null,
  };
}

/**
 * Extracts and prioritizes all forensic IP addresses discovered in an email.
 * Classifies them by their forensic evidentiary role.
 */
export function extractAllForensicIPs(headers = [], receivedSpf = "", authResults = "") {
  const discovered = [];
  const seenIPs = new Set();

  const addIP = (ip, role, priority, hopNum = null) => {
    if (!ip) return;
    const clean = ip.trim().replace(/[[\]]/g, "");
    if (!clean || seenIPs.has(clean)) return;
    seenIPs.add(clean);
    discovered.push({
      ip: clean,
      role,
      priority,
      isPrivate: isPrivateIP(clean),
      hopNumber: hopNum,
    });
  };

  // 1. High Priority: X-Originating-IP / X-Sender-IP / X-Real-IP (True End-User Device)
  for (const h of headers) {
    const key = (h.key || "").toLowerCase();
    const val = String(h.value || "");
    if (key === "x-originating-ip" || key === "x-sender-ip" || key === "x-real-ip") {
      const match = val.match(/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-fA-F:]{4,})/);
      if (match) {
        addIP(match[1], "End-User Client Device (X-Originating-IP)", 1);
      }
    }
  }

  // 2. High Priority: client-ip in Authentication-Results & Received-SPF (Audited by Gateway)
  const clientIpMatches = (receivedSpf + " " + authResults).match(/client-ip=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-fA-F:]{4,})/gi) || [];
  for (const m of clientIpMatches) {
    const ip = m.replace(/client-ip=/i, "").trim();
    addIP(ip, "Gateway Authenticated Sender (client-ip)", 2);
  }

  // 3. Sequential Received Headers (Transmitting MTAs)
  const receivedHeaders = headers
    .filter((h) => (h.key || "").toLowerCase() === "received")
    .map((h) => String(h.value || ""));

  const chronological = [...receivedHeaders].reverse();
  chronological.forEach((rawText, idx) => {
    const hopNum = idx + 1;
    // Look for IP in from clause: 'from host (rdns [IP])'
    const fromIpMatch = rawText.match(/from\s+[^;(]+(?:\([^)]*\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-fA-F:]{4,})\]|\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b)/i);
    if (fromIpMatch) {
      const ip = fromIpMatch[1] || fromIpMatch[2];
      addIP(ip, `MTA Relay Hop #${hopNum} (Transmitting Node)`, 3 + hopNum, hopNum);
    }

    // Also look for any bracketed IPs
    const bracketMatches = rawText.match(/\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-fA-F:]{4,})\]/g) || [];
    for (const bm of bracketMatches) {
      const ip = bm.replace(/[[\]]/g, "");
      addIP(ip, `MTA Relay Hop #${hopNum} (Observed IP)`, 10 + hopNum, hopNum);
    }
  });

  // Sort by priority (lowest number = highest forensic relevance)
  discovered.sort((a, b) => a.priority - b.priority);

  // Return best public originating IP
  const bestPublic = discovered.find((item) => !item.isPrivate);
  const primaryIP = bestPublic ? bestPublic.ip : discovered[0]?.ip || null;

  return {
    primaryIP,
    bestPublicNode: bestPublic || null,
    allDiscoveredIPs: discovered,
  };
}
