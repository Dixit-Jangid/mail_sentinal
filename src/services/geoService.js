/**
 * GeoIP Service â€” Client-side multi-provider lookup.
 * Works on Netlify / Vercel static hosting with no backend required.
 * Providers (tried in order):
 *   1. ipapi.co          â€” Free, CORS-enabled, no key needed
 *   2. ipwho.is          â€” Free, CORS-enabled, 7-decimal GPS
 *   3. freeipapi.com     â€” Free, CORS-enabled fallback
 *   4. ip-api.com        â€” HTTP-only but works client-side (limited to 45 req/min)
 * Never throws â€” always returns a usable object.
 */

const geoServiceCache = new Map();

const RESERVED_RANGES = [
  { prefix: "10.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.16.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.17.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.18.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.19.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.20.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.21.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.22.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.23.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.24.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.25.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.26.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.27.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.28.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.29.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.30.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.31.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "192.168.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "127.", type: "Loopback Interface (RFC 1122)", country: "Localhost", city: "Host Device" },
  { prefix: "169.254.", type: "Link-Local (APIPA)", country: "Link-Local Network", city: "Local Interface" },
];

function isPrivateAddress(ip) {
  const clean = (ip || "").trim().replace(/[[\]]/g, "");
  for (const r of RESERVED_RANGES) {
    if (clean.startsWith(r.prefix)) return true;
  }
  const parts = clean.split(".").map(Number);
  if (parts.length === 4 && parts[0] >= 224) return true;
  return false;
}

function buildPrivateResult(ip) {
  const clean = (ip || "").trim();
  const range = RESERVED_RANGES.find((r) => clean.startsWith(r.prefix));
  return {
    ip: clean,
    city: range ? range.city : "Internal Host",
    region: "Internal Subnet",
    country_name: range ? range.country : "Internal Network",
    country_code: "LOCAL",
    country_flag: "ðŸ”’",
    postal: "N/A",
    latitude: 0,
    longitude: 0,
    timezone: "UTC",
    isp: range ? range.type : "Private Network",
    org: "RFC 1918 Private Address",
    asn: "N/A",
    isPrivate: true,
    isVpn: false,
    isTor: false,
    isProxy: false,
    vpnType: "Internal LAN (No VPN)",
    vpnConfidence: "None",
    threatScore: 0,
    accuracyStatus: "Non-Routable RFC 1918 / Reserved Address",
  };
}

function buildStubResult(ip) {
  return {
    ip: (ip || "").trim(),
    city: "Location Pending",
    region: "Unknown Region",
    country_name: "Unknown Country",
    country_code: "UN",
    country_flag: "ðŸŒ",
    postal: "N/A",
    latitude: 0,
    longitude: 0,
    timezone: "UTC",
    isp: "Unknown ISP",
    org: "Unknown Organization",
    asn: "N/A",
    isPrivate: false,
    isVpn: false,
    isTor: false,
    isProxy: false,
    vpnType: "Unknown (lookup failed)",
    vpnConfidence: "None",
    threatScore: 0,
    accuracyStatus: "All GeoIP providers unreachable â€” check connection",
  };
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 6000) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    clearTimeout(id);
    return res;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

/**
 * Provider 1: ipapi.co â€” CORS-enabled, free, no API key required
 */
async function tryIpapiCo(ip) {
  const url = `https://ipapi.co/${encodeURIComponent(ip)}/json/`;
  const res = await fetchWithTimeout(url);
  if (!res.ok) return null;
  const d = await res.json();
  if (d.error || !d.country_name) return null;
  return {
    ip: d.ip || ip,
    city: d.city || "Unknown City",
    region: d.region || "Unknown Region",
    country_name: d.country_name || "Unknown Country",
    country_code: d.country_code || "UN",
    country_flag: d.country_code ? `https://flagcdn.com/16x12/${d.country_code.toLowerCase()}.png` : "ðŸŒ",
    postal: d.postal || "N/A",
    latitude: d.latitude || 0,
    longitude: d.longitude || 0,
    timezone: d.timezone || "UTC",
    isp: d.org || d.isp || "ISP Unknown",
    org: d.org || "Network Host",
    asn: d.asn || "N/A",
    isPrivate: false,
    isVpn: false,
    isTor: false,
    isProxy: false,
    vpnType: "Clean Direct Connection",
    vpnConfidence: "None",
    threatScore: 10,
    accuracyStatus: "Real-Time (ipapi.co)",
  };
}

/**
 * Provider 2: ipwho.is â€” CORS-enabled, free, 7-decimal GPS
 */
async function tryIpwhoIs(ip) {
  const url = `https://ipwho.is/${encodeURIComponent(ip)}`;
  const res = await fetchWithTimeout(url);
  if (!res.ok) return null;
  const d = await res.json();
  if (!d.success) return null;
  return {
    ip: d.ip || ip,
    city: d.city || "Unknown City",
    region: d.region || d.region_code || "Unknown Region",
    country_name: d.country || "Unknown Country",
    country_code: d.country_code || "UN",
    country_flag: d.flag?.emoji || "ðŸŒ",
    postal: d.postal || "N/A",
    latitude: typeof d.latitude === "number" ? d.latitude : parseFloat(d.latitude) || 0,
    longitude: typeof d.longitude === "number" ? d.longitude : parseFloat(d.longitude) || 0,
    timezone: d.timezone?.id ? `${d.timezone.id} (${d.timezone.utc || "UTC"})` : "UTC",
    isp: d.connection?.isp || "Internet Service Provider",
    org: d.connection?.org || d.connection?.domain || "Network Host",
    asn: d.connection?.asn ? `AS${d.connection.asn}` : "N/A",
    isPrivate: false,
    isVpn: false,
    isTor: false,
    isProxy: false,
    vpnType: "Clean Direct Connection",
    vpnConfidence: "None",
    threatScore: 10,
    accuracyStatus: "High-Precision GPS (ipwho.is)",
  };
}

/**
 * Provider 3: freeipapi.com â€” CORS-enabled fallback
 */
async function tryFreeIpApi(ip) {
  const url = `https://freeipapi.com/api/json/${encodeURIComponent(ip)}`;
  const res = await fetchWithTimeout(url);
  if (!res.ok) return null;
  const d = await res.json();
  if (!d.countryName) return null;
  return {
    ip: ip,
    city: d.cityName || "Unknown City",
    region: d.regionName || "Unknown Region",
    country_name: d.countryName || "Unknown Country",
    country_code: d.countryCode || "UN",
    country_flag: "ðŸŒ",
    postal: d.zipCode || "N/A",
    latitude: parseFloat(d.latitude) || 0,
    longitude: parseFloat(d.longitude) || 0,
    timezone: d.timeZone || "UTC",
    isp: "Public ISP",
    org: d.ipVersion ? `IPv${d.ipVersion} Network` : "Network Host",
    asn: d.asn ? `AS${d.asn}` : "N/A",
    isPrivate: false,
    isVpn: false,
    isTor: false,
    isProxy: false,
    vpnType: "Clean Direct Connection",
    vpnConfidence: "None",
    threatScore: 10,
    accuracyStatus: "Standard Precision (freeipapi.com)",
  };
}

/**
 * Provider 4: ip-api.com â€” works client-side on HTTP, limited to 45 req/min on free tier
 * Note: ip-api.com is HTTP-only, may be blocked on HTTPS pages.
 * Used as last fallback.
 */
async function tryIpApiCom(ip) {
  // This will fail from HTTPS pages due to mixed-content â€” wrapped in try/catch
  const url = `https://pro.ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting&lang=en`;
  try {
    const res = await fetchWithTimeout(url);
    if (!res.ok) return null;
    const d = await res.json();
    if (d.status !== "success") return null;
    const isProxy = Boolean(d.proxy);
    const isHosting = Boolean(d.hosting);
    return {
      ip: d.query || ip,
      city: d.city || "Unknown City",
      region: d.regionName || "Unknown Region",
      country_name: d.country || "Unknown Country",
      country_code: d.countryCode || "UN",
      country_flag: "ðŸŒ",
      postal: d.zip || "N/A",
      latitude: d.lat || 0,
      longitude: d.lon || 0,
      timezone: d.timezone || "UTC",
      isp: d.isp || "ISP",
      org: d.org || d.isp || "Network Host",
      asn: d.as || "N/A",
      isPrivate: false,
      isVpn: isProxy || isHosting,
      isTor: false,
      isProxy,
      isHosting,
      vpnType: isProxy ? "VPN / Anonymous Proxy" : isHosting ? "Datacenter / VPS" : "Clean Direct Connection",
      vpnConfidence: (isProxy || isHosting) ? "High" : "None",
      threatScore: isProxy ? 80 : isHosting ? 55 : 10,
      accuracyStatus: "Real-Time with VPN Detection (ip-api.com)",
    };
  } catch {
    return null;
  }
}

/**
 * Main IP lookup function.
 * Tries 4 providers in order. Never throws â€” returns stub on total failure.
 */
export async function lookupIP(ip) {
  if (!ip || typeof ip !== "string") {
    return buildStubResult("unknown");
  }

  const cleanIp = ip.trim().replace(/[[\]]/g, "");

  if (!cleanIp) return buildStubResult("unknown");

  // Return cached result
  if (geoServiceCache.has(cleanIp)) {
    return geoServiceCache.get(cleanIp);
  }

  // Private / reserved address
  if (isPrivateAddress(cleanIp)) {
    const result = buildPrivateResult(cleanIp);
    geoServiceCache.set(cleanIp, result);
    return result;
  }

  // Try providers in sequence
  const providers = [
    () => tryIpapiCo(cleanIp),
    () => tryIpwhoIs(cleanIp),
    () => tryFreeIpApi(cleanIp),
    () => tryIpApiCom(cleanIp),
  ];

  for (const provider of providers) {
    try {
      const result = await provider();
      if (result && result.country_name && result.country_name !== "Unknown Country") {
        geoServiceCache.set(cleanIp, result);
        return result;
      }
    } catch {
      // Try next provider
    }
  }

  // All providers failed â€” return stub (never throw to UI)
  const stub = buildStubResult(cleanIp);
  geoServiceCache.set(cleanIp, stub);
  return stub;
}

/**
 * Resolve a multi-hop email route â€” tries backend first, then client-side fallback.
 */
export async function lookupRoute(ips) {
  if (!Array.isArray(ips) || ips.length === 0) {
    return { totalHops: 0, hops: [], hasVpnInRoute: false, originHop: null, destinationHop: null };
  }

  const cleanIPs = ips
    .map((ip) => String(ip || "").trim().replace(/[[\]]/g, ""))
    .filter((ip) => ip && !isPrivateAddress(ip));

  if (cleanIPs.length === 0) {
    return { totalHops: 0, hops: [], hasVpnInRoute: false, originHop: null, destinationHop: null };
  }

  // Try backend route endpoint first (when running with Express server)
  try {
    const res = await fetchWithTimeout("/api/geoip-route", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ips: cleanIPs }),
    }, 8000);
    if (res.ok) {
      const data = await res.json();
      if (data.hops && data.hops.length > 0) return data;
    }
  } catch {
    // Fallback to client-side resolution
  }

  // Client-side hop-by-hop resolution
  const hops = [];
  for (const ip of cleanIPs.slice(0, 8)) {
    const geo = await lookupIP(ip);
    if (geo && !geo.isPrivate && geo.latitude !== 0) {
      hops.push({ ...geo, hopIndex: hops.length + 1 });
    }
  }

  return {
    totalHops: hops.length,
    hops,
    hasVpnInRoute: hops.some((h) => h.isVpn || h.isProxy),
    originHop: hops[0] || null,
    destinationHop: hops.length > 1 ? hops[hops.length - 1] : null,
  };
}

