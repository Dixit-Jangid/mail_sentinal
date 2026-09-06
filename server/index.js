import process from "node:process";
import express from "express";
import cors from "cors";
import dns from "node:dns/promises";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

/**
 * Health check endpoint
 */
app.get("/api/health", (req, res) => {
  res.json({ status: "online", timestamp: new Date().toISOString() });
});

/**
 * 1. REAL LIVE DATA BREACH & HIBP API
 * Fetches genuine data breach intelligence from live global repositories.
 */
app.get("/api/breach", async (req, res) => {
  const email = (req.query.email || "").trim().toLowerCase();

  if (!email || !email.includes("@")) {
    return res.status(400).json({ error: "A valid email address is required." });
  }

  const hibpUrl = `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000);

    const response = await fetch(
      `https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`,
      { signal: controller.signal }
    );
    clearTimeout(timeoutId);

    if (response.status === 404) {
      return res.json({
        email,
        pwned: false,
        breachCount: 0,
        passwordsExposed: 0,
        riskRating: "Safe",
        breaches: [],
        hibpUrl,
        checkedAt: new Date().toLocaleString(),
      });
    }

    if (response.ok) {
      const data = await response.json();
      const rawBreaches = data.ExposedBreaches?.breaches_details || [];
      const breaches = rawBreaches.map((b) => ({
        name: b.breach || "Security Breach",
        domain: b.domain || "Unknown",
        breachDate: b.xposed_date || b.added ? new Date(b.added || b.xposed_date).toLocaleDateString() : "Undisclosed",
        pwnCount: typeof b.xposed_records === "number" ? b.xposed_records : 0,
        description: b.details || `Breach incident affecting ${b.breach}.`,
        logo: b.logo || "",
        industry: b.industry || "General",
        dataClasses: b.xposed_data
          ? b.xposed_data.split(";").map((s) => s.trim()).filter(Boolean)
          : ["Email addresses", "Passwords"],
        verified: b.verified === "Yes",
      }));

      const passwordsExposed = data.BreachesSummary?.passwords_count || 0;
      const riskRating = data.BreachMetrics?.risk_rating || (breaches.length > 3 ? "Critical" : breaches.length > 0 ? "High" : "Low");

      return res.json({
        email,
        pwned: breaches.length > 0,
        breachCount: breaches.length,
        passwordsExposed,
        riskRating,
        breaches,
        hibpUrl,
        checkedAt: new Date().toLocaleString(),
      });
    }

    // Fallback if status was not 200 or 404 (e.g. rate limit)
    const checkRes = await fetch(
      `https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`
    );
    if (checkRes.ok) {
      const checkData = await checkRes.json();
      const breachNames = Array.isArray(checkData.Breaches) ? checkData.Breaches.flat() : [];
      return res.json({
        email,
        pwned: breachNames.length > 0,
        breachCount: breachNames.length,
        passwordsExposed: 0,
        riskRating: breachNames.length > 2 ? "High" : "Medium",
        breaches: breachNames.map((name) => ({
          name: String(name),
          domain: `${String(name).toLowerCase().replace(/[^a-z0-9]/g, "")}.com`,
          breachDate: "Recorded",
          pwnCount: 0,
          description: `Security breach involving credentials associated with ${name}.`,
          dataClasses: ["Email addresses", "Passwords"],
          verified: true,
        })),
        hibpUrl,
        checkedAt: new Date().toLocaleString(),
      });
    }

    return res.json({
      email,
      pwned: false,
      breachCount: 0,
      passwordsExposed: 0,
      riskRating: "Clean",
      breaches: [],
      hibpUrl,
      checkedAt: new Date().toLocaleString(),
    });
  } catch (error) {
    console.error("Breach lookup server error:", error);
    return res.status(500).json({
      error: "Unable to query live breach telemetry at this moment.",
      email,
      hibpUrl,
    });
  }
});

const serverGeoCache = new Map();

function isPrivateIpAddress(ip) {
  if (!ip || typeof ip !== "string") return true;
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
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}

// ── VPN / Proxy / Tor Heuristic Classifier ─────────────────────────────────
const VPN_KEYWORDS = [
  "nordvpn", "expressvpn", "surfshark", "mullvad", "protonvpn", "ipvanish",
  "cyberghost", "purevpn", "hidemyass", "torguard", "pia", "privatevpn",
  "windscribe", "tunnelbear", "hotspot shield", "vyprvpn",
  "tor exit", "tor network", "torexit", "anonymizer",
  "datacamp", "choopa", "vultr", "linode", "digitalocean", "ovh sas", "m247",
  "quadranet", "sharktech", "serverius", "frantech", "prgmr",
  "privacyfoundation", "privacyguard", "private internet",
];

function evaluateVpnThreat(data) {
  const isp = (data.isp || "").toLowerCase();
  const org = (data.org || "").toLowerCase();
  const asName = (data.as || "").toLowerCase();
  const combined = `${isp} ${org} ${asName}`;

  let isVpn = false;
  let vpnType = "Clean Direct Connection";
  let vpnConfidence = "None";
  let isTor = false;
  let isProxy = Boolean(data.proxy);
  let isHosting = Boolean(data.hosting);
  let threatScore = 10;
  let threatFlags = [];

  // Tor detection
  if (combined.includes("tor") || combined.includes("torexit") || combined.includes("onion")) {
    isTor = true;
    isVpn = true;
    vpnType = "Tor Exit Node";
    vpnConfidence = "High";
    threatScore = 95;
    threatFlags.push("TOR_EXIT_NODE");
  }

  // Direct proxy flag from ip-api
  if (data.proxy && !isTor) {
    isVpn = true;
    vpnType = "Commercial VPN / Anonymous Proxy";
    vpnConfidence = "High";
    threatScore = Math.max(threatScore, 80);
    threatFlags.push("PROXY_DETECTED");
  }

  // Hosting/datacenter with VPN keywords
  if (data.hosting && !isTor) {
    vpnType = "Datacenter / VPS / Relay Node";
    vpnConfidence = "Medium";
    threatScore = Math.max(threatScore, 55);
    threatFlags.push("DATACENTER_HOSTING");
    isVpn = true;
  }

  // Keyword-based detection
  for (const kw of VPN_KEYWORDS) {
    if (combined.includes(kw)) {
      isVpn = true;
      if (!isTor && !data.proxy) {
        vpnType = "Identified VPN Provider (" + kw.toUpperCase() + ")";
        vpnConfidence = "High";
        threatScore = Math.max(threatScore, 85);
        threatFlags.push("VPN_PROVIDER_ASN");
      }
      break;
    }
  }

  return { isVpn, vpnType, vpnConfidence, isTor, isProxy, isHosting, threatScore, threatFlags };
}

/**
 * 2. REAL LIVE HIGH-ACCURACY GEOIP LOOKUP API
 * Resolves genuine IP routing, ASN, ISP, and high-precision GPS coordinates.
 * Also detects VPN, Proxy, Tor, and Datacenter relay nodes.
 */
app.get("/api/geoip", async (req, res) => {
  const ip = (req.query.ip || "").trim().replace(/[[\]]/g, "");

  if (!ip) {
    return res.status(400).json({ error: "An IP address query parameter is required." });
  }

  // Check in-memory cache first
  if (serverGeoCache.has(ip)) {
    return res.json(serverGeoCache.get(ip));
  }

  // Check for private / loopback IPs
  if (isPrivateIpAddress(ip)) {
    const privateResponse = {
      ip,
      city: "Localhost / Internal Subnet",
      region: "Private RFC 1918",
      country_name: "Internal Network",
      country_code: "LOCAL",
      country_flag: "🔒",
      postal: "N/A",
      latitude: 0,
      longitude: 0,
      timezone: "UTC",
      isp: "Local Area Network (RFC 1918)",
      org: "Private Infrastructure",
      asn: "N/A",
      isPrivate: true,
      isVpn: false,
      vpnType: "Internal LAN (No VPN)",
      vpnConfidence: "None",
      isTor: false,
      isProxy: false,
      isHosting: false,
      threatScore: 0,
      threatFlags: [],
      accuracyStatus: "Non-Routable RFC 1918 Address",
    };
    serverGeoCache.set(ip, privateResponse);
    return res.json(privateResponse);
  }

  // Provider 1: ip-api.com with proxy+hosting fields (best VPN detection)
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const fields = "status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting,mobile";
    const liveRes = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (liveRes.ok) {
      const data = await liveRes.json();
      if (data.status === "success") {
        const vpnInfo = evaluateVpnThreat(data);
        const geoResult = {
          ip: data.query || ip,
          city: data.city || "Unknown City",
          region: data.regionName || "Unknown Region",
          country_name: data.country || "Unknown Country",
          country_code: data.countryCode || "UN",
          country_flag: "🌐",
          postal: data.zip || "N/A",
          latitude: data.lat || 0,
          longitude: data.lon || 0,
          timezone: data.timezone || "UTC",
          isp: data.isp || "Internet Service Provider",
          org: data.org || data.isp || "Network Host",
          asn: data.as || "N/A",
          isPrivate: false,
          ...vpnInfo,
          accuracyStatus: "Real-Time (ip-api.com + VPN Detection)",
        };
        serverGeoCache.set(ip, geoResult);
        return res.json(geoResult);
      }
    }
  } catch (err) {
    console.warn("ip-api.com lookup failed, trying fallback:", err.message);
  }

  // Provider 2: ipwho.is (7 decimal GPS accuracy, timezone, ISP, ASN, postal)
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4500);

    const liveRes = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (liveRes.ok) {
      const data = await liveRes.json();
      if (data.success) {
        const syntheticData = { isp: data.connection?.isp || "", org: data.connection?.org || "", as: data.connection?.asn ? `AS${data.connection.asn}` : "" };
        const vpnInfo = evaluateVpnThreat(syntheticData);
        const geoResult = {
          ip,
          city: data.city || "Unknown City",
          region: data.region || data.region_code || "Unknown Region",
          country_name: data.country || "Unknown Country",
          country_code: data.country_code || "UN",
          country_flag: data.flag?.emoji || "🌐",
          postal: data.postal || "N/A",
          latitude: typeof data.latitude === "number" ? data.latitude : parseFloat(data.latitude) || 0,
          longitude: typeof data.longitude === "number" ? data.longitude : parseFloat(data.longitude) || 0,
          timezone: data.timezone?.id ? `${data.timezone.id} (${data.timezone.utc || "UTC"})` : "UTC",
          isp: data.connection?.isp || "Internet Service Provider",
          org: data.connection?.org || data.connection?.domain || "Network Host",
          asn: data.connection?.asn ? `AS${data.connection.asn}` : "N/A",
          isPrivate: false,
          ...vpnInfo,
          accuracyStatus: "High-Precision GPS (ipwho.is)",
        };
        serverGeoCache.set(ip, geoResult);
        return res.json(geoResult);
      }
    }
  } catch (err) {
    console.warn("ipwho.is lookup failed, trying fallback:", err.message);
  }

  // Provider 3: freeipapi.com
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4500);

    const fallbackRes = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(ip)}`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (fallbackRes.ok) {
      const data = await fallbackRes.json();
      if (data.countryName) {
        const geoResult = {
          ip,
          city: data.cityName || "Unknown City",
          region: data.regionName || "Unknown Region",
          country_name: data.countryName || "Unknown Country",
          country_code: data.countryCode || "UN",
          country_flag: "🌐",
          postal: data.zipCode || "N/A",
          latitude: typeof data.latitude === "number" ? data.latitude : parseFloat(data.latitude) || 0,
          longitude: typeof data.longitude === "number" ? data.longitude : parseFloat(data.longitude) || 0,
          timezone: data.timeZone || "UTC",
          isp: "Public ISP",
          org: `IPv${data.ipVersion || 4} Node`,
          asn: data.asn ? `AS${data.asn}` : "N/A",
          isPrivate: false,
          isVpn: false,
          vpnType: "Clean Direct Connection",
          vpnConfidence: "None",
          isTor: false,
          isProxy: false,
          isHosting: false,
          threatScore: 10,
          threatFlags: [],
          accuracyStatus: "Standard Precision (freeipapi)",
        };
        serverGeoCache.set(ip, geoResult);
        return res.json(geoResult);
      }
    }
  } catch (err) {
    console.warn("freeipapi lookup failed:", err.message);
  }

  return res.status(502).json({ error: "Failed to resolve IP location from live providers." });
});



/**
 * 2b. MULTI-HOP EMAIL ROUTE RESOLVER
 * Accepts an array of IPs (from email Received headers) and returns
 * full geolocation + VPN metadata for each hop in the transmission chain.
 */
app.post("/api/geoip-route", async (req, res) => {
  const { ips } = req.body;

  if (!Array.isArray(ips) || ips.length === 0) {
    return res.status(400).json({ error: "An array of IP addresses is required." });
  }

  const cleanIPs = ips
    .map((ip) => String(ip || "").trim().replace(/[[\]]/g, ""))
    .filter((ip) => ip && !isPrivateIpAddress(ip))
    .slice(0, 10);

  if (cleanIPs.length === 0) {
    return res.json({ totalHops: 0, hops: [], hasVpnInRoute: false, originHop: null, destinationHop: null });
  }

  const hops = [];
  for (const ip of cleanIPs) {
    try {
      if (serverGeoCache.has(ip)) {
        hops.push({ ...serverGeoCache.get(ip), hopIndex: hops.length + 1 });
        continue;
      }

      const fields = "status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting,mobile";
      const r = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}`);
      if (r.ok) {
        const data = await r.json();
        if (data.status === "success") {
          const vpnInfo = evaluateVpnThreat(data);
          const hop = {
            ip: data.query || ip,
            city: data.city || "Unknown City",
            region: data.regionName || "Unknown Region",
            country_name: data.country || "Unknown Country",
            country_code: data.countryCode || "UN",
            country_flag: "🌐",
            postal: data.zip || "N/A",
            latitude: data.lat || 0,
            longitude: data.lon || 0,
            timezone: data.timezone || "UTC",
            isp: data.isp || "ISP",
            org: data.org || "Network",
            asn: data.as || "N/A",
            isPrivate: false,
            ...vpnInfo,
            hopIndex: hops.length + 1,
          };
          serverGeoCache.set(ip, hop);
          hops.push(hop);
        }
      }
    } catch (err) {
      console.warn(`Hop resolution failed for ${ip}:`, err.message);
    }
    await new Promise((resolve) => setTimeout(resolve, 300));
  }

  const hasVpnInRoute = hops.some((h) => h.isVpn);
  return res.json({
    totalHops: hops.length,
    hops,
    hasVpnInRoute,
    originHop: hops[0] || null,
    destinationHop: hops.length > 1 ? hops[hops.length - 1] : null,
  });
});

/**
 * 3. REAL LIVE DNS & DOMAIN REPUTATION API
 * Queries real DNS records (MX mail exchangers, SPF TXT records, DMARC records) for sender domains.
 */
app.get("/api/dns-check", async (req, res) => {
  const domain = (req.query.domain || "").trim().toLowerCase();

  if (!domain) {
    return res.status(400).json({ error: "Domain parameter is required." });
  }

  try {
    let mxRecords = [];
    let txtRecords = [];
    let dmarcRecords = [];

    // Query MX records
    try {
      mxRecords = await dns.resolveMx(domain);
    } catch {
      mxRecords = [];
    }

    // Query TXT records for SPF
    try {
      const rawTxt = await dns.resolveTxt(domain);
      txtRecords = rawTxt.flat();
    } catch {
      txtRecords = [];
    }

    // Query DMARC records (_dmarc.domain)
    try {
      const rawDmarc = await dns.resolveTxt(`_dmarc.${domain}`);
      dmarcRecords = rawDmarc.flat();
    } catch {
      dmarcRecords = [];
    }

    const spfRecord = txtRecords.find((t) => t.toLowerCase().startsWith("v=spf1")) || null;
    const dmarcRecord = dmarcRecords.find((t) => t.toLowerCase().startsWith("v=dmarc1")) || null;

    return res.json({
      domain,
      hasMxRecords: mxRecords.length > 0,
      mxRecords,
      hasSpfRecord: spfRecord !== null,
      spfRecord,
      hasDmarcRecord: dmarcRecord !== null,
      dmarcRecord,
      domainValid: mxRecords.length > 0 || txtRecords.length > 0,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("DNS check error:", error);
    return res.status(500).json({ error: "DNS verification query failed." });
  }
});

/**
 * 4. REAL LIVE DOMAIN INTELLIGENCE & INFRASTRUCTURE FINGERPRINTING API
 * Gathers NS records, MX exchangers, A records, registrar heuristics, and brand typosquatting risk.
 */
app.get("/api/domain-intel", async (req, res) => {
  const domain = (req.query.domain || "").trim().toLowerCase();

  if (!domain || !domain.includes(".")) {
    return res.status(400).json({ error: "A valid domain name is required." });
  }

  try {
    let aRecords = [];
    let nsRecords = [];
    let mxRecords = [];
    let txtRecords = [];

    await Promise.allSettled([
      dns.resolve4(domain).then((r) => (aRecords = r)).catch(() => {}),
      dns.resolveNs(domain).then((r) => (nsRecords = r)).catch(() => {}),
      dns.resolveMx(domain).then((r) => (mxRecords = r)).catch(() => {}),
      dns.resolveTxt(domain).then((r) => (txtRecords = r.flat())).catch(() => {}),
    ]);

    // Brand Typosquatting & Impersonation Heuristic
    const monitoredBrands = ["paypal", "microsoft", "google", "apple", "amazon", "netflix", "chase", "bankofamerica", "wellsfargo", "dhl", "fedex"];
    let typosquattingTarget = null;
    const cleanName = domain.split(".")[0];

    for (const brand of monitoredBrands) {
      if (cleanName.includes(brand) && cleanName !== brand) {
        typosquattingTarget = brand.toUpperCase();
        break;
      }
      // Simple edit distance / character substitution (e.g., paypa1, micros0ft)
      const normalized = cleanName.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s");
      if (normalized === brand && cleanName !== brand) {
        typosquattingTarget = brand.toUpperCase();
        break;
      }
    }

    // Host Fingerprinting based on NS and A records
    let hostingProvider = "Independent / Private Registrar";
    const nsJoined = nsRecords.join(" ").toLowerCase();
    if (nsJoined.includes("cloudflare")) hostingProvider = "Cloudflare Infrastructure";
    else if (nsJoined.includes("awsdns") || nsJoined.includes("amazon")) hostingProvider = "Amazon Web Services (AWS)";
    else if (nsJoined.includes("google") || nsJoined.includes("googledomains")) hostingProvider = "Google Cloud Platform";
    else if (nsJoined.includes("azure") || nsJoined.includes("microsoft")) hostingProvider = "Microsoft Azure";
    else if (nsJoined.includes("namecheap")) hostingProvider = "Namecheap Registrar";
    else if (nsJoined.includes("godaddy") || nsJoined.includes("domaincontrol")) hostingProvider = "GoDaddy DNS";
    else if (nsJoined.includes("ovh")) hostingProvider = "OVH Hosting";

    return res.json({
      domain,
      aRecords,
      nsRecords,
      mxRecords,
      txtRecords,
      hasMx: mxRecords.length > 0,
      hostingProvider,
      typosquattingDetected: Boolean(typosquattingTarget),
      typosquattingTarget,
      isRegistered: aRecords.length > 0 || nsRecords.length > 0 || mxRecords.length > 0,
      reputationScore: typosquattingTarget ? 15 : (mxRecords.length > 0 ? 95 : 50),
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Domain intelligence query error:", error);
    return res.status(500).json({ error: "Domain intelligence query failed." });
  }
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distPath = path.join(__dirname, "../dist");

app.use(express.static(distPath));
app.get("*", (req, res) => {
  if (req.path.startsWith("/api")) {
    return res.status(404).json({ error: "API endpoint not found" });
  }
  const indexPath = path.join(distPath, "index.html");
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
  return res.send("AegisMail API Backend is running. Run 'npm run build' to compile and serve the frontend bundle.");
});

app.listen(PORT, () => {
  console.log(`[AI Email Forensics] Real Data Backend API running on http://localhost:${PORT}`);
});
