/**
 * Service to lookup real-time geographic and network information for an IP address.
 */

const RESERVED_RANGES = [
  { prefix: "10.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "172.16.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "192.168.", type: "Private Network (RFC 1918)", country: "Internal Network", city: "Local Subnet" },
  { prefix: "127.", type: "Loopback Interface (RFC 1122)", country: "Localhost", city: "Host Device" },
];

export async function lookupIP(ip) {
  if (!ip || typeof ip !== "string") {
    throw new Error("Invalid IP address");
  }

  const cleanIp = ip.trim();

  // Check for private / internal addresses
  for (const range of RESERVED_RANGES) {
    if (cleanIp.startsWith(range.prefix)) {
      return {
        ip: cleanIp,
        city: range.city,
        region: "Internal Subnet",
        country_name: range.country,
        country_code: "LOCAL",
        postal: "N/A",
        latitude: 0,
        longitude: 0,
        timezone: "UTC",
        isp: range.type,
        org: "Private Network",
        asn: "RFC 1918",
        isPrivate: true,
      };
    }
  }

  // 1. Try local backend API
  try {
    const response = await fetch(`/api/geoip?ip=${encodeURIComponent(cleanIp)}`);
    if (response.ok) {
      const data = await response.json();
      return data;
    }
  } catch (err) {
    console.warn("Backend GeoIP endpoint unreachable, trying direct live query:", err);
  }

  // 2. Direct live query fallback via freeipapi
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const liveRes = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(cleanIp)}`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (liveRes.ok) {
      const data = await liveRes.json();
      return {
        ip: cleanIp,
        city: data.cityName || "Unknown City",
        region: data.regionName || "Unknown Region",
        country_name: data.countryName || "Unknown Country",
        country_code: data.countryCode || "UN",
        postal: data.zipCode || "N/A",
        latitude: data.latitude || 0,
        longitude: data.longitude || 0,
        timezone: data.timeZone || "UTC",
        isp: "Internet Service Provider",
        org: data.ipVersion ? `IPv${data.ipVersion} Network` : "Network Host",
        asn: data.asn ? `AS${data.asn}` : "N/A",
        isPrivate: false,
      };
    }
  } catch (err) {
    console.error("Direct GeoIP lookup failed:", err);
    throw new Error(`Unable to resolve geolocation for IP ${cleanIp}. Please check your connection.`, { cause: err });
  }

  throw new Error(`Unable to retrieve real geolocation for IP ${cleanIp}`);
}
