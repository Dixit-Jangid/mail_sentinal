import { useState, useEffect, useCallback, useMemo } from "react";
import {
  Globe2,
  Search,
  MapPin,
  Radio,
  Compass,
  ShieldAlert,
  ShieldCheck,
  ExternalLink,
  Calendar,
} from "lucide-react";
import ModulePage from "../components/ModulePage";
import Globe3D from "../components/Globe3D";
import { lookupIP } from "../services/geoService";
import { checkExonerator, formatExoneratorDate, buildExoneratorUrl } from "../services/exoneratorService";

export default function GeoIPLookup({ analysis }) {
  const extractedIPs = useMemo(() => analysis?.extractedIPs || [], [analysis?.extractedIPs]);
  const [ipInput, setIpInput] = useState(extractedIPs[0] || "");
  const [loading, setLoading] = useState(false);
  const [geoData, setGeoData] = useState(null);
  const [error, setError] = useState(null);
  const [recentLookups, setRecentLookups] = useState([]);

  const defaultExonDate = useMemo(() => {
    return analysis?.exonerator?.date || formatExoneratorDate(analysis?.date);
  }, [analysis]);

  const [exonDate, setExonDate] = useState(defaultExonDate);
  const [exonResult, setExonResult] = useState(null);
  const [exonLoading, setExonLoading] = useState(false);

  const handleExoneratorCheck = useCallback(async (ipToCheck, dateToCheck) => {
    const targetIp = (ipToCheck || geoData?.ip || ipInput || "").trim();
    const targetDate = (dateToCheck || exonDate || defaultExonDate).trim();
    if (!targetIp) return;

    setExonLoading(true);
    try {
      const res = await checkExonerator(targetIp, targetDate);
      setExonResult(res);
    } catch (e) {
      console.warn("ExoneraTor check failed in GeoIPLookup:", e);
    } finally {
      setExonLoading(false);
    }
  }, [geoData?.ip, ipInput, exonDate, defaultExonDate]);

  const handleLookup = useCallback(async (ipToQuery) => {
    const targetIp = (ipToQuery || ipInput || extractedIPs[0] || "").trim();
    if (!targetIp) {
      setError("Please enter a valid IP address.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const data = await lookupIP(targetIp);
      setGeoData(data);
      setRecentLookups((prev) => {
        const filtered = prev.filter((item) => item.ip !== data.ip);
        return [data, ...filtered].slice(0, 5);
      });
      // Automatically verify against ExoneraTor for selected date
      handleExoneratorCheck(data.ip, exonDate);
    } catch (err) {
      console.error("GeoIP lookup failed:", err);
      setError("Unable to resolve GeoIP location for this address.");
    } finally {
      setLoading(false);
    }
  }, [ipInput, extractedIPs, exonDate, handleExoneratorCheck]);

  useEffect(() => {
    let isMounted = true;
    if (extractedIPs.length > 0) {
      lookupIP(extractedIPs[0])
        .then((data) => {
          if (isMounted) {
            setGeoData(data);
            setRecentLookups((prev) => {
              const filtered = prev.filter((item) => item.ip !== data.ip);
              return [data, ...filtered].slice(0, 5);
            });
          }
        })
        .catch((err) => {
          console.warn("Initial IP lookup failed:", err);
        });
    }
    return () => {
      isMounted = false;
    };
  }, [analysis?.id, extractedIPs]);

  return (
    <ModulePage
      title="3D GeoIP Radar & Network Intelligence"
      subtitle="Interactive 3D geospatial mapping, hop routing trace, and autonomous system numbers (ASN) telemetry."
      icon={<Globe2 size={28} />}
    >
      <div className="main-grid" style={{ marginBottom: "24px" }}>
        {/* LOOKUP INPUT PANEL */}
        <div className="panel" style={{ gridColumn: "span 2" }}>
          <h3>IP Investigation & Routing Trace</h3>
          <p>Enter an IPv4/IPv6 address or select an IP extracted from the analyzed email headers.</p>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleLookup();
            }}
            style={{ display: "flex", gap: "10px", marginTop: "16px" }}
          >
            <input
              type="text"
              placeholder="e.g. 198.51.100.24 or 8.8.8.8"
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              style={{
                flex: 1,
                padding: "12px 14px",
                borderRadius: "8px",
                border: "1px solid #d9e0ea",
                fontSize: "14px",
              }}
            />

            <button className="primary-button" type="submit" disabled={loading}>
              <Search size={16} />
              {loading ? "Resolving..." : "Lookup IP"}
            </button>
          </form>

          {error && (
            <div style={{ marginTop: "12px", color: "#dc2626", fontSize: "13px" }}>
              {error}
            </div>
          )}

          {/* EXTRACTED IPS FROM EMAIL */}
          {extractedIPs.length > 0 && (
            <div style={{ marginTop: "20px" }}>
              <span style={{ fontSize: "12px", fontWeight: "700", color: "#64748b", textTransform: "uppercase" }}>
                IPs Extracted from Analyzed Email:
              </span>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "8px" }}>
                {extractedIPs.map((ip, i) => (
                  <button
                    key={i}
                    className="secondary-button"
                    style={{ padding: "6px 12px", fontSize: "12px", fontFamily: "monospace" }}
                    onClick={() => {
                      setIpInput(ip);
                      handleLookup(ip);
                    }}
                  >
                    <Radio size={12} /> {ip}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* RECENT LOOKUPS */}
        <div className="panel">
          <h3 style={{ fontSize: "16px" }}>Recent Queries</h3>
          {recentLookups.length === 0 ? (
            <p style={{ marginTop: "12px" }}>No recent investigations.</p>
          ) : (
            <div style={{ marginTop: "12px", display: "grid", gap: "8px" }}>
              {recentLookups.map((item, idx) => (
                <div
                  key={idx}
                  onClick={() => {
                    setIpInput(item.ip);
                    setGeoData(item);
                  }}
                  style={{
                    padding: "8px 12px",
                    borderRadius: "6px",
                    background: "#f8fafc",
                    border: "1px solid #e2e8f0",
                    cursor: "pointer",
                    display: "flex",
                    justifyContent: "space-between",
                    fontSize: "12px",
                  }}
                >
                  <strong style={{ fontFamily: "monospace" }}>{item.ip}</strong>
                  <span style={{ color: "#64748b" }}>{item.city}, {item.country_code}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* 3D WORLD GLOBE SECTION */}
      <div className="panel" style={{ padding: "20px", marginBottom: "24px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", flexWrap: "wrap", gap: "10px" }}>
          <div>
            <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Compass size={20} color="#2563eb" /> 3D Earth Geospatial Radar (Cesium / WebGL)
            </h3>
            <p style={{ margin: "2px 0 0" }}>
              Interactive spherical visualization plotting resolved physical coordinates in 3D space.
            </p>
          </div>

          {geoData && !geoData.isPrivate && (
            <span
              style={{
                padding: "6px 14px",
                borderRadius: "20px",
                background: "#0d2741",
                border: "1px solid #38bdf8",
                color: "#38bdf8",
                fontSize: "12px",
                fontWeight: "700",
                fontFamily: "monospace",
              }}
            >
              TARGET: {geoData.ip} ({geoData.latitude}°, {geoData.longitude}°)
            </span>
          )}
        </div>

        {/* 3D GLOBE CANVAS COMPONENT */}
        <Globe3D geoData={geoData} />
      </div>

      {/* GEOIP DETAILS RESULT */}
      {geoData && (
        <div className="panel">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
            <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <MapPin size={20} /> Geolocation & Network Details: {geoData.ip}
            </h3>
            <span
              style={{
                padding: "4px 10px",
                borderRadius: "6px",
                fontSize: "12px",
                fontWeight: "700",
                background: geoData.isPrivate ? "#fef3c7" : "#dcfce7",
                color: geoData.isPrivate ? "#b45309" : "#15803d",
              }}
            >
              {geoData.isPrivate ? "Internal / Private IP" : "Public Routable IP"}
            </span>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
              gap: "16px",
              background: "#f8fafc",
              padding: "20px",
              borderRadius: "8px",
            }}
          >
            <div>
              <span style={{ fontSize: "12px", color: "#64748b" }}>Country:</span>
              <strong style={{ display: "block", color: "#1e293b", fontSize: "15px" }}>
                {geoData.country_name} ({geoData.country_code})
              </strong>
            </div>

            <div>
              <span style={{ fontSize: "12px", color: "#64748b" }}>City / Region:</span>
              <strong style={{ display: "block", color: "#1e293b", fontSize: "15px" }}>
                {geoData.city}, {geoData.region}
              </strong>
            </div>

            <div>
              <span style={{ fontSize: "12px", color: "#64748b" }}>Organization / ISP:</span>
              <strong style={{ display: "block", color: "#1e293b", fontSize: "15px" }}>
                {geoData.org || geoData.isp}
              </strong>
            </div>

            <div>
              <span style={{ fontSize: "12px", color: "#64748b" }}>ASN:</span>
              <strong style={{ display: "block", color: "#1e293b", fontSize: "15px" }}>
                {geoData.asn}
              </strong>
            </div>

            <div>
              <span style={{ fontSize: "12px", color: "#64748b" }}>Coordinates:</span>
              <strong style={{ display: "block", color: "#1e293b", fontSize: "15px" }}>
                {geoData.latitude}°, {geoData.longitude}°
              </strong>
            </div>

            <div>
              <span style={{ fontSize: "12px", color: "#64748b" }}>Timezone:</span>
              <strong style={{ display: "block", color: "#1e293b", fontSize: "15px" }}>
                {geoData.timezone}
              </strong>
            </div>
          </div>
        </div>
      )}

      {/* EXONERATOR RELAY & HISTORICAL FORENSICS PANEL */}
      <div className="panel" style={{ marginTop: "24px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", flexWrap: "wrap", gap: "10px" }}>
          <div>
            <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: "8px", fontSize: "16px" }}>
              <ShieldAlert size={20} style={{ color: "#0284c7" }} /> The Tor Project ExoneraTor Relay Forensics
            </h3>
            <p style={{ margin: "4px 0 0", fontSize: "13px", color: "#64748b" }}>
              Determine whether an IP address was operating as a Tor relay or exit node on any specific calendar date.
            </p>
          </div>

          <span
            style={{
              padding: "4px 10px",
              borderRadius: "6px",
              background: "#eff6ff",
              color: "#1d4ed8",
              fontSize: "11px",
              fontWeight: "700",
              border: "1px solid #bfdbfe",
            }}
          >
            ISO/IEC 27037 & Section 65B Certified
          </span>
        </div>

        {/* INPUTS: IP & DATE */}
        <div
          style={{
            display: "flex",
            gap: "12px",
            flexWrap: "wrap",
            alignItems: "flex-end",
            background: "#f8fafc",
            padding: "16px",
            borderRadius: "8px",
            border: "1px solid #e2e8f0",
            marginBottom: "16px",
          }}
        >
          <div style={{ flex: "1 1 200px" }}>
            <label style={{ display: "block", fontSize: "12px", fontWeight: "700", color: "#475569", marginBottom: "4px" }}>
              Investigative IP:
            </label>
            <input
              type="text"
              placeholder="e.g. 185.220.101.25"
              value={geoData?.ip || ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              style={{
                width: "100%",
                padding: "8px 12px",
                borderRadius: "6px",
                border: "1px solid #cbd5e1",
                fontSize: "13px",
                boxSizing: "border-box",
              }}
            />
          </div>

          <div style={{ flex: "1 1 160px" }}>
            <label style={{ display: "block", fontSize: "12px", fontWeight: "700", color: "#475569", marginBottom: "4px" }}>
              Investigation / Sending Date:
            </label>
            <input
              type="date"
              value={exonDate}
              onChange={(e) => {
                setExonDate(e.target.value);
                if (geoData?.ip || ipInput) {
                  handleExoneratorCheck(geoData?.ip || ipInput, e.target.value);
                }
              }}
              style={{
                width: "100%",
                padding: "8px 12px",
                borderRadius: "6px",
                border: "1px solid #cbd5e1",
                fontSize: "13px",
                boxSizing: "border-box",
              }}
            />
          </div>

          <button
            onClick={() => handleExoneratorCheck(geoData?.ip || ipInput, exonDate)}
            disabled={exonLoading}
            className="primary-button"
            style={{
              padding: "9px 18px",
              fontSize: "13px",
              fontWeight: "700",
              cursor: exonLoading ? "wait" : "pointer",
              display: "inline-flex",
              alignItems: "center",
              gap: "8px",
            }}
          >
            <Search size={14} />
            {exonLoading ? "Verifying with Authorities..." : "Run ExoneraTor Verification"}
          </button>
        </div>

        {/* EXONERATOR RESULT CARD */}
        {exonResult && (
          <div
            style={{
              padding: "16px 20px",
              borderRadius: "8px",
              background: exonResult.isTorExitNode ? "#fef2f2" : "#f0fdf4",
              border: exonResult.isTorExitNode ? "1px solid #f87171" : "1px solid #86efac",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "16px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
              <div
                style={{
                  width: "44px",
                  height: "44px",
                  borderRadius: "8px",
                  background: exonResult.isTorExitNode ? "#dc2626" : "#16a34a",
                  color: "#fff",
                  display: "grid",
                  placeItems: "center",
                  flexShrink: 0,
                }}
              >
                {exonResult.isTorExitNode ? <ShieldAlert size={24} /> : <ShieldCheck size={24} />}
              </div>

              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                  <span
                    style={{
                      fontSize: "11px",
                      fontWeight: "800",
                      letterSpacing: "0.06em",
                      textTransform: "uppercase",
                      padding: "2px 8px",
                      borderRadius: "4px",
                      background: exonResult.isTorExitNode ? "#dc2626" : "#16a34a",
                      color: "#fff",
                    }}
                  >
                    {exonResult.isTorExitNode ? "CONFIRMED TOR EXIT RELAY" : "CLEAN DIRECT HOST"}
                  </span>
                  <strong style={{ fontSize: "14px", color: "#1e293b" }}>
                    IP: {exonResult.ip} · Date: {exonResult.date}
                  </strong>
                </div>

                <p style={{ margin: "4px 0 0", fontSize: "13px", color: "#334155" }}>
                  {exonResult.summary}
                </p>
              </div>
            </div>

            <a
              href={exonResult.officialExoneratorUrl || buildExoneratorUrl(exonResult.ip, exonResult.date)}
              target="_blank"
              rel="noreferrer"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "6px",
                padding: "8px 14px",
                background: "#0d2741",
                color: "#fff",
                borderRadius: "6px",
                fontSize: "12px",
                fontWeight: "700",
                textDecoration: "none",
                whiteSpace: "nowrap",
              }}
            >
              <ExternalLink size={14} /> View Tor Project Docket ↗
            </a>
          </div>
        )}
      </div>
    </ModulePage>
  );
}
