import { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import { RotateCw, ZoomIn, ZoomOut, Crosshair, MapPin, Shield, ShieldAlert } from "lucide-react";

// Arc colour palette per hop index
const ARC_COLORS = ["#ff4444", "#ffaa00", "#00e5ff", "#00ff88", "#aa44ff", "#ff6699", "#44aaff"];
const PARTICLE_COLORS = ["#ff8888", "#ffcc66", "#66eeff", "#66ffbb", "#cc88ff", "#ff99bb", "#88ccff"];

/**
 * Converts geographic Lat/Lon to 3D Cartesian coordinates on a sphere.
 */
function latLonToVector3(lat, lon, radius) {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  const x = -(radius * Math.sin(phi) * Math.cos(theta));
  const z = radius * Math.sin(phi) * Math.sin(theta);
  const y = radius * Math.cos(phi);
  return new THREE.Vector3(x, y, z);
}

/**
 * Creates a smooth parabolic Bezier arc between two points on the sphere.
 */
function createArcCurve(from, to, radius = 1.0, elevation = 0.4) {
  const mid = from.clone().add(to).multiplyScalar(0.5);
  const dist = from.distanceTo(to);
  const liftAmount = radius + elevation * (0.5 + dist * 0.6);
  mid.normalize().multiplyScalar(liftAmount);
  return new THREE.QuadraticBezierCurve3(from, mid, to);
}

/**
 * Globe3D — Interactive 3D WebGL Earth with:
 *   - Globe STATIC by default (autoRotate = false, user can enable)
 *   - Multi-hop Bezier arc flight paths between email relay IPs
 *   - Glowing animated particles flying along each arc
 *   - VPN / Proxy / Tor detection HUD badge
 *   - Interactive hop selector panel
 *
 * Props:
 *   geoData   — single IP lookup result (single-point mode)
 *   routeHops — array of hop objects from /api/geoip-route (multi-hop mode)
 */
export default function Globe3D({ geoData, routeHops = [] }) {
  const mountRef = useRef(null);
  // Globe is STILL by default — user must click the rotate button to spin it
  const [autoRotate, setAutoRotate] = useState(false);
  const autoRotateRef = useRef(false);
  const [zoomLevel, setZoomLevel] = useState(2.8);
  const [activeHopIdx, setActiveHopIdx] = useState(0);

  const sceneRef = useRef(null);
  const rendererRef = useRef(null);
  const cameraRef = useRef(null);
  const globeGroupRef = useRef(null);
  const markerGroupRef = useRef(null);
  const arcGroupRef = useRef(null);
  const isDraggingRef = useRef(false);
  const previousMousePositionRef = useRef({ x: 0, y: 0 });
  const animFrameRef = useRef(null);

  useEffect(() => { autoRotateRef.current = autoRotate; }, [autoRotate]);

  const targetLat = typeof geoData?.latitude === "number" ? geoData.latitude : 0;
  const targetLon = typeof geoData?.longitude === "number" ? geoData.longitude : 0;
  const hasTarget = geoData && !geoData.isPrivate && (targetLat !== 0 || targetLon !== 0);

  // Collect valid routable hops
  const validHops = routeHops.filter((h) => h && !h.isPrivate && (h.latitude || h.longitude));

  // VPN status across all hops
  const detectedVpnHop = validHops.find((h) => h.isVpn || h.isTor || h.isProxy);
  const hasVpnInRoute = Boolean(detectedVpnHop);

  // Scene setup (runs once)
  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const width = container.clientWidth || 600;
    const height = container.clientHeight || 450;

    const scene = new THREE.Scene();
    scene.background = new THREE.Color("#020d1a");
    sceneRef.current = scene;

    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.z = 2.8;
    cameraRef.current = camera;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 0.8;
    container.innerHTML = "";
    container.appendChild(renderer.domElement);
    rendererRef.current = renderer;
    let disposed = false;
    const earthTextures = [];

    const globeGroup = new THREE.Group();
    scene.add(globeGroup);
    globeGroupRef.current = globeGroup;

    const markerGroup = new THREE.Group();
    globeGroup.add(markerGroup);
    markerGroupRef.current = markerGroup;

    const arcGroup = new THREE.Group();
    globeGroup.add(arcGroup);
    arcGroupRef.current = arcGroup;

    // Stars
    const starsGeo = new THREE.BufferGeometry();
    const starsCount = 3000;
    const starPos = new Float32Array(starsCount * 3);
    for (let i = 0; i < starsCount * 3; i += 3) {
      const r = 80 + Math.random() * 120;
      const t = Math.random() * 2 * Math.PI;
      const p = Math.acos(2 * Math.random() - 1);
      starPos[i] = r * Math.sin(p) * Math.cos(t);
      starPos[i + 1] = r * Math.sin(p) * Math.sin(t);
      starPos[i + 2] = r * Math.cos(p);
    }
    starsGeo.setAttribute("position", new THREE.BufferAttribute(starPos, 3));
    const starsMat = new THREE.PointsMaterial({ color: "#e8f4fd", size: 0.3, sizeAttenuation: true, transparent: true, opacity: 0.8 });
    scene.add(new THREE.Points(starsGeo, starsMat));

    // Lighting
    scene.add(new THREE.AmbientLight("#d0e8ff", 0.3));
    const sunLight = new THREE.DirectionalLight("#fff5e0", 2);
    sunLight.position.set(5, 3, 5);
    scene.add(sunLight);
    const fillLight = new THREE.DirectionalLight("#2060ff", 0.3);
    fillLight.position.set(-5, -2, -3);
    scene.add(fillLight);

    const radius = 1.0;

    // Atmospheric glow
    const glowGeo = new THREE.SphereGeometry(radius * 1.18, 64, 64);
    const glowMat = new THREE.ShaderMaterial({
      vertexShader: `
        varying vec3 vNormal;
        void main() {
          vNormal = normalize(normalMatrix * normal);
          gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
        }
      `,
      fragmentShader: `
        varying vec3 vNormal;
        void main() {
          float intensity = pow(0.72 - dot(vNormal, vec3(0.0, 0.0, 1.0)), 3.5);
          vec3 glowColor = vec3(0.2, 0.5, 1.0);
          gl_FragColor = vec4(glowColor, 1.0) * intensity * 0.9;
        }
      `,
      blending: THREE.AdditiveBlending,
      side: THREE.BackSide,
      transparent: true,
      depthWrite: false,
    });
    scene.add(new THREE.Mesh(glowGeo, glowMat));

    // Earth
    const earthGeo = new THREE.SphereGeometry(radius, 64, 64);
    const earthMaterial = new THREE.MeshPhongMaterial({
      color: "#d9e5f2",
      specular: new THREE.Color("#647b99"),
      shininess: 22,
    });
    const earthMesh = new THREE.Mesh(earthGeo, earthMaterial);
    globeGroup.add(earthMesh);

    const textureLoader = new THREE.TextureLoader();
    const loadEarthTexture = (filename, applyTexture) => {
      textureLoader.load(
        `${import.meta.env.BASE_URL}${filename}`,
        (texture) => {
          if (disposed) {
            texture.dispose();
            return;
          }
          earthTextures.push(texture);
          applyTexture(texture);
          earthMaterial.needsUpdate = true;
        },
        undefined,
        (error) => console.error(`Unable to load Earth texture "${filename}":`, error)
      );
    };

    loadEarthTexture("earth-atmos-2048.jpg", (texture) => {
      texture.colorSpace = THREE.SRGBColorSpace;
      earthMaterial.map = texture;
    });
    loadEarthTexture("earth-normal-2048.jpg", (texture) => {
      earthMaterial.normalMap = texture;
      earthMaterial.normalScale.set(0.45, 0.45);
    });
    loadEarthTexture("earth-specular-2048.jpg", (texture) => {
      earthMaterial.specularMap = texture;
    });

    // Mouse drag
    const domElement = renderer.domElement;
    const onMouseDown = (e) => { isDraggingRef.current = true; previousMousePositionRef.current = { x: e.clientX, y: e.clientY }; };
    const onMouseMove = (e) => {
      if (!isDraggingRef.current || !globeGroupRef.current) return;
      const dx = e.clientX - previousMousePositionRef.current.x;
      const dy = e.clientY - previousMousePositionRef.current.y;
      globeGroupRef.current.rotation.y += dx * 0.005;
      globeGroupRef.current.rotation.x = Math.max(-Math.PI / 2.2, Math.min(Math.PI / 2.2, globeGroupRef.current.rotation.x + dy * 0.005));
      previousMousePositionRef.current = { x: e.clientX, y: e.clientY };
    };
    const onMouseUp = () => { isDraggingRef.current = false; };

    // Scroll zoom
    const onWheel = (e) => {
      e.preventDefault();
      const newZ = Math.max(1.6, Math.min(4.5, cameraRef.current.position.z + (e.deltaY > 0 ? 0.15 : -0.15)));
      cameraRef.current.position.z = newZ;
      setZoomLevel(newZ);
    };

    domElement.addEventListener("mousedown", onMouseDown);
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    domElement.addEventListener("wheel", onWheel, { passive: false });

    // Resize
    const onResize = () => {
      if (!container || !rendererRef.current || !cameraRef.current) return;
      const w = container.clientWidth;
      const h = container.clientHeight;
      cameraRef.current.aspect = w / h;
      cameraRef.current.updateProjectionMatrix();
      rendererRef.current.setSize(w, h);
    };
    window.addEventListener("resize", onResize);

    // Animation loop
    const clock = new THREE.Clock();
    const animate = () => {
      animFrameRef.current = requestAnimationFrame(animate);
      const elapsed = clock.getElapsedTime();

      // Auto-rotate only when explicitly enabled (default: OFF)
      if (!isDraggingRef.current && globeGroupRef.current && autoRotateRef.current) {
        globeGroupRef.current.rotation.y += 0.0015;
      }

      // Animate pulse rings
      if (markerGroupRef.current) {
        markerGroupRef.current.children.forEach((child) => {
          if (child.userData?.isPulseRing) {
            const scale = 1 + ((elapsed * 1.5) % 1.8);
            child.scale.set(scale, scale, scale);
            if (child.material) child.material.opacity = Math.max(0, 1 - scale / 2.8);
          }
        });
      }

      // Animate arc particles and glow pulse
      if (arcGroupRef.current) {
        arcGroupRef.current.children.forEach((child) => {
          if (child.userData?.isParticle && child.userData.curve) {
            child.userData.t = (child.userData.t + child.userData.speed) % 1;
            const pt = child.userData.curve.getPoint(child.userData.t);
            child.position.copy(pt);
          }
          if (child.userData?.isArcLine && child.material) {
            child.material.opacity = 0.5 + 0.35 * Math.sin(elapsed * 2.5 + (child.userData.phaseOffset || 0));
          }
        });
      }

      renderer.render(scene, camera);
    };
    animate();

    return () => {
      cancelAnimationFrame(animFrameRef.current);
      domElement.removeEventListener("mousedown", onMouseDown);
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
      domElement.removeEventListener("wheel", onWheel);
      window.removeEventListener("resize", onResize);
      disposed = true;
      earthTextures.forEach((texture) => texture.dispose());
      earthGeo.dispose();
      earthMaterial.dispose();
      starsGeo.dispose();
      starsMat.dispose();
      glowGeo.dispose(); glowMat.dispose(); renderer.dispose();
    };
  }, []);

  // Single-point marker (when no route hops)
  useEffect(() => {
    const markerGroup = markerGroupRef.current;
    const globeGroup = globeGroupRef.current;
    if (!markerGroup || !globeGroup) return;

    while (markerGroup.children.length > 0) {
      const child = markerGroup.children[0];
      if (child.geometry) child.geometry.dispose();
      if (child.material) child.material.dispose();
      markerGroup.remove(child);
    }

    if (!hasTarget || validHops.length > 0) return;

    const radius = 1.0;
    const pos = latLonToVector3(targetLat, targetLon, radius);
    const dir = pos.clone().normalize();

    const beacon = new THREE.Mesh(new THREE.SphereGeometry(0.022, 16, 16), new THREE.MeshBasicMaterial({ color: "#ff3333" }));
    beacon.position.copy(pos);
    markerGroup.add(beacon);

    const core = new THREE.Mesh(new THREE.SphereGeometry(0.01, 8, 8), new THREE.MeshBasicMaterial({ color: "#ffffff" }));
    core.position.copy(pos);
    markerGroup.add(core);

    const beamEnd = pos.clone().add(dir.clone().multiplyScalar(0.22));
    markerGroup.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([pos, beamEnd]), new THREE.LineBasicMaterial({ color: "#ff6666", linewidth: 2 })));

    const ring = new THREE.Mesh(new THREE.RingGeometry(0.018, 0.04, 32), new THREE.MeshBasicMaterial({ color: "#ff3333", side: THREE.DoubleSide, transparent: true, opacity: 0.85 }));
    ring.position.copy(pos.clone().multiplyScalar(1.001));
    ring.lookAt(pos.clone().multiplyScalar(2));
    ring.userData = { isPulseRing: true };
    markerGroup.add(ring);

    globeGroup.rotation.y = -((targetLon + 90) * (Math.PI / 180));
    globeGroup.rotation.x = Math.max(-Math.PI / 3, Math.min(Math.PI / 3, (targetLat - 15) * (Math.PI / 180)));
  }, [geoData?.ip, targetLat, targetLon, hasTarget, validHops.length]);

  // Multi-hop arc flight paths
  useEffect(() => {
    const markerGroup = markerGroupRef.current;
    const arcGroup = arcGroupRef.current;
    const globeGroup = globeGroupRef.current;
    if (!markerGroup || !arcGroup || !globeGroup) return;

    [markerGroup, arcGroup].forEach((group) => {
      while (group.children.length > 0) {
        const child = group.children[0];
        if (child.geometry) child.geometry.dispose();
        if (child.material) child.material.dispose();
        group.remove(child);
      }
    });

    if (validHops.length === 0) return;

    const radius = 1.0;

    validHops.forEach((hop, idx) => {
      const pos = latLonToVector3(hop.latitude, hop.longitude, radius);
      const color = ARC_COLORS[idx % ARC_COLORS.length];
      const isVpn = hop.isVpn || hop.isTor || hop.isProxy;

      // Beacon
      const beacon = new THREE.Mesh(new THREE.SphereGeometry(isVpn ? 0.030 : 0.022, 16, 16), new THREE.MeshBasicMaterial({ color: isVpn ? "#ff4444" : color }));
      beacon.position.copy(pos);
      beacon.userData = { hopIdx: idx };
      markerGroup.add(beacon);

      // Core
      const core = new THREE.Mesh(new THREE.SphereGeometry(0.01, 8, 8), new THREE.MeshBasicMaterial({ color: "#ffffff" }));
      core.position.copy(pos);
      markerGroup.add(core);

      // Beam
      const dir = pos.clone().normalize();
      const beamEnd = pos.clone().add(dir.multiplyScalar(isVpn ? 0.35 : 0.20));
      markerGroup.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([pos, beamEnd]), new THREE.LineBasicMaterial({ color, linewidth: 2 })));

      // Pulse ring
      const ring = new THREE.Mesh(new THREE.RingGeometry(0.018, 0.04, 32), new THREE.MeshBasicMaterial({ color: isVpn ? "#ff4444" : color, side: THREE.DoubleSide, transparent: true, opacity: 0.85 }));
      ring.position.copy(pos.clone().multiplyScalar(1.001));
      ring.lookAt(pos.clone().multiplyScalar(2));
      ring.userData = { isPulseRing: true };
      markerGroup.add(ring);

      // Arc from previous hop
      if (idx > 0) {
        const prevHop = validHops[idx - 1];
        const prevPos = latLonToVector3(prevHop.latitude, prevHop.longitude, radius);
        const curve = createArcCurve(prevPos, pos, radius, 0.45);
        const points = curve.getPoints(80);

        // Main arc line
        const arcLine = new THREE.Line(new THREE.BufferGeometry().setFromPoints(points), new THREE.LineBasicMaterial({ color: ARC_COLORS[(idx - 1) % ARC_COLORS.length], transparent: true, opacity: 0.75, linewidth: 2 }));
        arcLine.userData = { isArcLine: true, phaseOffset: idx * 1.2 };
        arcGroup.add(arcLine);

        // Glow arc
        const glowArc = new THREE.Line(new THREE.BufferGeometry().setFromPoints(points), new THREE.LineBasicMaterial({ color: PARTICLE_COLORS[(idx - 1) % PARTICLE_COLORS.length], transparent: true, opacity: 0.25, linewidth: 4 }));
        glowArc.userData = { isArcLine: true, phaseOffset: idx * 1.2 + 0.5 };
        arcGroup.add(glowArc);

        // Animated particles
        for (let p = 0; p < 3; p++) {
          const particle = new THREE.Mesh(new THREE.SphereGeometry(0.013, 8, 8), new THREE.MeshBasicMaterial({ color: PARTICLE_COLORS[(idx - 1) % PARTICLE_COLORS.length], transparent: true, opacity: 0.9 }));
          const startT = p / 3;
          particle.position.copy(curve.getPoint(startT));
          particle.userData = { isParticle: true, curve, t: startT, speed: 0.004 + Math.random() * 0.003 };
          arcGroup.add(particle);
        }
      }
    });

    // Orient globe to show midpoint of path
    const firstHop = validHops[0];
    const lastHop = validHops[validHops.length - 1];
    const midLon = (firstHop.longitude + lastHop.longitude) / 2;
    const midLat = (firstHop.latitude + lastHop.latitude) / 2;
    globeGroup.rotation.y = -((midLon + 90) * (Math.PI / 180));
    globeGroup.rotation.x = Math.max(-Math.PI / 3, Math.min(Math.PI / 3, (midLat - 15) * (Math.PI / 180)));
  }, [validHops.length, routeHops]); // eslint-disable-line react-hooks/exhaustive-deps

  // Focus on specific hop
  const focusHop = (idx) => {
    setActiveHopIdx(idx);
    const hop = validHops[idx];
    if (!hop || !globeGroupRef.current) return;
    globeGroupRef.current.rotation.y = -((hop.longitude + 90) * (Math.PI / 180));
    globeGroupRef.current.rotation.x = Math.max(-Math.PI / 3, Math.min(Math.PI / 3, (hop.latitude - 15) * (Math.PI / 180)));
  };

  const handleZoom = (delta) => {
    if (!cameraRef.current) return;
    const newZ = Math.max(1.6, Math.min(4.5, cameraRef.current.position.z + delta));
    cameraRef.current.position.z = newZ;
    setZoomLevel(newZ);
  };

  const resetView = () => {
    if (!cameraRef.current || !globeGroupRef.current) return;
    cameraRef.current.position.z = 2.8;
    setZoomLevel(2.8);
    if (validHops.length > 0) {
      const firstHop = validHops[0];
      const lastHop = validHops[validHops.length - 1];
      globeGroupRef.current.rotation.y = -(((firstHop.longitude + lastHop.longitude) / 2 + 90) * (Math.PI / 180));
      globeGroupRef.current.rotation.x = Math.max(-Math.PI / 3, Math.min(Math.PI / 3, ((firstHop.latitude + lastHop.latitude) / 2 - 15) * (Math.PI / 180)));
    } else if (hasTarget) {
      globeGroupRef.current.rotation.y = -((targetLon + 90) * (Math.PI / 180));
      globeGroupRef.current.rotation.x = Math.max(-Math.PI / 3, Math.min(Math.PI / 3, (targetLat - 15) * (Math.PI / 180)));
    } else {
      globeGroupRef.current.rotation.set(0, 0, 0);
    }
  };

  const ctrlStyle = (active) => ({
    background: active ? "rgba(37, 99, 235, 0.85)" : "rgba(2, 13, 26, 0.85)",
    backdropFilter: "blur(6px)",
    border: `1px solid ${active ? "rgba(37,99,235,0.7)" : "rgba(56, 189, 248, 0.35)"}`,
    color: "#e0f2fe",
    width: "36px",
    height: "36px",
    borderRadius: "6px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    cursor: "pointer",
  });

  const activeHop = validHops[activeHopIdx];

  return (
    <div style={{ position: "relative", width: "100%", height: "520px", background: "#020d1a", borderRadius: "12px", overflow: "hidden", border: "1px solid #0f2d4a", boxShadow: "0 16px 40px rgba(0,0,0,0.5)" }}>
      <div ref={mountRef} style={{ width: "100%", height: "100%", cursor: "grab" }} />

      {/* HUD TOP-LEFT */}
      <div style={{ position: "absolute", top: "16px", left: "16px", pointerEvents: "none", zIndex: 10 }}>
        {/* Title */}
        <div style={{ display: "inline-flex", alignItems: "center", gap: "8px", background: "rgba(2,13,26,0.82)", backdropFilter: "blur(10px)", border: "1px solid rgba(56,189,248,0.4)", padding: "6px 14px", borderRadius: "6px", color: "#38bdf8", fontSize: "11px", fontWeight: "700", letterSpacing: "0.08em", textTransform: "uppercase" }}>
          <Crosshair size={13} />
          {validHops.length > 1 ? `Email Transmission · ${validHops.length} Hops` : "3D Geolocation Radar · Satellite Imagery"}
        </div>

        {/* VPN Detection Badge */}
        {validHops.length > 0 && (
          <div style={{ marginTop: "8px", display: "inline-flex", alignItems: "center", gap: "8px", background: hasVpnInRoute ? "rgba(127,0,0,0.85)" : "rgba(0,40,20,0.85)", backdropFilter: "blur(10px)", border: `1px solid ${hasVpnInRoute ? "#ef4444" : "#10b981"}`, padding: "6px 14px", borderRadius: "6px", color: hasVpnInRoute ? "#fca5a5" : "#6ee7b7", fontSize: "11px", fontWeight: "700", letterSpacing: "0.06em" }}>
            {hasVpnInRoute ? <ShieldAlert size={14} /> : <Shield size={14} />}
            {hasVpnInRoute ? `VPN / PROXY DETECTED · ${detectedVpnHop?.vpnType || "Anonymous Relay"}` : "VPN / PROXY: CLEAN · Direct ISP Path"}
          </div>
        )}

        {/* Active Hop Card */}
        {activeHop && (
          <div style={{ marginTop: "8px", background: "rgba(2,13,26,0.88)", backdropFilter: "blur(10px)", border: "1px solid rgba(56,189,248,0.25)", borderRadius: "8px", padding: "10px 14px", maxWidth: "280px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "6px", color: ARC_COLORS[activeHopIdx % ARC_COLORS.length], fontWeight: "700", fontSize: "13px" }}>
              <MapPin size={13} />
              Hop {activeHop.hopIndex ?? activeHopIdx + 1}: {activeHop.city}, {activeHop.country_name}
            </div>
            <div style={{ marginTop: "4px", color: "#94a3b8", fontFamily: "monospace", fontSize: "11px" }}>IP: {activeHop.ip}</div>
            <div style={{ marginTop: "2px", color: "#38bdf8", fontFamily: "monospace", fontSize: "11px" }}>
              {Number(activeHop.latitude).toFixed(4)}°, {Number(activeHop.longitude).toFixed(4)}°
            </div>
            <div style={{ marginTop: "3px", color: "#cbd5e1", fontSize: "11px" }}>{activeHop.isp || activeHop.org}</div>
            {activeHop.isVpn && (
              <div style={{ marginTop: "4px", padding: "3px 8px", borderRadius: "4px", background: "rgba(127,0,0,0.6)", color: "#fca5a5", fontSize: "10px", fontWeight: "700" }}>
                ⚠ {activeHop.vpnType}
              </div>
            )}
          </div>
        )}

        {/* Single geoData card */}
        {!activeHop && geoData && !geoData.isPrivate && (
          <div style={{ marginTop: "10px", background: "rgba(2,13,26,0.88)", backdropFilter: "blur(10px)", border: "1px solid rgba(56,189,248,0.25)", borderRadius: "8px", padding: "12px 16px", maxWidth: "280px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "#f87171", fontWeight: "700", fontSize: "13px" }}>
              <MapPin size={14} /> {geoData.city}, {geoData.country_name}
            </div>
            <div style={{ marginTop: "4px", color: "#94a3b8", fontFamily: "monospace", fontSize: "11px" }}>IP: {geoData.ip}</div>
            <div style={{ marginTop: "2px", color: "#38bdf8", fontFamily: "monospace", fontSize: "11px" }}>
              Lat: {targetLat.toFixed(4)}° · Lon: {targetLon.toFixed(4)}°
            </div>
            <div style={{ marginTop: "4px", color: "#cbd5e1", fontSize: "11px" }}>{geoData.isp || geoData.org}</div>
            {geoData.isVpn && (
              <div style={{ marginTop: "6px", padding: "4px 8px", borderRadius: "4px", background: "rgba(127,0,0,0.6)", color: "#fca5a5", fontSize: "11px", fontWeight: "700" }}>
                ⚠ {geoData.vpnType}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Controls TOP-RIGHT */}
      <div style={{ position: "absolute", top: "16px", right: "16px", display: "flex", flexDirection: "column", gap: "8px", zIndex: 10 }}>
        <button onClick={() => handleZoom(-0.4)} title="Zoom In" style={ctrlStyle(false)}><ZoomIn size={16} /></button>
        <button onClick={() => handleZoom(0.4)} title="Zoom Out" style={ctrlStyle(false)}><ZoomOut size={16} /></button>
        <button onClick={() => setAutoRotate((r) => !r)} title={autoRotate ? "Stop Rotation" : "Enable Auto-Rotate"} style={ctrlStyle(autoRotate)}>
          <RotateCw size={16} />
        </button>
        <button onClick={resetView} title="Reset View" style={ctrlStyle(false)}><Crosshair size={16} /></button>
      </div>

      {/* Hop Selector BOTTOM (multi-hop mode) */}
      {validHops.length > 1 && (
        <div style={{ position: "absolute", bottom: "40px", left: "16px", right: "16px", display: "flex", gap: "6px", flexWrap: "wrap", zIndex: 10 }}>
          {validHops.map((hop, idx) => (
            <button
              key={idx}
              onClick={() => focusHop(idx)}
              style={{
                padding: "5px 10px", borderRadius: "6px",
                border: `1px solid ${idx === activeHopIdx ? ARC_COLORS[idx % ARC_COLORS.length] : "rgba(56,189,248,0.3)"}`,
                background: idx === activeHopIdx ? "rgba(2,13,26,0.95)" : "rgba(2,13,26,0.75)",
                color: idx === activeHopIdx ? ARC_COLORS[idx % ARC_COLORS.length] : "#94a3b8",
                fontSize: "11px", fontFamily: "monospace", cursor: "pointer", backdropFilter: "blur(6px)",
                display: "flex", alignItems: "center", gap: "5px",
              }}
            >
              {hop.isVpn ? "⚠" : "●"} Hop {idx + 1}: {hop.ip} ({hop.country_code})
              {hop.isVpn && <span style={{ color: "#ff4444", fontWeight: "800" }}>VPN</span>}
            </button>
          ))}
        </div>
      )}

      {/* Bottom Telemetry Bar */}
      <div style={{ position: "absolute", bottom: "12px", left: "16px", right: "16px", display: "flex", justifyContent: "space-between", pointerEvents: "none", fontSize: "10px", color: "#334155", fontFamily: "monospace", letterSpacing: "0.05em", textTransform: "uppercase" }}>
        <span>WebGL · Three.js · Satellite Imagery · Drag to Rotate · Scroll to Zoom</span>
        <span>CAM ALT: {(zoomLevel * 1000).toFixed(0)} KM</span>
      </div>

      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
