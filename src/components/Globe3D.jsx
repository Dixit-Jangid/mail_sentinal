import { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import { RotateCw, ZoomIn, ZoomOut, Crosshair, MapPin, Loader } from "lucide-react";

// ──────────────────────────────────────────────────────────────────────────────
// Open-source Earth texture URLs (NASA Blue Marble / Three.js CDN)
// Primary: Three.js official repo CDN (MIT-compatible)
// Fallback: NASA Visible Earth
// ──────────────────────────────────────────────────────────────────────────────
const EARTH_TEXTURE_URLS = [
  "https://unpkg.com/three@0.160.1/examples/textures/planets/earth_atmos_2048.jpg",
  "https://raw.githubusercontent.com/mrdoob/three.js/r160/examples/textures/planets/earth_atmos_2048.jpg",
  "https://raw.githubusercontent.com/turban/webgl-earth/master/images/2_no_clouds_4k.jpg",
];

const EARTH_SPECULAR_URLS = [
  "https://unpkg.com/three@0.160.1/examples/textures/planets/earth_specular_2048.jpg",
  "https://raw.githubusercontent.com/mrdoob/three.js/r160/examples/textures/planets/earth_specular_2048.jpg",
];

const EARTH_NORMAL_URLS = [
  "https://unpkg.com/three@0.160.1/examples/textures/planets/earth_normal_2048.jpg",
  "https://raw.githubusercontent.com/mrdoob/three.js/r160/examples/textures/planets/earth_normal_2048.jpg",
];

const CLOUD_TEXTURE_URLS = [
  "https://unpkg.com/three@0.160.1/examples/textures/planets/earth_clouds_1024.png",
  "https://raw.githubusercontent.com/mrdoob/three.js/r160/examples/textures/planets/earth_clouds_1024.png",
];

/**
 * Converts geographic Latitude and Longitude to 3D Cartesian coordinates on a sphere.
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
 * Attempts to load a texture from a list of fallback URLs.
 */
function loadTextureWithFallback(loader, urls) {
  return new Promise((resolve, reject) => {
    let idx = 0;
    const tryNext = () => {
      if (idx >= urls.length) {
        reject(new Error("All texture URLs failed"));
        return;
      }
      const url = urls[idx++];
      loader.load(
        url,
        (texture) => resolve(texture),
        undefined,
        () => {
          console.warn(`Texture failed from ${url}, trying next...`);
          tryNext();
        }
      );
    };
    tryNext();
  });
}

export default function Globe3D({ geoData }) {
  const mountRef = useRef(null);
  const [autoRotate, setAutoRotate] = useState(true);
  const [zoomLevel, setZoomLevel] = useState(2.8);
  const [textureLoading, setTextureLoading] = useState(true);
  const [textureError, setTextureError] = useState(false);

  const sceneRef = useRef(null);
  const rendererRef = useRef(null);
  const cameraRef = useRef(null);
  const globeGroupRef = useRef(null);
  const markerGroupRef = useRef(null);
  const cloudsRef = useRef(null);
  const isDraggingRef = useRef(false);
  const previousMousePositionRef = useRef({ x: 0, y: 0 });
  const animFrameRef = useRef(null);

  const targetLat = typeof geoData?.latitude === "number" ? geoData.latitude : 0;
  const targetLon = typeof geoData?.longitude === "number" ? geoData.longitude : 0;
  const hasTarget = geoData && !geoData.isPrivate && (targetLat !== 0 || targetLon !== 0);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const width = container.clientWidth || 600;
    const height = container.clientHeight || 450;

    // ── Scene ──────────────────────────────────────────────────────────────
    const scene = new THREE.Scene();
    scene.background = new THREE.Color("#020d1a");
    sceneRef.current = scene;

    // ── Camera ─────────────────────────────────────────────────────────────
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.z = 2.8;
    cameraRef.current = camera;

    // ── Renderer ───────────────────────────────────────────────────────────
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 0.8;
    container.innerHTML = "";
    container.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // ── Globe Group ─────────────────────────────────────────────────────────
    const globeGroup = new THREE.Group();
    scene.add(globeGroup);
    globeGroupRef.current = globeGroup;

    // ── Marker Group ────────────────────────────────────────────────────────
    const markerGroup = new THREE.Group();
    globeGroup.add(markerGroup);
    markerGroupRef.current = markerGroup;

    // ── Background Stars ────────────────────────────────────────────────────
    const starsGeo = new THREE.BufferGeometry();
    const starsCount = 3000;
    const starPos = new Float32Array(starsCount * 3);
    for (let i = 0; i < starsCount * 3; i += 3) {
      const r = 80 + Math.random() * 120;
      const theta = Math.random() * 2 * Math.PI;
      const phi = Math.acos(2 * Math.random() - 1);
      starPos[i] = r * Math.sin(phi) * Math.cos(theta);
      starPos[i + 1] = r * Math.sin(phi) * Math.sin(theta);
      starPos[i + 2] = r * Math.cos(phi);
    }
    starsGeo.setAttribute("position", new THREE.BufferAttribute(starPos, 3));
    const starsMat = new THREE.PointsMaterial({ color: "#e8f4fd", size: 0.3, sizeAttenuation: true, transparent: true, opacity: 0.8 });
    scene.add(new THREE.Points(starsGeo, starsMat));

    // ── Lighting ─────────────────────────────────────────────────────────────
    const ambientLight = new THREE.AmbientLight("#d0e8ff", 0.4);
    scene.add(ambientLight);

    const sunLight = new THREE.DirectionalLight("#fff5e0", 2.2);
    sunLight.position.set(5, 3, 5);
    scene.add(sunLight);

    const fillLight = new THREE.DirectionalLight("#2060ff", 0.3);
    fillLight.position.set(-5, -2, -3);
    scene.add(fillLight);

    const radius = 1.0;

    // ── Atmospheric Glow Shader ──────────────────────────────────────────────
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

    // ── Load Real Open-Source Textures ──────────────────────────────────────
    const loader = new THREE.TextureLoader();
    loader.crossOrigin = "anonymous";

    const earthGeo = new THREE.SphereGeometry(radius, 64, 64);
    let earthMesh;

    // Placeholder while textures load
    const placeholderMat = new THREE.MeshPhongMaterial({ color: "#1a3a5c" });
    earthMesh = new THREE.Mesh(earthGeo, placeholderMat);
    globeGroup.add(earthMesh);

    // Async texture loading
    (async () => {
      try {
        const [earthTex, specTex, normalTex] = await Promise.allSettled([
          loadTextureWithFallback(loader, EARTH_TEXTURE_URLS),
          loadTextureWithFallback(loader, EARTH_SPECULAR_URLS),
          loadTextureWithFallback(loader, EARTH_NORMAL_URLS),
        ]);

        if (earthTex.status === "fulfilled") {
          // Three.js r152+ automatically handles sRGB colorspace for loaded textures

          const realMat = new THREE.MeshPhongMaterial({
            map: earthTex.value,
            ...(specTex.status === "fulfilled" && { specularMap: specTex.value }),
            ...(normalTex.status === "fulfilled" && { normalMap: normalTex.value, normalScale: new THREE.Vector2(2, 2) }),
            specular: new THREE.Color("#113355"),
            shininess: 25,
          });

          // Swap material
          earthMesh.material.dispose();
          earthMesh.material = realMat;
          setTextureLoading(false);

          // Load cloud layer
          loadTextureWithFallback(loader, CLOUD_TEXTURE_URLS)
            .then((cloudTex) => {
              const cloudGeo = new THREE.SphereGeometry(radius * 1.01, 64, 64);
              const cloudMat = new THREE.MeshPhongMaterial({
                map: cloudTex,
                alphaMap: cloudTex,
                transparent: true,
                opacity: 0.35,
                depthWrite: false,
              });
              const cloudMesh = new THREE.Mesh(cloudGeo, cloudMat);
              globeGroup.add(cloudMesh);
              cloudsRef.current = cloudMesh;
            })
            .catch(() => {
              console.info("Cloud texture unavailable, skipping cloud layer.");
            });
        } else {
          throw new Error("Earth texture failed to load");
        }
      } catch {
        console.error("Texture loading failed, rendering fallback procedural globe.");
        setTextureError(true);
        setTextureLoading(false);
        // Procedural fallback with grid lines
        const fallbackMat = new THREE.MeshPhongMaterial({ color: "#1a4a7a", specular: "#2063ab", shininess: 15, wireframe: false });
        earthMesh.material.dispose();
        earthMesh.material = fallbackMat;

        const wireGeo = new THREE.SphereGeometry(radius * 1.002, 36, 18);
        const wireMat = new THREE.MeshBasicMaterial({ color: "#38bdf8", wireframe: true, transparent: true, opacity: 0.15 });
        globeGroup.add(new THREE.Mesh(wireGeo, wireMat));
      }
    })();

    // ── Mouse Drag Rotation ─────────────────────────────────────────────────
    const domElement = renderer.domElement;
    const onMouseDown = (e) => {
      isDraggingRef.current = true;
      previousMousePositionRef.current = { x: e.clientX, y: e.clientY };
    };
    const onMouseMove = (e) => {
      if (!isDraggingRef.current || !globeGroupRef.current) return;
      const dx = e.clientX - previousMousePositionRef.current.x;
      const dy = e.clientY - previousMousePositionRef.current.y;
      globeGroupRef.current.rotation.y += dx * 0.005;
      globeGroupRef.current.rotation.x = Math.max(
        -Math.PI / 2.2,
        Math.min(Math.PI / 2.2, globeGroupRef.current.rotation.x + dy * 0.005)
      );
      previousMousePositionRef.current = { x: e.clientX, y: e.clientY };
    };
    const onMouseUp = () => { isDraggingRef.current = false; };

    // ── Scroll-to-Zoom ─────────────────────────────────────────────────────
    const onWheel = (e) => {
      e.preventDefault();
      const delta = e.deltaY > 0 ? 0.15 : -0.15;
      const newZ = Math.max(1.6, Math.min(4.5, cameraRef.current.position.z + delta));
      cameraRef.current.position.z = newZ;
      setZoomLevel(newZ);
    };

    domElement.addEventListener("mousedown", onMouseDown);
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    domElement.addEventListener("wheel", onWheel, { passive: false });

    // ── Resize Handler ─────────────────────────────────────────────────────
    const onResize = () => {
      if (!container || !rendererRef.current || !cameraRef.current) return;
      const w = container.clientWidth;
      const h = container.clientHeight;
      cameraRef.current.aspect = w / h;
      cameraRef.current.updateProjectionMatrix();
      rendererRef.current.setSize(w, h);
    };
    window.addEventListener("resize", onResize);

    // ── Animation Loop ──────────────────────────────────────────────────────
    const clock = new THREE.Clock();
    const animate = () => {
      animFrameRef.current = requestAnimationFrame(animate);
      const elapsed = clock.getElapsedTime();

      if (!isDraggingRef.current && globeGroupRef.current) {
        if (autoRotate) globeGroupRef.current.rotation.y += 0.0015;
      }

      if (cloudsRef.current) {
        cloudsRef.current.rotation.y += 0.0004;
      }

      // Pulsing marker rings
      if (markerGroupRef.current) {
        markerGroupRef.current.children.forEach((child) => {
          if (child.userData?.isPulseRing) {
            const scale = 1 + ((elapsed * 1.5) % 1.8);
            child.scale.set(scale, scale, scale);
            if (child.material) child.material.opacity = Math.max(0, 1 - scale / 2.8);
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

      earthGeo.dispose();
      starsGeo.dispose();
      starsMat.dispose();
      glowGeo.dispose();
      glowMat.dispose();
      renderer.dispose();
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Update auto-rotate flag without remounting ──────────────────────────
  const autoRotateRef = useRef(autoRotate);
  useEffect(() => { autoRotateRef.current = autoRotate; }, [autoRotate]);

  // ── Place Marker Whenever geoData Changes ──────────────────────────────
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

    if (!hasTarget) return;

    const radius = 1.0;
    const pos = latLonToVector3(targetLat, targetLon, radius);
    const dir = pos.clone().normalize();

    // Glowing red beacon sphere
    const beaconGeo = new THREE.SphereGeometry(0.022, 16, 16);
    const beaconMat = new THREE.MeshBasicMaterial({ color: "#ff3333" });
    const beacon = new THREE.Mesh(beaconGeo, beaconMat);
    beacon.position.copy(pos);
    markerGroup.add(beacon);

    // Inner bright core
    const coreGeo = new THREE.SphereGeometry(0.01, 8, 8);
    const coreMat = new THREE.MeshBasicMaterial({ color: "#ffffff" });
    const core = new THREE.Mesh(coreGeo, coreMat);
    core.position.copy(pos);
    markerGroup.add(core);

    // Outward beam line
    const beamEnd = pos.clone().add(dir.clone().multiplyScalar(0.22));
    const lineGeo = new THREE.BufferGeometry().setFromPoints([pos, beamEnd]);
    const lineMat = new THREE.LineBasicMaterial({ color: "#ff6666", linewidth: 2 });
    markerGroup.add(new THREE.Line(lineGeo, lineMat));

    // Pulsing ring
    const ringGeo = new THREE.RingGeometry(0.018, 0.04, 32);
    const ringMat = new THREE.MeshBasicMaterial({
      color: "#ff3333",
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.85,
    });
    const ring = new THREE.Mesh(ringGeo, ringMat);
    ring.position.copy(pos.clone().multiplyScalar(1.001));
    ring.lookAt(pos.clone().multiplyScalar(2));
    ring.userData = { isPulseRing: true };
    markerGroup.add(ring);

    // Second trailing ring
    const ring2Geo = new THREE.RingGeometry(0.018, 0.04, 32);
    const ring2Mat = new THREE.MeshBasicMaterial({ color: "#ff8888", side: THREE.DoubleSide, transparent: true, opacity: 0.5 });
    const ring2 = new THREE.Mesh(ring2Geo, ring2Mat);
    ring2.position.copy(pos.clone().multiplyScalar(1.001));
    ring2.lookAt(pos.clone().multiplyScalar(2));
    ring2.userData = { isPulseRing: true };
    markerGroup.add(ring2);

    // Rotate globe to face the target
    const targetRotY = -((targetLon + 90) * (Math.PI / 180));
    const targetRotX = Math.max(-Math.PI / 3, Math.min(Math.PI / 3, (targetLat - 15) * (Math.PI / 180)));
    globeGroup.rotation.y = targetRotY;
    globeGroup.rotation.x = targetRotX;
  }, [geoData?.ip, targetLat, targetLon, hasTarget]);

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
    if (hasTarget) {
      globeGroupRef.current.rotation.y = -((targetLon + 90) * (Math.PI / 180));
      globeGroupRef.current.rotation.x = Math.max(-Math.PI / 3, Math.min(Math.PI / 3, (targetLat - 15) * (Math.PI / 180)));
    } else {
      globeGroupRef.current.rotation.set(0, 0, 0);
    }
  };

  const ctrlStyle = (active) => ({
    background: active ? "rgba(37, 99, 235, 0.85)" : "rgba(2, 13, 26, 0.85)",
    backdropFilter: "blur(6px)",
    border: "1px solid rgba(56, 189, 248, 0.35)",
    color: "#e0f2fe",
    width: "36px",
    height: "36px",
    borderRadius: "6px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    cursor: "pointer",
  });

  return (
    <div
      style={{
        position: "relative",
        width: "100%",
        height: "480px",
        background: "#020d1a",
        borderRadius: "12px",
        overflow: "hidden",
        border: "1px solid #0f2d4a",
        boxShadow: "0 16px 40px rgba(0, 0, 0, 0.5)",
      }}
    >
      {/* 3D WebGL Canvas */}
      <div
        ref={mountRef}
        style={{ width: "100%", height: "100%", cursor: "grab" }}
      />

      {/* Texture Loading Indicator */}
      {textureLoading && (
        <div
          style={{
            position: "absolute",
            bottom: "50px",
            left: "50%",
            transform: "translateX(-50%)",
            display: "flex",
            alignItems: "center",
            gap: "8px",
            background: "rgba(2, 13, 26, 0.85)",
            border: "1px solid rgba(56, 189, 248, 0.3)",
            borderRadius: "20px",
            padding: "6px 16px",
            color: "#38bdf8",
            fontSize: "12px",
            fontWeight: "600",
            backdropFilter: "blur(6px)",
          }}
        >
          <Loader size={14} style={{ animation: "spin 1s linear infinite" }} />
          Loading NASA Earth Texture...
        </div>
      )}

      {textureError && (
        <div
          style={{
            position: "absolute",
            bottom: "50px",
            left: "50%",
            transform: "translateX(-50%)",
            background: "rgba(40, 10, 10, 0.85)",
            border: "1px solid #7f1d1d",
            borderRadius: "20px",
            padding: "6px 16px",
            color: "#fca5a5",
            fontSize: "12px",
            backdropFilter: "blur(6px)",
          }}
        >
          ⚠ Texture unavailable — check internet connection
        </div>
      )}

      {/* HUD TOP-LEFT */}
      <div
        style={{
          position: "absolute",
          top: "16px",
          left: "16px",
          pointerEvents: "none",
          zIndex: 10,
        }}
      >
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "8px",
            background: "rgba(2, 13, 26, 0.82)",
            backdropFilter: "blur(10px)",
            border: "1px solid rgba(56, 189, 248, 0.4)",
            padding: "6px 14px",
            borderRadius: "6px",
            color: "#38bdf8",
            fontSize: "11px",
            fontWeight: "700",
            letterSpacing: "0.08em",
            textTransform: "uppercase",
          }}
        >
          <Crosshair size={13} />
          3D Geolocation Radar · NASA Blue Marble
        </div>

        {geoData && !geoData.isPrivate && (
          <div
            style={{
              marginTop: "10px",
              background: "rgba(2, 13, 26, 0.88)",
              backdropFilter: "blur(10px)",
              border: "1px solid rgba(56, 189, 248, 0.25)",
              borderRadius: "8px",
              padding: "12px 16px",
              maxWidth: "280px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "#f87171", fontWeight: "700", fontSize: "13px" }}>
              <MapPin size={14} /> {geoData.city}, {geoData.country_name}
            </div>
            <div style={{ marginTop: "4px", color: "#94a3b8", fontFamily: "monospace", fontSize: "11px" }}>
              IP: {geoData.ip}
            </div>
            <div style={{ marginTop: "2px", color: "#38bdf8", fontFamily: "monospace", fontSize: "11px" }}>
              Lat: {targetLat.toFixed(4)}° · Lon: {targetLon.toFixed(4)}°
            </div>
            <div style={{ marginTop: "4px", color: "#cbd5e1", fontSize: "11px" }}>
              {geoData.isp || geoData.org}
            </div>
          </div>
        )}
      </div>

      {/* Controls */}
      <div
        style={{
          position: "absolute",
          top: "16px",
          right: "16px",
          display: "flex",
          flexDirection: "column",
          gap: "8px",
          zIndex: 10,
        }}
      >
        <button onClick={() => handleZoom(-0.4)} title="Zoom In" style={ctrlStyle(false)}>
          <ZoomIn size={16} />
        </button>
        <button onClick={() => handleZoom(0.4)} title="Zoom Out" style={ctrlStyle(false)}>
          <ZoomOut size={16} />
        </button>
        <button
          onClick={() => setAutoRotate((r) => !r)}
          title={autoRotate ? "Pause Rotation" : "Resume Rotation"}
          style={ctrlStyle(autoRotate)}
        >
          <RotateCw size={16} />
        </button>
        <button onClick={resetView} title="Reset View" style={ctrlStyle(false)}>
          <Crosshair size={16} />
        </button>
      </div>

      {/* Bottom Telemetry Bar */}
      <div
        style={{
          position: "absolute",
          bottom: "12px",
          left: "16px",
          right: "16px",
          display: "flex",
          justifyContent: "space-between",
          pointerEvents: "none",
          fontSize: "10px",
          color: "#334155",
          fontFamily: "monospace",
          letterSpacing: "0.05em",
          textTransform: "uppercase",
        }}
      >
        <span>WebGL · Three.js · NASA Blue Marble Texture · Drag to Rotate · Scroll to Zoom</span>
        <span>CAM ALT: {(zoomLevel * 1000).toFixed(0)} KM</span>
      </div>

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}
