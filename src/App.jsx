import { useEffect, useState } from "react";
import Sidebar from "./components/Sidebar";
import { navItems } from "./constants/navigation";
import Topbar from "./components/Topbar";
import AuthPage from "./pages/AuthPage";
import Dashboard from "./pages/Dashboard";
import AnalyzeEmail from "./pages/AnalyzeEmail";
import ThreatIntelligence from "./pages/ThreatIntelligence";
import GeoIPLookup from "./pages/GeoIPLookup";
import ForensicLedger from "./pages/ForensicLedger";
import Reports from "./pages/Reports";
import SettingsPage from "./pages/SettingsPage";
import { authRequest } from "./services/authService";
import { readScanHistory, recordScanHistory } from "./services/scanHistoryService";
import { analyzeEmlFile, DEFAULT_SETTINGS } from "./services/emailAnalyzer";
import "./App.css";

function App() {
  const [activePage, setActivePage] = useState("dashboard");
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [file, setFile] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [authError, setAuthError] = useState("");
  const [sessionCheck, setSessionCheck] = useState(0);
  const [scanHistory, setScanHistory] = useState([]);
  const [scanHistoryError, setScanHistoryError] = useState("");

  useEffect(() => {
    let active = true;

    authRequest("me")
      .then(({ user: sessionUser }) => {
        if (!active) return;
        setUser(sessionUser);
        if (sessionUser) {
          try {
            setScanHistory(readScanHistory(sessionUser.email));
            setScanHistoryError("");
          } catch (error) {
            console.error("Unable to load scan history:", error);
            setScanHistory([]);
            setScanHistoryError(error.message || "Unable to load saved scan history.");
          }
        } else {
          setScanHistory([]);
          setScanHistoryError("");
        }
      })
      .catch((error) => {
        if (active) setAuthError(error.message || "Unable to reach the authentication service.");
      })
      .finally(() => {
        if (active) setAuthLoading(false);
      });

    return () => { active = false; };
  }, [sessionCheck]);

  const handleLogout = async () => {
    try {
      await authRequest("logout", { method: "POST" });
      setUser(null);
      setAuthError("");
      setScanHistory([]);
      setScanHistoryError("");
    } catch (error) {
      setAuthError(error.message || "Unable to sign out. Please try again.");
    }
  };

  const retrySessionCheck = () => {
    setAuthLoading(true);
    setAuthError("");
    setSessionCheck((check) => check + 1);
  };

  if (authLoading) {
    return <main className="auth-screen"><p className="auth-loading">Checking your session...</p></main>;
  }

  if (!user) {
    return (
      <AuthPage
        initialError={authError}
        onAuthenticated={(authenticatedUser) => {
          setUser(authenticatedUser);
          setAuthError("");
        }}
        onRetry={retrySessionCheck}
      />
    );
  }

  const selectedNav =
    navItems.find((item) => item.id === activePage)?.label ||
    (activePage === "settings" ? "Settings" : "Dashboard");

  const pageTitle =
    activePage === "dashboard" ? "Security Overview" : selectedNav;

  const handleFile = (selectedFile) => {
    if (!selectedFile) return;

    if (!selectedFile.name.toLowerCase().endsWith(".eml")) {
      alert("Please choose a valid .eml email file.");
      return;
    }

    setFile(selectedFile);
    setAnalysis(null);
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setDragging(false);
    handleFile(event.dataTransfer.files?.[0]);
  };

  const analyzeFile = async () => {
    if (!file) {
      alert("Please choose an .eml file first.");
      return;
    }

    setAnalyzing(true);
    try {
      const result = await analyzeEmlFile(file, settings);
      handleAnalysisComplete(result);
      return result;
    } catch (error) {
      console.error("Analysis failed:", error);
      alert("Unable to analyze this .eml file. Please verify it is a valid email file.");
      return null;
    } finally {
      setAnalyzing(false);
    }
  };

  const handleAnalysisComplete = (result) => {
    setAnalysis(result);
    try {
      setScanHistory(recordScanHistory(user.email, result));
      setScanHistoryError("");
    } catch (error) {
      console.error("Unable to save scan history:", error);
      setScanHistoryError(error.message || "Unable to save this scan to history.");
    }
  };

  return (
    <div className="app-shell">
      {/* SIDEBAR */}
      <Sidebar
        activePage={activePage}
        setActivePage={setActivePage}
        sidebarOpen={sidebarOpen}
      />

      {/* MAIN CONTENT AREA */}
      <main className="main-area">
        <Topbar
          pageTitle={pageTitle}
          sidebarOpen={sidebarOpen}
          setSidebarOpen={setSidebarOpen}
          user={user}
          onLogout={handleLogout}
          authError={authError}
        />

        <section className="content">
          {activePage === "dashboard" && (
            <Dashboard
              file={file}
              analysis={analysis}
              analyzing={analyzing}
              scanHistory={scanHistory}
              scanHistoryError={scanHistoryError}
              dragging={dragging}
              setDragging={setDragging}
              handleDrop={handleDrop}
              handleFile={handleFile}
              setFile={setFile}
              analyzeFile={analyzeFile}
              setActivePage={setActivePage}
            />
          )}

          {activePage === "analyze" && (
            <AnalyzeEmail
              file={file}
              setFile={setFile}
              analysis={analysis}
              onAnalysisComplete={handleAnalysisComplete}
              onBack={() => setActivePage("dashboard")}
              settings={settings}
            />
          )}

          {activePage === "intelligence" && (
            <ThreatIntelligence
              analysis={analysis}
              setActivePage={setActivePage}
            />
          )}

          {activePage === "geoip" && (
            <GeoIPLookup analysis={analysis} />
          )}

          {activePage === "blockchain" && (
            <ForensicLedger
              analysis={analysis}
              file={file}
              setActivePage={setActivePage}
            />
          )}

          {activePage === "reports" && (
            <Reports
              analysis={analysis}
              setActivePage={setActivePage}
            />
          )}

          {activePage === "settings" && (
            <SettingsPage
              settings={settings}
              setSettings={setSettings}
            />
          )}
        </section>
      </main>
    </div>
  );
}

export default App;