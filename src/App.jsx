import { useState } from "react";
import Sidebar from "./components/Sidebar";
import { navItems } from "./constants/navigation";
import Topbar from "./components/Topbar";
import Dashboard from "./pages/Dashboard";
import AnalyzeEmail from "./pages/AnalyzeEmail";
import BulkScan from "./pages/BulkScan";
import ThreatIntelligence from "./pages/ThreatIntelligence";
import DataBreachLookup from "./pages/DataBreachLookup";
import GeoIPLookup from "./pages/GeoIPLookup";
import ForensicLedger from "./pages/ForensicLedger";
import Reports from "./pages/Reports";
import CaseManagement from "./pages/CaseManagement";
import SettingsPage from "./pages/SettingsPage";
import { analyzeEmlFile, DEFAULT_SETTINGS } from "./services/emailAnalyzer";
import "./App.css";

function App() {
  const [activePage, setActivePage] = useState("dashboard");
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [file, setFile] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [notifications, setNotifications] = useState(false);
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);

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
      setAnalysis(result);
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
  };

  const handleSelectEmailFromBulk = (bulkResult) => {
    setAnalysis(bulkResult);
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
          notifications={notifications}
          setNotifications={setNotifications}
          recentScanCount={analysis ? 1 : 0}
        />

        <section className="content">
          {activePage === "dashboard" && (
            <Dashboard
              file={file}
              analysis={analysis}
              analyzing={analyzing}
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

          {activePage === "cases" && (
            <CaseManagement
              analysis={analysis}
              setActivePage={setActivePage}
            />
          )}

          {activePage === "bulk" && (
            <BulkScan
              onSelectEmail={handleSelectEmailFromBulk}
              setActivePage={setActivePage}
              settings={settings}
            />
          )}

          {activePage === "intelligence" && (
            <ThreatIntelligence
              analysis={analysis}
              setActivePage={setActivePage}
            />
          )}

          {activePage === "breach" && (
            <DataBreachLookup analysis={analysis} />
          )}

          {activePage === "geoip" && (
            <GeoIPLookup analysis={analysis} />
          )}

          {activePage === "blockchain" && (
            <ForensicLedger
              analysis={analysis}
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