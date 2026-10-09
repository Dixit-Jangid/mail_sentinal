import {
  Database,
  Download,
  FileSearch,
  Globe2,
  LayoutDashboard,
  ShieldAlert,
} from "lucide-react";

export const navItems = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "analyze", label: "Analyze Email", icon: FileSearch },
  { id: "intelligence", label: "Threat Intelligence", icon: ShieldAlert },
  { id: "geoip", label: "GeoIP Lookup", icon: Globe2 },
  { id: "blockchain", label: "Forensic Ledger", icon: Database },
  { id: "reports", label: "Reports", icon: Download },
];
