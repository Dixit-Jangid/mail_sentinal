import {
  BarChart3,
  Database,
  Download,
  FileSearch,
  FolderArchive,
  Globe2,
  LayoutDashboard,
  ShieldAlert,
  UserX,
} from "lucide-react";

export const navItems = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "analyze", label: "Analyze Email", icon: FileSearch },
  { id: "cases", label: "Case Management", icon: FolderArchive },
  { id: "bulk", label: "Bulk Scan", icon: BarChart3 },
  { id: "intelligence", label: "Threat Intelligence", icon: ShieldAlert },
  { id: "breach", label: "Data Breach (HIBP)", icon: UserX },
  { id: "geoip", label: "GeoIP Lookup", icon: Globe2 },
  { id: "blockchain", label: "Forensic Ledger", icon: Database },
  { id: "reports", label: "Reports", icon: Download },
];
