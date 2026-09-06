# 🛡️ AegisMail — Autonomous Email Forensics & Threat Intelligence Platform

AegisMail is an advanced, privacy-preserving digital forensics and automated incident response platform engineered for Security Operations Centers (SOCs), incident responders, and cyber crime investigation units. It transforms raw RFC 822 / MIME `.eml` files into court-admissible forensic dossiers, 3D relay hops, social engineering cue breakdowns, and automated containment playbooks.

---

## 📌 Problem Overview & Strategic Value

Modern cyber threats increasingly exploit **Business Email Compromise (BEC)**, executive impersonation, typosquatted brand domains, and evasive attachments to bypass standard secure email gateways (SEGs). When investigating suspicious messages, security analysts and forensic investigators require:

1. **Tamper-Evident Chain of Custody**: Immediate bitstream verification using SHA-256 cryptographic hashing.
2. **Hop-by-Hop Origin Tracing**: Parsing and geo-mapping of `Received:` headers to identify true originating relays, ASNs, and physical infrastructure.
3. **Behavioral & Linguistic Decomposition**: NLP-driven detection of financial urgency, credential harvesting, coercion, and phishing lures.
4. **Admissible Forensic Certification**: Court-ready electronic evidence certificates compliant with **ISO/IEC 27037:2012** and statutory requirements (**Section 65B Indian Evidence Act / Section 63 Bharatiya Sakshya Adhiniyam**).
5. **Automated Incident Response**: Actionable playbooks including Microsoft 365 Exchange purge scripts, firewall perimeter drop rules, and SIEM hunting queries.

---

## 🚀 Key Architectural Capabilities

| Module | Technical Highlights |
| :--- | :--- |
| **🔍 RFC 822 / MIME Parser** | In-browser, zero-leakage parsing of raw `.eml` files with WebCrypto SHA-256 digests. |
| **🌐 3D Interactive WebGL Globe** | Three.js orbital visualization mapping Hop 0 relay nodes, ASNs, and geographic coordinates. |
| **🧠 Deep NLP Social Engineering Engine** | Analyzes deceptive patterns: BEC Wire Diversion, Credential Harvesting, Executive Impersonation, and PhaaS. |
| **🛡️ Protocol Alignment & DNS** | Deep verification of SPF, DKIM, DMARC, Return-Path discrepancies, and display name spoofing with browser-native Google DoH fallback. |
| **⚖️ Admissibility Certification** | Formats printable, tamper-evident forensic certificates for formal judicial proceedings and incident dockets. |
| **📊 Bulk Batch Triage** | Concurrent parsing and triage of multiple `.eml` files with risk filtering, progress tracking, and CSV export. |
| **🚨 DFIR SOC Playbooks** | Generates tailored incident response checklists, perimeter firewall drop commands, and SIEM queries. |

---

## 🛠️ Getting Started & Local Development

### Prerequisites
- **Node.js**: 18.0 or later
- **npm**: 9.0 or later

### 1. Install Dependencies
```bash
npm install
```

### 2. Run in Development Mode
Starts both the Express API server (Port 5000) and the Vite frontend (Port 5173):
```bash
npm run dev
```
Access the application at [http://localhost:5173](http://localhost:5173).

### 3. Production Build & Full-Stack Serving
Compile the optimized frontend bundle and serve all API routes and static assets from Express:
```bash
npm run build
npm run server
```
The full application runs on [http://localhost:5000](http://localhost:5000) with zero cross-origin configuration required.

---

## 🌐 Deployment Options

### Option A: Static / Serverless (Vercel / Netlify / Cloudflare Pages)
AegisMail is architected with a client-side **DNS-over-HTTPS (DoH)** fallback via Google Public DNS (`https://dns.google/resolve`), allowing it to perform live domain checks, MX lookups, and SPF/DMARC validations entirely within the browser.
- **Build Command**: `npm run build`
- **Output Directory**: `dist`
- **SPA Routing**: Handled automatically via [vercel.json](file:///c:/Users/cherr/OneDrive/Documents/Hackathon/sih-frontend/vercel.json).

### Option B: Containerized / VPS Full-Stack (Render / Railway / Docker / AWS)
- **Build Command**: `npm install && npm run build`
- **Start Command**: `node server/index.js`
- **Environment Variables**: `PORT=5000` (or dynamically assigned by cloud provider)

---

## 🔒 Privacy & Evidence Integrity

- **Zero Unintended Exfiltration**: By default, `.eml` files are processed locally in memory.
- **Cryptographic Hashes**: Every file generates verifiable SHA-256 and MD5 fingerprints upon ingestion.
- **PII Redaction**: Built-in toggle to mask email addresses and sensitive identifying text in exported reports and court certificates.
- **Standards Compliance**: Adheres to ISO/IEC 27037 (Digital Evidence Handling) and NIST SP 800-86 (Forensic Techniques for Incident Response).
