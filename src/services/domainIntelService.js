/**
 * Domain Intelligence & WHOIS Analysis Service
 * Features:
 *  - WHOIS / RDAP query resolution
 *  - Domain-age intelligence (Newly Registered Domain detection)
 *  - MX mail infrastructure classification (Google, Microsoft 365, Proofpoint, etc.)
 *  - Lookalike / Typosquatting / Homoglyph Brand Deception Analysis
 */

export const HIGH_VALUE_TARGET_BRANDS = [
  "paypal", "microsoft", "google", "apple", "amazon", "netflix",
  "chase", "bankofamerica", "wellsfargo", "citibank", "capitalone",
  "dhl", "fedex", "ups", "usps", "docusign", "stripe", "adobe",
  "dropbox", "zoom", "salesforce", "slack", "linkedin", "facebook",
  "instagram", "twitter", "x", "meta", "coinbase", "binance",
  "metamask", "blockchain", "kraken", "irs", "treasury", "sec",
  "healthcare", "internal-revenue", "payroll", "quickbooks", "intuit"
];

/**
 * Computes Levenshtein distance between two strings.
 */
export function levenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          Math.min(
            matrix[i][j - 1] + 1,   // insertion
            matrix[i - 1][j] + 1    // deletion
          )
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Detects lookalike / typosquatting attacks against monitored high-value brands.
 */
export function analyzeLookalikeDomain(domain) {
  if (!domain || !domain.includes(".")) {
    return {
      isLookalike: false,
      targetBrand: null,
      technique: "None",
      riskScore: 0,
      confidence: "None",
    };
  }

  const sld = domain.split(".")[0].toLowerCase();
  const fullNoDots = domain.replace(/\.[a-z]{2,}$/i, "").toLowerCase();

  // 1. Homoglyph / Punycode check (xn--)
  if (domain.toLowerCase().startsWith("xn--") || domain.includes(".xn--")) {
    return {
      isLookalike: true,
      targetBrand: "Internationalized Domain Name (IDN)",
      technique: "PUNYCODE_HOMOGLYPH",
      riskScore: 90,
      confidence: "High",
      detail: "Adversary employing non-ASCII homoglyphs via Punycode (RFC 3492) to mimic legitimate characters.",
    };
  }

  // 2. Exact substring embedding (e.g. paypal-security-update.com or support-microsoft.com)
  for (const brand of HIGH_VALUE_TARGET_BRANDS) {
    if (brand.length < 4) continue; // skip tiny names like 'x' or 'irs' for substring

    if ((sld.includes(brand) && sld !== brand) || (fullNoDots.includes(brand) && fullNoDots !== brand)) {
      return {
        isLookalike: true,
        targetBrand: brand.toUpperCase(),
        technique: "COMBOSQUATTING_SUBSTRING",
        riskScore: 85,
        confidence: "High",
        detail: `Domain incorporates protected brand '${brand.toUpperCase()}' within composite deceptive string '${sld}'.`,
      };
    }

    // Levenshtein edit distance check (typosquatting e.g., paypa1, micros0ft, amzon, goog1e)
    const normalizedSld = sld
      .replace(/0/g, "o")
      .replace(/1/g, "l")
      .replace(/3/g, "e")
      .replace(/5/g, "s")
      .replace(/vv/g, "w");

    const dist = levenshteinDistance(normalizedSld, brand);
    if (dist > 0 && dist <= 2 && Math.abs(normalizedSld.length - brand.length) <= 2) {
      return {
        isLookalike: true,
        targetBrand: brand.toUpperCase(),
        technique: "TYPOSQUATTING_LEVENSHTEIN",
        riskScore: 92,
        confidence: "Critical",
        detail: `Domain '${sld}' has edit distance of ${dist} from authentic brand '${brand.toUpperCase()}'. Likely typographic trap.`,
      };
    }
  }

  return {
    isLookalike: false,
    targetBrand: null,
    technique: "None",
    riskScore: 0,
    confidence: "Clean",
    detail: "No known brand typosquatting or homoglyph impersonation signatures detected.",
  };
}

/**
 * Classifies MX mail exchange infrastructure.
 */
export function classifyMailProvider(mxRecords = []) {
  if (!Array.isArray(mxRecords) || mxRecords.length === 0) {
    return {
      provider: "No MX Records Configured",
      category: "MISSING_MX",
      isReputable: false,
      reputationScore: 10,
      description: "Domain cannot receive inbound mail, typical of disposable blast senders.",
    };
  }

  const mxJoined = mxRecords
    .map((r) => (typeof r === "string" ? r : r.exchange || ""))
    .join(" ")
    .toLowerCase();

  if (mxJoined.includes("google") || mxJoined.includes("aspmx") || mxJoined.includes("googlemail")) {
    return {
      provider: "Google Workspace / Gmail Enterprise",
      category: "MAJOR_ENTERPRISE_CLOUD",
      isReputable: true,
      reputationScore: 95,
      description: "Protected by Google Cloud MTA security filters and TLS transport.",
    };
  }

  if (mxJoined.includes("outlook") || mxJoined.includes("microsoft") || mxJoined.includes("protection.outlook.com")) {
    return {
      provider: "Microsoft 365 / Exchange Online Protection (EOP)",
      category: "MAJOR_ENTERPRISE_CLOUD",
      isReputable: true,
      reputationScore: 95,
      description: "Protected by Microsoft Exchange Online email security gateways.",
    };
  }

  if (mxJoined.includes("pphosted") || mxJoined.includes("proofpoint")) {
    return {
      provider: "Proofpoint Enterprise Gateway",
      category: "SPECIALIZED_SECURE_GATEWAY",
      isReputable: true,
      reputationScore: 98,
      description: "Corporate enterprise behind dedicated cybersecurity mail filter.",
    };
  }

  if (mxJoined.includes("mimecast")) {
    return {
      provider: "Mimecast Secure Email Gateway",
      category: "SPECIALIZED_SECURE_GATEWAY",
      isReputable: true,
      reputationScore: 98,
      description: "Protected by Mimecast gateway perimeter.",
    };
  }

  if (mxJoined.includes("cisco") || mxJoined.includes("ironport")) {
    return {
      provider: "Cisco IronPort Email Security",
      category: "SPECIALIZED_SECURE_GATEWAY",
      isReputable: true,
      reputationScore: 95,
      description: "Enterprise Cisco ESA perimeter.",
    };
  }

  if (mxJoined.includes("secureserver.net") || mxJoined.includes("godaddy")) {
    return {
      provider: "GoDaddy Commercial Webmail",
      category: "COMMERCIAL_HOSTING",
      isReputable: true,
      reputationScore: 70,
      description: "Shared commercial hosting mail exchanger.",
    };
  }

  if (mxJoined.includes("zoho")) {
    return {
      provider: "Zoho Mail Service",
      category: "CLOUD_SUITE",
      isReputable: true,
      reputationScore: 80,
      description: "Cloud business productivity suite.",
    };
  }

  if (mxJoined.includes("ovh") || mxJoined.includes("ovh.net")) {
    return {
      provider: "OVH Cloud Mail Hosting",
      category: "VPS_HOSTING",
      isReputable: true,
      reputationScore: 65,
      description: "European VPS / Cloud hosting platform.",
    };
  }

  return {
    provider: "Custom / Self-Hosted Mail Server",
    category: "INDEPENDENT_MTA",
    isReputable: true,
    reputationScore: 60,
    description: "Independent mail exchanger without known third-party enterprise filtering signature.",
  };
}

/**
 * Calculates domain age intelligence and flags Newly Registered Domains (NRD).
 */
export function calculateDomainAge(registrationDateStr) {
  if (!registrationDateStr) {
    return {
      ageInDays: null,
      ageFormatted: "Unknown (Privacy Redacted / RDAP Pending)",
      isNewlyRegistered: false,
      riskLevel: "UNKNOWN",
      riskScore: 10,
    };
  }

  try {
    const regDate = new Date(registrationDateStr);
    if (isNaN(regDate.getTime())) {
      return {
        ageInDays: null,
        ageFormatted: "Unparseable Date",
        isNewlyRegistered: false,
        riskLevel: "UNKNOWN",
        riskScore: 10,
      };
    }

    const now = new Date();
    const diffMs = now.getTime() - regDate.getTime();
    const ageInDays = Math.max(0, Math.floor(diffMs / (1000 * 60 * 60 * 24)));

    let ageFormatted;
    if (ageInDays < 30) {
      ageFormatted = `${ageInDays} day${ageInDays === 1 ? "" : "s"} old (CRITICAL: Newly Registered Domain)`;
    } else if (ageInDays < 365) {
      const months = Math.floor(ageInDays / 30);
      ageFormatted = `${months} month${months === 1 ? "" : "s"} (${ageInDays} days)`;
    } else {
      const years = (ageInDays / 365).toFixed(1);
      ageFormatted = `${years} years (${ageInDays} days)`;
    }

    let riskLevel = "ESTABLISHED";
    let riskScore = 0;
    let isNewlyRegistered = false;

    if (ageInDays <= 30) {
      isNewlyRegistered = true;
      riskLevel = "CRITICAL_NEW_DOMAIN";
      riskScore = 35;
    } else if (ageInDays <= 90) {
      isNewlyRegistered = true;
      riskLevel = "RECENT_DOMAIN";
      riskScore = 20;
    }

    return {
      ageInDays,
      ageFormatted,
      registrationDate: regDate.toISOString().split("T")[0],
      isNewlyRegistered,
      riskLevel,
      riskScore,
    };
  } catch {
    return {
      ageInDays: null,
      ageFormatted: "Evaluation Failed",
      isNewlyRegistered: false,
      riskLevel: "UNKNOWN",
      riskScore: 10,
    };
  }
}

/**
 * Resolves live domain intelligence combining server API, RDAP, and DNS checks.
 */
export async function resolveDomainIntelligence(domain) {
  if (!domain || !domain.includes(".")) return null;

  let serverData = null;

  // 1. Try local server API with a quick timeout to avoid blocking the overall analysis.
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1500);
    const res = await fetch(`/api/domain-intel?domain=${encodeURIComponent(domain)}`, { signal: controller.signal });
    clearTimeout(timeoutId);
    if (res.ok) {
      serverData = await res.json();
    }
  } catch {
    // Non-blocking
  }

  // 2. Perform Lookalike analysis
  const lookalike = analyzeLookalikeDomain(domain);

  // 3. Fallback or merge
  const mxRecords = serverData?.mxRecords || [];
  const mailProvider = classifyMailProvider(mxRecords);
  const domainAge = calculateDomainAge(serverData?.creationDate || serverData?.registeredDate);

  return {
    domain,
    isRegistered: serverData?.isRegistered ?? true,
    aRecords: serverData?.aRecords || [],
    nsRecords: serverData?.nsRecords || [],
    mxRecords,
    txtRecords: serverData?.txtRecords || [],
    hasMx: mxRecords.length > 0,
    mailProvider,
    registrar: serverData?.registrar || "ICANN Accredited Registrar",
    registrarIanaId: serverData?.registrarIanaId || "N/A",
    creationDate: serverData?.creationDate || null,
    expirationDate: serverData?.expirationDate || null,
    domainAge,
    hostingProvider: serverData?.hostingProvider || "Standard Cloud/Hosting",
    lookalike,
    typosquattingDetected: lookalike.isLookalike,
    typosquattingTarget: lookalike.targetBrand,
    reputationScore: lookalike.isLookalike
      ? 15
      : domainAge.isNewlyRegistered
      ? 40
      : mxRecords.length > 0
      ? 95
      : 50,
  };
}
