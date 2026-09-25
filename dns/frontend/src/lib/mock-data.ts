import {
  DashboardBundleData,
  DomainItem,
  ClientItem,
  DomainInvestigationData,
  ClientInvestigationData,
  DomainDetailData,
  ClientDetailData,
  SystemStatusData,
} from "@/types/api";

export const MOCK_DASHBOARD_BUNDLE: DashboardBundleData = {
  summary: {
    total_queries: 4829104,
    total_threats: 14280,
    threats_blocked_pct: 4.8,
    unique_clients: 342,
    unique_domains: 89120,
    last_pipeline_run_at: new Date().toISOString(),
  },
  timeseries: [
    { time_bucket: "2026-08-28T00:00:00Z", total_queries: 184200, threat_queries: 820 },
    { time_bucket: "2026-08-28T02:00:00Z", total_queries: 142100, threat_queries: 610 },
    { time_bucket: "2026-08-28T04:00:00Z", total_queries: 112400, threat_queries: 430 },
    { time_bucket: "2026-08-28T06:00:00Z", total_queries: 245000, threat_queries: 1150 },
    { time_bucket: "2026-08-28T08:00:00Z", total_queries: 489200, threat_queries: 2410 },
    { time_bucket: "2026-08-28T10:00:00Z", total_queries: 612400, threat_queries: 3120 },
    { time_bucket: "2026-08-28T12:00:00Z", total_queries: 789100, threat_queries: 4210 },
    { time_bucket: "2026-08-28T14:00:00Z", total_queries: 692000, threat_queries: 3480 },
    { time_bucket: "2026-08-28T16:00:00Z", total_queries: 541000, threat_queries: 2190 },
    { time_bucket: "2026-08-28T18:00:00Z", total_queries: 412000, threat_queries: 1420 },
    { time_bucket: "2026-08-28T20:00:00Z", total_queries: 324000, threat_queries: 980 },
    { time_bucket: "2026-08-28T22:00:00Z", total_queries: 284000, threat_queries: 760 },
  ],
  categories: [
    { category: "Command and Control (C2)", count: 5420, pct: 38.0 },
    { category: "Phishing / Credential Harvesting", count: 4110, pct: 28.8 },
    { category: "DNS Tunneling / Exfiltration", count: 2310, pct: 16.2 },
    { category: "DGA (Algorithmically Generated)", count: 1420, pct: 9.9 },
    { category: "Cryptomining & Abuse", count: 1020, pct: 7.1 },
  ],
  top_domains: [
    { domain: "api.github.com", query_count: 842100, label: "clean", threat_score: 2, last_seen: new Date().toISOString() },
    { domain: "gateway.discord.gg", query_count: 612400, label: "clean", threat_score: 5, last_seen: new Date().toISOString() },
    { domain: "telemetry.cloud-metrics.ru", query_count: 384200, label: "suspicious", threat_score: 68, last_seen: new Date().toISOString() },
    { domain: "auth-portal.sso-verify.cc", query_count: 142900, label: "malicious", threat_score: 94, last_seen: new Date().toISOString() },
    { domain: "update.system-patcher.top", query_count: 98400, label: "malicious", threat_score: 89, last_seen: new Date().toISOString() },
    { domain: "cdn.jsdelivr.net", query_count: 942100, label: "clean", threat_score: 1, last_seen: new Date().toISOString() },
  ],
  top_clients: [
    { client_ip: "192.168.1.105", query_count: 341200, malicious_query_count: 420, last_seen: new Date().toISOString() },
    { client_ip: "10.0.4.22", query_count: 289100, malicious_query_count: 14, last_seen: new Date().toISOString() },
    { client_ip: "172.16.8.99", query_count: 215400, malicious_query_count: 1280, last_seen: new Date().toISOString() },
    { client_ip: "192.168.1.140", query_count: 184200, malicious_query_count: 0, last_seen: new Date().toISOString() },
    { client_ip: "10.0.12.54", query_count: 142800, malicious_query_count: 3, last_seen: new Date().toISOString() },
  ],
  recent_flagged: [
    { domain: "auth-portal.sso-verify.cc", label: "malicious", label_reason: "High-confidence credential phishing portal spoofing Okta/Microsoft SSO", ti_source: "URLhaus + AlienVault", confidence: 96, flagged_at: new Date(Date.now() - 2 * 60000).toISOString() },
    { domain: "update.system-patcher.top", label: "malicious", label_reason: "Cobalt Strike C2 payload delivery endpoint", ti_source: "ThreatFox C2", confidence: 92, flagged_at: new Date(Date.now() - 8 * 60000).toISOString() },
    { domain: "telemetry.cloud-metrics.ru", label: "suspicious", label_reason: "Newly registered high-entropy domain generating abnormal burst queries", ti_source: "Tranco / Entropy Engine", confidence: 74, flagged_at: new Date(Date.now() - 15 * 60000).toISOString() },
    { domain: "dga-v2-7x92kp.biz", label: "malicious", label_reason: "DGA domain matching known Mirai botnet seed algorithm", ti_source: "Internal DGA Classifier", confidence: 88, flagged_at: new Date(Date.now() - 22 * 60000).toISOString() },
    { domain: "fastflux-node99.asia", label: "malicious", label_reason: "Fast-flux DNS rotation with 40+ rapid TTL changes in 1 hour", ti_source: "Passive DNS Feed", confidence: 95, flagged_at: new Date(Date.now() - 34 * 60000).toISOString() },
  ],
};

export const MOCK_DOMAINS: DomainItem[] = [
  {
    domain: "auth-portal.sso-verify.cc",
    total_queries: 142900,
    query_count: 142900,
    unique_clients: 34,
    threat_count: 142900,
    malicious_count: 142900,
    suspicious_count: 0,
    clean_count: 0,
    last_label: "malicious",
    label: "malicious",
    threat_score: 94,
    confidence: 96,
    last_ti_source: "URLhaus",
    label_reason: "Credential harvesting portal",
    first_seen: "2026-08-20T10:14:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    domain: "update.system-patcher.top",
    total_queries: 98400,
    query_count: 98400,
    unique_clients: 18,
    threat_count: 98400,
    malicious_count: 98400,
    suspicious_count: 0,
    clean_count: 0,
    last_label: "malicious",
    label: "malicious",
    threat_score: 89,
    confidence: 92,
    last_ti_source: "ThreatFox",
    label_reason: "Cobalt Strike C2 server",
    first_seen: "2026-08-22T08:30:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    domain: "telemetry.cloud-metrics.ru",
    total_queries: 384200,
    query_count: 384200,
    unique_clients: 88,
    threat_count: 14200,
    malicious_count: 0,
    suspicious_count: 14200,
    clean_count: 370000,
    last_label: "suspicious",
    label: "suspicious",
    threat_score: 68,
    confidence: 74,
    last_ti_source: "Tranco",
    label_reason: "Uncategorized Russian ASN burst traffic",
    first_seen: "2026-08-25T14:20:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    domain: "dga-v2-7x92kp.biz",
    total_queries: 42100,
    query_count: 42100,
    unique_clients: 12,
    threat_count: 42100,
    malicious_count: 42100,
    suspicious_count: 0,
    clean_count: 0,
    last_label: "malicious",
    label: "malicious",
    threat_score: 91,
    confidence: 88,
    last_ti_source: "Classifier",
    label_reason: "DGA botnet callback",
    first_seen: "2026-08-27T19:00:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    domain: "fastflux-node99.asia",
    total_queries: 87600,
    query_count: 87600,
    unique_clients: 26,
    threat_count: 87600,
    malicious_count: 87600,
    suspicious_count: 0,
    clean_count: 0,
    last_label: "malicious",
    label: "malicious",
    threat_score: 95,
    confidence: 95,
    last_ti_source: "Passive DNS",
    label_reason: "Fast-flux proxy network",
    first_seen: "2026-08-26T11:45:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    domain: "tunnel-data.cdn-storage.org",
    total_queries: 231400,
    query_count: 231400,
    unique_clients: 5,
    threat_count: 231400,
    malicious_count: 231400,
    suspicious_count: 0,
    clean_count: 0,
    last_label: "malicious",
    label: "malicious",
    threat_score: 98,
    confidence: 99,
    last_ti_source: "Entropy Engine",
    label_reason: "High volume base64 TXT DNS tunneling",
    first_seen: "2026-08-27T02:10:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    domain: "api.github.com",
    total_queries: 842100,
    query_count: 842100,
    unique_clients: 312,
    threat_count: 0,
    malicious_count: 0,
    suspicious_count: 0,
    clean_count: 842100,
    last_label: "clean",
    label: "clean",
    threat_score: 2,
    confidence: 99,
    last_ti_source: "Tranco Top 100",
    label_reason: "Verified Developer API",
    first_seen: "2026-01-01T00:00:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    domain: "gateway.discord.gg",
    total_queries: 612400,
    query_count: 612400,
    unique_clients: 245,
    threat_count: 0,
    malicious_count: 0,
    suspicious_count: 0,
    clean_count: 612400,
    last_label: "clean",
    label: "clean",
    threat_score: 5,
    confidence: 99,
    last_ti_source: "Tranco Top 500",
    label_reason: "Communication Gateway",
    first_seen: "2026-01-01T00:00:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    domain: "cdn.jsdelivr.net",
    total_queries: 942100,
    query_count: 942100,
    unique_clients: 338,
    threat_count: 0,
    malicious_count: 0,
    suspicious_count: 0,
    clean_count: 942100,
    last_label: "clean",
    label: "clean",
    threat_score: 1,
    confidence: 99,
    last_ti_source: "Tranco Top 500",
    label_reason: "Public CDN Infrastructure",
    first_seen: "2026-01-01T00:00:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    domain: "connectivitycheck.gstatic.com",
    total_queries: 1420000,
    query_count: 1420000,
    unique_clients: 342,
    threat_count: 0,
    malicious_count: 0,
    suspicious_count: 0,
    clean_count: 1420000,
    last_label: "clean",
    label: "clean",
    threat_score: 0,
    confidence: 100,
    last_ti_source: "Google Infrastructure",
    label_reason: "Operating System Probe",
    first_seen: "2026-01-01T00:00:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    domain: "login.microsoftonline.com",
    total_queries: 789400,
    query_count: 789400,
    unique_clients: 320,
    threat_count: 0,
    malicious_count: 0,
    suspicious_count: 0,
    clean_count: 789400,
    last_label: "clean",
    label: "clean",
    threat_score: 3,
    confidence: 99,
    last_ti_source: "Microsoft Azure",
    label_reason: "Enterprise Identity Provider",
    first_seen: "2026-01-01T00:00:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    domain: "crypto-pool.xmr-miner.online",
    total_queries: 65400,
    query_count: 65400,
    unique_clients: 4,
    threat_count: 65400,
    malicious_count: 65400,
    suspicious_count: 0,
    clean_count: 0,
    last_label: "malicious",
    label: "malicious",
    threat_score: 93,
    confidence: 98,
    last_ti_source: "CoinBlock TI",
    label_reason: "Stratum cryptomining pool endpoint",
    first_seen: "2026-08-24T16:00:00Z",
    last_seen: new Date().toISOString(),
  },
];

export const MOCK_CLIENTS: ClientItem[] = [
  {
    client_ip: "172.16.8.99",
    total_queries: 215400,
    unique_domains: 412,
    threat_count: 1280,
    malicious_count: 1280,
    suspicious_count: 0,
    clean_count: 214120,
    first_seen: "2026-08-15T08:00:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    client_ip: "192.168.1.105",
    total_queries: 341200,
    unique_domains: 645,
    threat_count: 420,
    malicious_count: 420,
    suspicious_count: 0,
    clean_count: 340780,
    first_seen: "2026-08-10T12:00:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    client_ip: "10.0.4.22",
    total_queries: 289100,
    unique_domains: 512,
    threat_count: 14,
    malicious_count: 0,
    suspicious_count: 14,
    clean_count: 289086,
    first_seen: "2026-08-01T00:00:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    client_ip: "192.168.1.140",
    total_queries: 184200,
    unique_domains: 380,
    threat_count: 0,
    malicious_count: 0,
    suspicious_count: 0,
    clean_count: 184200,
    first_seen: "2026-08-01T00:00:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    client_ip: "10.0.12.54",
    total_queries: 142800,
    unique_domains: 290,
    threat_count: 3,
    malicious_count: 0,
    suspicious_count: 3,
    clean_count: 142797,
    first_seen: "2026-08-05T09:30:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    client_ip: "192.168.2.88",
    total_queries: 98400,
    unique_domains: 195,
    threat_count: 580,
    malicious_count: 580,
    suspicious_count: 0,
    clean_count: 97820,
    first_seen: "2026-08-20T14:15:00Z",
    last_seen: new Date().toISOString(),
  },
  {
    client_ip: "10.10.1.200",
    total_queries: 412000,
    unique_domains: 780,
    threat_count: 0,
    malicious_count: 0,
    suspicious_count: 0,
    clean_count: 412000,
    first_seen: "2026-07-15T00:00:00Z",
    last_seen: new Date().toISOString(),
  },
];

export interface QueryRecord {
  id: string;
  timestamp: string; // Full format: YYYY-MM-DD HH:mm:ss
  client_ip: string;
  domain: string;
  query_type: string;
  response_code: "NOERROR" | "NXDOMAIN" | "SERVFAIL" | "REFUSED";
  verdict: "malicious" | "suspicious" | "clean" | "unknown";
  risk_score: number;
  latency_ms: number;
}

export function generateMockQueries(count = 100): QueryRecord[] {
  const queryTypes = ["A", "AAAA", "TXT", "CNAME", "MX", "PTR", "SRV"];
  const domains = [
    { name: "auth-portal.sso-verify.cc", verdict: "malicious" as const, risk: 94 },
    { name: "update.system-patcher.top", verdict: "malicious" as const, risk: 89 },
    { name: "telemetry.cloud-metrics.ru", verdict: "suspicious" as const, risk: 68 },
    { name: "dga-v2-7x92kp.biz", verdict: "malicious" as const, risk: 91 },
    { name: "fastflux-node99.asia", verdict: "malicious" as const, risk: 95 },
    { name: "tunnel-data.cdn-storage.org", verdict: "malicious" as const, risk: 98 },
    { name: "api.github.com", verdict: "clean" as const, risk: 2 },
    { name: "gateway.discord.gg", verdict: "clean" as const, risk: 5 },
    { name: "cdn.jsdelivr.net", verdict: "clean" as const, risk: 1 },
    { name: "connectivitycheck.gstatic.com", verdict: "clean" as const, risk: 0 },
    { name: "login.microsoftonline.com", verdict: "clean" as const, risk: 3 },
  ];
  const clients = ["172.16.8.99", "192.168.1.105", "10.0.4.22", "192.168.1.140", "10.0.12.54", "192.168.2.88"];

  const results: QueryRecord[] = [];
  const now = Date.now();

  for (let i = 0; i < count; i++) {
    const dom = domains[i % domains.length];
    const client = clients[i % clients.length];
    const qType = queryTypes[i % queryTypes.length];
    const timeOffset = i * 18 * 1000;
    const dateObj = new Date(now - timeOffset);
    
    const pad = (n: number) => n.toString().padStart(2, "0");
    const fullTimestamp = `${dateObj.getFullYear()}-${pad(dateObj.getMonth() + 1)}-${pad(dateObj.getDate())} ${pad(dateObj.getHours())}:${pad(dateObj.getMinutes())}:${pad(dateObj.getSeconds())}`;

    results.push({
      id: `query-${i + 1}`,
      timestamp: fullTimestamp,
      client_ip: client,
      domain: dom.name,
      query_type: qType,
      response_code: dom.verdict === "malicious" ? (i % 2 === 0 ? "NXDOMAIN" : "NOERROR") : "NOERROR",
      verdict: dom.verdict,
      risk_score: dom.risk,
      latency_ms: Math.round(12 + Math.random() * 48),
    });
  }

  return results;
}

export function generateMockDomainDetail(domain: string): DomainDetailData {
  const found = MOCK_DOMAINS.find((d) => d.domain === domain) || MOCK_DOMAINS[0];
  const isMalicious = found.label === "malicious";
  const isSuspicious = found.label === "suspicious";

  return {
    domain: found.domain,
    label: found.label,
    threat_score: found.threat_score,
    confidence: found.confidence,
    stats: {
      queries: found.total_queries,
      total_queries: found.total_queries,
      unique_clients: found.unique_clients,
      threats: found.threat_count,
      threat_count: found.threat_count,
      malicious: found.malicious_count,
      suspicious: found.suspicious_count,
      clean: found.clean_count,
    },
    first_seen: found.first_seen,
    last_seen: found.last_seen,
    threat_intel: {
      source: found.last_ti_source,
      label_reason: found.label_reason,
    },
    network: {
      asn: isMalicious ? "AS48234" : "AS13335",
      asn_org: isMalicious ? "Bulletproof Host Network" : "Cloudflare / Global CDN",
      country: isMalicious ? "RU" : "US",
      resolved_ips: isMalicious ? "185.220.101.4" : "104.244.42.1",
    },
    dns: {
      query_type_breakdown: { A: Math.round(found.total_queries * 0.85), AAAA: Math.round(found.total_queries * 0.1), TXT: Math.round(found.total_queries * 0.05) },
      response_code_breakdown: { NOERROR: Math.round(found.total_queries * 0.9), NXDOMAIN: Math.round(found.total_queries * 0.1) },
      domain_age_days: isMalicious ? 14 : 4200,
    },
    enrichment: {},
    source: "dashboard_db",
  };
}

export function generateMockClientDetail(clientIp: string): ClientDetailData {
  const found = MOCK_CLIENTS.find((c) => c.client_ip === clientIp) || MOCK_CLIENTS[0];

  return {
    client_ip: found.client_ip,
    stats: {
      total_queries: found.total_queries,
      unique_domains: found.unique_domains,
      threat_count: found.threat_count,
      malicious_count: found.malicious_count,
      suspicious_count: found.suspicious_count || 0,
      clean_count: found.clean_count || found.total_queries,
    },
    first_seen: found.first_seen,
    last_seen: found.last_seen,
    top_domains: [
      { domain: "api.github.com", count: 14200 },
      { domain: "gateway.discord.gg", count: 8900 },
      { domain: "auth-portal.sso-verify.cc", count: 420 },
    ],
    source: "dashboard_db",
  };
}

export function generateMockSystemStatus(): SystemStatusData {
  return {
    dashboard_db_available: true,
    aggregation: {
      name: "dns_threat_pipeline_v1",
      last_watermark_id: 4829104,
      last_watermark_ts: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
    last_run: {
      run_id: "run-98421",
      status: "COMPLETED",
      started_at: new Date(Date.now() - 120000).toISOString(),
      finished_at: new Date().toISOString(),
      duration_ms: 142,
      source_type: "PARQUET_STREAM",
      rows_processed: 24500,
      batches_processed: 12,
      error_message: null,
    },
  };
}

export function generateMockDomainInvestigation(domain: string): DomainInvestigationData {
  const isMalicious = domain.includes("verify") || domain.includes("patcher") || domain.includes("dga") || domain.includes("tunnel");
  const isSuspicious = domain.includes("telemetry") || domain.includes(".ru") || domain.includes(".top");
  const label = isMalicious ? "malicious" : isSuspicious ? "suspicious" : "clean";
  const risk_score = isMalicious ? 92 : isSuspicious ? 68 : 5;

  return {
    domain: {
      queried: domain,
      normalized: domain.toLowerCase(),
      fqdn: domain,
      registered_domain: domain.split(".").slice(-2).join("."),
      tld: domain.split(".").slice(-1)[0] || "com",
      subdomain: domain.split(".").length > 2 ? domain.split(".")[0] : "",
    },
    classification: {
      status: isMalicious ? "KNOWN_MALICIOUS" : isSuspicious ? "REVIEW_NEEDED" : "KNOWN_CLEAN",
      label,
      confidence: isMalicious ? 95 : isSuspicious ? 76 : 99,
      risk_score,
      reason: isMalicious ? "Matched known C2 endpoint pattern" : "Domain verified against security benchmarks.",
      source: "SOC_TI_ENGINE",
    },
    local_intelligence: {
      urlhaus: {
        provider: "URLhaus",
        matched: isMalicious,
        status: isMalicious ? "MATCHED" : "CLEAN",
        provenance: "LOCAL",
        freshness: "LIVE_LOOKUP",
      },
      tranco: {
        provider: "Tranco",
        matched: !isMalicious,
        status: !isMalicious ? "MATCHED" : "CLEAN",
        provenance: "LOCAL",
        freshness: "LIVE_LOOKUP",
      },
    },
    external_intelligence: {
      status: "AVAILABLE",
      virustotal: { provider: "virustotal", status: isMalicious ? "AVAILABLE" : "CLEAN", malicious_count: isMalicious ? 14 : 0, suspicious_count: isSuspicious ? 3 : 0 },
      otx: { provider: "otx", status: isMalicious ? "AVAILABLE" : "CLEAN" },
    },
    correlation: {
      engine: "GRAPH_CORRELATION_V2",
      status: "EVALUATED",
      score: risk_score,
      threshold: 70,
      confidence: 90,
      verdict: label,
      provenance: "COMPUTED",
    },
    dns_activity: {
      status: "OBSERVED",
      query_count: isMalicious ? 48900 : 842100,
      unique_clients: isMalicious ? 12 : 240,
      malicious_count: isMalicious ? 48900 : 0,
      suspicious_count: 0,
      clean_count: isMalicious ? 0 : 842100,
      first_seen: "2026-08-01T00:00:00Z",
      last_seen: new Date().toISOString(),
      query_types: { A: isMalicious ? 42000 : 750000, AAAA: isMalicious ? 5000 : 82000, TXT: isMalicious ? 1900 : 10100 },
      response_codes: { NOERROR: isMalicious ? 45000 : 840000, NXDOMAIN: isMalicious ? 3900 : 2100 },
    },
    reputation: {
      active_record: true,
      status: label,
      source: isMalicious ? "Threat Intelligence Feed" : "Internal Resolver",
      confidence: 95,
      matched_domain: domain,
      first_seen: "2026-08-01T00:00:00Z",
      last_seen: new Date().toISOString(),
    },
    querying_clients: [
      { client_ip: "172.16.8.99", query_count: 1420, last_seen: new Date().toISOString() },
      { client_ip: "192.168.1.105", query_count: 820, last_seen: new Date().toISOString() },
      { client_ip: "10.0.4.22", query_count: 14, last_seen: new Date().toISOString() },
    ],
    investigation: {
      known: true,
      why: isMalicious ? "Flagged due to direct threat signature correlation." : "Domain verified against security benchmarks.",
      evidence: [],
    },
    duration_ms: 24,
  };
}

export function generateMockClientInvestigation(clientIp: string): ClientInvestigationData {
  const isHighRisk = clientIp.includes("99") || clientIp.includes("105");

  return {
    client: {
      ip: clientIp,
      network_type: "Internal Corporate LAN (VLAN 10)",
      first_seen: "2026-08-01T00:00:00Z",
      last_seen: new Date().toISOString(),
      total_queries: isHighRisk ? 341200 : 98400,
    },
    summary: {
      total_queries: isHighRisk ? 341200 : 98400,
      unique_domains: isHighRisk ? 645 : 190,
      malicious_queries: isHighRisk ? 1280 : 0,
      malicious_domains: isHighRisk ? 8 : 0,
      suspicious_queries: isHighRisk ? 420 : 12,
      suspicious_domains: isHighRisk ? 4 : 1,
      benign_queries: isHighRisk ? 339500 : 98388,
      benign_domains: isHighRisk ? 633 : 189,
      unknown_queries: 0,
      unknown_domains: 0,
      threat_traffic_ratio: isHighRisk ? 0.048 : 0.0,
      threat_domain_ratio: isHighRisk ? 0.018 : 0.0,
      threat_ratio: isHighRisk ? 0.048 : 0.0,
      risk_status: isHighRisk ? "THREATS_DETECTED" : "CLEAN_TRAFFIC",
    },
    threat_domains: [
      { domain: "auth-portal.sso-verify.cc", label: "malicious", query_count: 420, ti_source: "URLhaus" },
      { domain: "update.system-patcher.top", label: "malicious", query_count: 210, ti_source: "ThreatFox" },
      { domain: "telemetry.cloud-metrics.ru", label: "suspicious", query_count: 1420, ti_source: "Tranco" },
    ],
    top_domains: [
      { domain: "api.github.com", label: "clean", query_count: 84200, ti_source: "Tranco" },
      { domain: "gateway.discord.gg", label: "clean", query_count: 48900, ti_source: "Tranco" },
      { domain: "auth-portal.sso-verify.cc", label: "malicious", query_count: 420, ti_source: "URLhaus" },
      { domain: "update.system-patcher.top", label: "malicious", query_count: 210, ti_source: "ThreatFox" },
    ],
    recent_activity: [
      { timestamp: new Date().toISOString(), domain: "auth-portal.sso-verify.cc", query_type: "A", response_code: "NOERROR", final_label: "malicious", ti_source: "URLhaus" },
      { timestamp: new Date(Date.now() - 60000).toISOString(), domain: "api.github.com", query_type: "A", response_code: "NOERROR", final_label: "clean", ti_source: "Tranco" },
      { timestamp: new Date(Date.now() - 120000).toISOString(), domain: "telemetry.cloud-metrics.ru", query_type: "AAAA", response_code: "NOERROR", final_label: "suspicious", ti_source: "Tranco" },
    ],
    duration_ms: 18,
  };
}
