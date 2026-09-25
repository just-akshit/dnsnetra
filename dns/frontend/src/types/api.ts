export interface MetricsSummary {
  id?: number;
  total_queries: number;
  total_threats: number;
  threats_blocked_pct: number;
  unique_clients: number;
  unique_domains: number;
  last_pipeline_run_at: string;
}

export interface TimeseriesBucket {
  time_bucket: string;
  total_queries: number;
  threat_queries: number;
}

export interface ThreatCategory {
  category: string;
  count: number;
  pct: number;
}

export interface TopDomain {
  domain: string;
  query_count: number;
  label: string;
  threat_score: number | null;
  last_seen: string;
}

export interface TopClient {
  client_ip: string;
  query_count: number;
  malicious_query_count: number;
  last_seen: string;
}

export interface RecentFlaggedDomain {
  domain: string;
  label: string;
  label_reason?: string | null;
  ti_source?: string | null;
  confidence?: number | null;
  flagged_at: string;
}

export interface AggregationWatermark {
  last_watermark_id: number;
  last_watermark_ts: string | null;
  last_status?: string | null;
  last_run_at?: string | null;
  last_duration_ms?: number | null;
  name?: string;
  updated_at?: string | null;
}

export interface DashboardBundleData {
  summary: MetricsSummary | null;
  timeseries: TimeseriesBucket[];
  categories: ThreatCategory[];
  top_domains: TopDomain[];
  top_clients: TopClient[];
  recent_flagged: RecentFlaggedDomain[];
  aggregation?: AggregationWatermark | null;
}

export interface DashboardBundleResponse {
  status: string;
  data: DashboardBundleData;
}

export interface PaginationMeta {
  page: number;
  page_size: number;
  total: number;
  pages: number;
}

export interface DomainItem {
  domain: string;
  total_queries: number;
  query_count: number;
  unique_clients: number;
  threat_count: number;
  malicious_count: number;
  suspicious_count: number;
  clean_count: number;
  last_label: string;
  label: string;
  threat_score: number | null;
  confidence: number | null;
  last_ti_source: string | null;
  label_reason: string | null;
  first_seen: string | null;
  last_seen: string | null;
}

export interface DomainsResponse {
  data: DomainItem[];
  meta: PaginationMeta;
}

export interface DomainDetailData {
  domain: string;
  label: string;
  threat_score: number | null;
  confidence: number | null;
  stats: {
    queries: number;
    total_queries: number;
    unique_clients: number;
    threats: number;
    threat_count: number;
    malicious: number;
    suspicious: number;
    clean: number;
  };
  first_seen: string | null;
  last_seen: string | null;
  threat_intel: {
    source: string | null;
    label_reason: string | null;
  };
  network: {
    asn: string | null;
    asn_org: string | null;
    country: string | null;
    resolved_ips: string | null;
  };
  dns: {
    query_type_breakdown: Record<string, number>;
    response_code_breakdown: Record<string, number>;
    domain_age_days: number | null;
  };
  enrichment: Record<string, any>;
  source: string;
}

export interface DomainDetailResponse {
  data: DomainDetailData;
}

export interface ClientItem {
  client_ip: string;
  total_queries: number;
  unique_domains: number;
  threat_count: number;
  malicious_count: number;
  suspicious_count?: number;
  clean_count?: number;
  first_seen: string | null;
  last_seen: string | null;
}

export interface ClientsResponse {
  data: ClientItem[];
  meta: PaginationMeta;
}

export interface ClientTopDomain {
  domain: string;
  count: number;
}

export interface ClientDetailData {
  client_ip: string;
  stats: {
    total_queries: number;
    unique_domains: number;
    threat_count: number;
    malicious_count: number;
    suspicious_count: number;
    clean_count: number;
  };
  first_seen: string | null;
  last_seen: string | null;
  top_domains: ClientTopDomain[];
  source: string;
}

export interface ClientDetailResponse {
  data: ClientDetailData;
}

export interface AggregationRunAudit {
  run_id: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
  source_type: string | null;
  rows_processed: number;
  batches_processed: number;
  error_message: string | null;
}

export interface SystemStatusData {
  dashboard_db_available: boolean;
  aggregation?: {
    name: string;
    last_watermark_id: number;
    last_watermark_ts: string | null;
    updated_at: string | null;
  } | null;
  last_run?: AggregationRunAudit | null;
  error?: string;
}

// ===========================================================================
// Phase 3 — Investigation Types
// ===========================================================================

export interface NormalizedDomainInfo {
  queried: string;
  normalized: string;
  fqdn: string;
  registered_domain: string;
  tld: string;
  subdomain: string;
}

export type CanonicalVerdict = "malicious" | "benign" | "review_needed" | "unknown";

export interface ClassificationInfo {
  status: "KNOWN_MALICIOUS" | "POPULAR_BENIGN_CONTEXT" | "KNOWN_CLEAN" | "REVIEW_NEEDED" | "UNKNOWN";
  label: CanonicalVerdict | string;
  risk_score: number;
  confidence: number;
  reason: string;
  source: string;
  scope?: string | null;
}

export interface LocalIntelSource {
  provider: string;
  matched: boolean;
  status: string;
  result?: string | null;
  provenance: "LOCAL" | "REAL" | "PERSISTED" | "COMPUTED";
  freshness: "LIVE_LOOKUP" | "ACTIVE_REPUTATION" | "HISTORICAL" | "NOT_APPLICABLE";
  match_scope?: string;
  matched_domain?: string;
  confidence?: number;
  reason?: string;
}

export interface LocalIntelligenceData {
  tranco: LocalIntelSource;
  urlhaus: LocalIntelSource;
}

export interface ExternalProviderData {
  provider: string;
  status: "AVAILABLE" | "NO_DATA" | "NOT_CONFIGURED" | "PROVIDER_FAILURE" | "SKIPPED" | string;
  result?: "MALICIOUS" | "CLEAN" | string | null;
  provenance?: "LOCAL" | "REAL" | "PERSISTED" | "COMPUTED" | null;
  freshness?: "LIVE_LOOKUP" | "ACTIVE_REPUTATION" | "HISTORICAL" | "NOT_APPLICABLE" | string;
  availability_reason?: string | null;
  malicious_count?: number;
  harmless_count?: number;
  suspicious_count?: number;
  confidence?: number | null;
  observed_at?: string | null;
  reason?: string | null;
  error?: string | null;
}

export interface ExternalIntelligenceData {
  status: string;
  provenance?: string | null;
  freshness?: string | null;
  virustotal: ExternalProviderData;
  otx: ExternalProviderData;
}

export interface CorrelationData {
  engine: string;
  status?: "EVALUATED" | "NOT_EVALUATED" | "NOT_APPLICABLE" | "FAILED" | string;
  score: number | null;
  threshold: number;
  confidence: number | null;
  verdict: string | null;
  provenance: "COMPUTED" | "PERSISTED" | "LOCAL" | "REAL" | null;
  freshness?: "LIVE_LOOKUP" | "ACTIVE_REPUTATION" | "HISTORICAL" | "NOT_APPLICABLE" | string;
  reason?: string;
}



export interface DNSActivityData {
  status: "OBSERVED" | "NOT_OBSERVED";
  query_count: number;
  unique_clients: number;
  malicious_count: number;
  suspicious_count: number;
  clean_count: number;
  first_seen: string | null;
  last_seen: string | null;
  query_types: Record<string, number>;
  response_codes: Record<string, number>;
}

export interface ActiveReputationData {
  active_record: boolean;
  status?: string | null;
  source?: string | null;
  confidence?: number | null;
  match_scope?: string | null;
  matched_domain?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
}

export interface QueryingClientItem {
  client_ip: string;
  query_count?: number | null;
  last_seen?: string | null;
}

export interface EvidenceItem {
  provider: string;
  result: string;
  provenance: "LOCAL" | "REAL" | "PERSISTED" | "COMPUTED" | "NO_DATA";
  freshness?: "LIVE_LOOKUP" | "ACTIVE_REPUTATION" | "HISTORICAL" | "NOT_APPLICABLE";
  scope?: string;
  matched_domain?: string;
  score?: number;
  threshold?: number;
  confidence?: number;
}

// ===========================================================================
// Phase 4 — Domain & Client Enrichment Types
// ===========================================================================

export interface MXRecord {
  priority: number;
  exchange: string;
}

export interface DNSEnrichmentData {
  status: "AVAILABLE" | "NO_DATA" | "PROVIDER_FAILURE" | string;
  a: string[];
  aaaa: string[];
  cname: string[];
  ns: string[];
  mx: MXRecord[];
  provider: string;
  provenance: "LOCAL" | "REAL" | "PERSISTED" | "COMPUTED" | string;
  freshness: "LIVE_LOOKUP" | "ACTIVE_REPUTATION" | "HISTORICAL" | "NOT_APPLICABLE" | string;
  error?: string | null;
}

export interface GeoEnrichmentData {
  status: "AVAILABLE" | "NO_DATA" | "PROVIDER_FAILURE" | "NOT_CONFIGURED" | "NOT_APPLICABLE" | string;
  country?: string | null;
  country_code?: string | null;
  region?: string | null;
  city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  timezone?: string | null;
  postal?: string | null;
  accuracy_radius?: number | null;
  provider: string;
  provenance: "LOCAL" | "REAL" | "PERSISTED" | "COMPUTED" | string;
  freshness: "LIVE_LOOKUP" | "ACTIVE_REPUTATION" | "HISTORICAL" | "NOT_APPLICABLE" | string;
  error?: string | null;
}

export interface NetworkEnrichmentData {
  status: "AVAILABLE" | "NO_DATA" | "PROVIDER_FAILURE" | "NOT_APPLICABLE" | string;
  asn?: string | null;
  asn_organization?: string | null;
  isp?: string | null;
  organization?: string | null;
  connection_type?: string | null;
  provider: string;
  provenance: "LOCAL" | "REAL" | "PERSISTED" | "COMPUTED" | string;
  freshness: "LIVE_LOOKUP" | "ACTIVE_REPUTATION" | "HISTORICAL" | "NOT_APPLICABLE" | string;
  error?: string | null;
}

export interface IPEnrichmentItem {
  ip: string;
  ip_type: string;
  geo: GeoEnrichmentData;
  network: NetworkEnrichmentData;
}

export interface RegistrationEnrichmentData {
  status: "AVAILABLE" | "NO_DATA" | "PROVIDER_FAILURE" | string;
  source: string;
  registrar?: string | null;
  registrar_id?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  expires_at?: string | null;
  domain_status: string[];
  nameservers: string[];
  provider: string;
  provenance: "LOCAL" | "REAL" | "PERSISTED" | "COMPUTED" | string;
  freshness: "LIVE_LOOKUP" | "ACTIVE_REPUTATION" | "HISTORICAL" | "NOT_APPLICABLE" | string;
  error?: string | null;
}

export interface DomainEnrichmentData {
  status: "AVAILABLE" | "PARTIAL" | "NO_DATA" | "PROVIDER_FAILURE" | "NOT_CONFIGURED" | string;
  dns: DNSEnrichmentData;
  ips: IPEnrichmentItem[];
  registration: RegistrationEnrichmentData;
  duration_ms?: number;
}

export interface ClientIPEnrichmentData {
  ip: string;
  ip_type: string;
  status: "AVAILABLE" | "PARTIAL" | "NO_DATA" | "PROVIDER_FAILURE" | "NOT_CONFIGURED" | "NOT_APPLICABLE" | string;
  geo: GeoEnrichmentData;
  network: NetworkEnrichmentData;
  duration_ms?: number;
}

export interface DomainInvestigationData {
  domain: NormalizedDomainInfo;
  classification: ClassificationInfo;
  local_intelligence: LocalIntelligenceData;
  external_intelligence: ExternalIntelligenceData;
  correlation: CorrelationData;
  dns_activity: DNSActivityData;
  reputation: ActiveReputationData;
  querying_clients: QueryingClientItem[];
  investigation: {
    known: boolean;
    why: string;
    evidence: EvidenceItem[];
  };
  enrichment?: DomainEnrichmentData;
  duration_ms: number;
}

export interface DomainInvestigationResponse {
  status: string;
  data: DomainInvestigationData;
}

export interface ClientInvestigationEndpointInfo {
  ip: string;
  network_type: string;
  first_seen: string | null;
  last_seen: string | null;
  total_queries: number;
}

export interface ClientInvestigationSummary {
  total_queries: number;
  unique_domains: number;
  malicious_queries: number;
  malicious_domains: number;
  suspicious_queries: number;
  suspicious_domains: number;
  benign_queries: number;
  benign_domains: number;
  unknown_queries: number;
  unknown_domains: number;
  threat_traffic_ratio: number;
  threat_domain_ratio: number;
  threat_ratio: number;
  risk_status: "THREATS_DETECTED" | "CLEAN_TRAFFIC";
}

export interface ClientThreatItem {
  domain: string;
  label: string;
  query_count: number;
  ti_source?: string;
  provenance?: string;
  last_seen?: string | null;
}

export interface ClientActivityLogItem {
  timestamp: string;
  domain: string;
  query_type: string;
  response_code: string;
  final_label: string;
  ti_source?: string;
}

export interface ClientInvestigationData {
  client: ClientInvestigationEndpointInfo;
  summary: ClientInvestigationSummary;
  threat_domains: ClientThreatItem[];
  top_domains: ClientThreatItem[];
  recent_activity: ClientActivityLogItem[];
  enrichment?: ClientIPEnrichmentData;
  duration_ms: number;
}

export interface ClientInvestigationResponse {
  status: string;
  data: ClientInvestigationData;
}

// ------------------------------------------------------------------
// Time-Window DNS Analytics (Phase 4.2)
// ------------------------------------------------------------------

export interface AnalyticsWindow {
  start: string;
  end: string;
  duration_minutes: number;
}

export interface DomainAnalyticsMetrics {
  total_queries: number;
  unique_fqdns: number;
  unique_registered_domains: number;
  unique_clients: number;
  malicious_domains: number;
  suspicious_domains: number;
}

export interface TimelineBucket {
  timestamp: string;
  queries: number;
  unique_domains: number;
}

export interface DomainAnalyticsData {
  window: AnalyticsWindow;
  metrics: DomainAnalyticsMetrics;
  timeline: TimelineBucket[];
}

export interface DomainAnalyticsResponse {
  status: string;
  data: DomainAnalyticsData;
}

// ===========================================================================
// Reports API Contracts (PostgreSQL Only)
// ===========================================================================

export interface ReportSummaryData {
  total_queries: number;
  malicious_queries: number;
  unique_domains: number;
  unique_clients: number;
  threat_percentage: number;
}

export interface ReportTimeseriesBucket {
  time_bucket: string;
  total_queries: number;
  malicious_queries: number;
}

export interface ReportOverviewData {
  time_range: {
    start: string;
    end: string;
    preset: string | null;
    bucket_seconds: number;
  };
  summary: ReportSummaryData;
  timeseries: ReportTimeseriesBucket[];
}

export interface ReportOverviewResponse {
  status: string;
  data: ReportOverviewData;
}

export interface ReportQueryItem {
  id: number;
  timestamp: string;
  client_ip: string;
  domain: string;
  query_type: string;
  final_label: string;
  ti_source: string;
  response_code: string;
}

export interface ReportDomainItem {
  domain: string;
  query_count: number;
  unique_clients: number;
  malicious_queries: number;
  first_seen: string | null;
  last_seen: string | null;
  latest_verdict: string;
}

export interface ReportMaliciousDomainItem {
  domain: string;
  query_count: number;
  unique_clients: number;
  malicious_queries: number;
  first_seen: string | null;
  last_seen: string | null;
  latest_verdict: string;
  ti_source: string;
}

export interface ReportClientItem {
  client_ip: string;
  query_count: number;
  unique_domains: number;
  malicious_queries: number;
  first_seen: string | null;
  last_seen: string | null;
}

export interface ReportPaginatedMeta {
  page: number;
  page_size: number;
  total: number;
  pages: number;
  time_range: {
    start: string;
    end: string;
    preset: string | null;
  };
}

export interface ReportPaginatedResponse<T> {
  status: string;
  data: T[];
  meta: ReportPaginatedMeta;
}

// ===========================================================================
// Entity Report Contracts (Client IP & Domain Reports)
// ===========================================================================

export interface ClientReportSummary {
  entity: string;
  entity_type: "client";
  total_queries: number;
  unique_domains: number;
  malicious_queries?: number;
  benign_queries?: number;
  review_needed_queries?: number;
  unknown_queries?: number;
  malicious_domains: number;
  benign_domains?: number;
  review_needed_domains?: number;
  unknown_domains?: number;
  clean_domains?: number;
  suspicious_domains?: number;
  first_seen: string | null;
  last_seen: string | null;
  threat_percentage: number;
}

export interface ClientQueriedDomainItem {
  domain: string;
  query_count: number;
  malicious_queries: number;
  benign_queries?: number;
  review_needed_queries?: number;
  unknown_queries?: number;
  clean_queries?: number;
  suspicious_queries?: number;
  latest_verdict: string;
  first_seen: string | null;
  last_seen: string | null;
}

export interface ClientMaliciousDomainItem {
  domain: string;
  query_count: number;
  malicious_queries: number;
  latest_verdict: string;
  ti_source: string;
  first_seen: string | null;
  last_seen: string | null;
}

export interface ClientCleanDomainItem {
  domain: string;
  query_count: number;
  latest_verdict: string;
  first_seen: string | null;
  last_seen: string | null;
}

export interface ClientReportData {
  summary: ClientReportSummary;
  most_queried_domains: ClientQueriedDomainItem[];
  malicious_domains: ClientMaliciousDomainItem[];
  benign_domains?: ClientCleanDomainItem[];
  review_needed_domains?: ClientCleanDomainItem[];
  unknown_domains?: ClientCleanDomainItem[];
  clean_domains?: ClientCleanDomainItem[];
  query_history: ReportQueryItem[];
  meta: ReportPaginatedMeta;
}

export interface DomainReportSummary {
  entity: string;
  entity_type: "domain";
  total_queries: number;
  unique_clients: number;
  malicious_queries: number;
  benign_queries?: number;
  review_needed_queries?: number;
  unknown_queries?: number;
  clean_queries?: number;
  suspicious_queries?: number;
  first_seen: string | null;
  last_seen: string | null;
  threat_percentage: number;
}

export interface DomainClientItem {
  client_ip: string;
  query_count: number;
  malicious_queries: number;
  benign_queries?: number;
  review_needed_queries?: number;
  unknown_queries?: number;
  clean_queries?: number;
  suspicious_queries?: number;
  first_seen: string | null;
  last_seen: string | null;
}

export interface DomainReportData {
  summary: DomainReportSummary;
  clients_querying: DomainClientItem[];
  query_history: ReportQueryItem[];
  meta: ReportPaginatedMeta;
}

export interface EntityReportResponse {
  status: string;
  data: ClientReportData | DomainReportData;
}






