/**
 * DNSNetra Authoritative API Client
 * Maps table state directly to FastAPI backend contracts.
 */

export interface PaginatedResult<T> {
  total: number
  limit: number
  offset: number
  has_more: boolean
  items: T[]
}

export interface DomainItem {
  domain: string
  total_queries: number
  unique_clients: number
  benign_queries: number
  malicious_queries: number
  review_needed_queries: number
  unknown_queries: number
  latest_verdict?: string | null
  first_seen: string
  last_seen: string
}

export interface ClientItem {
  client_ip: string
  total_queries: number
  unique_domains: number
  benign_queries: number
  malicious_queries: number
  review_needed_queries: number
  unknown_queries: number
  last_domain?: string | null
  last_query_type?: string | null
  first_seen: string
  last_seen: string
}

export interface QueryItem {
  id: number
  timestamp: string
  client_ip: string
  domain: string
  query_type: string
  response_code?: string | null
  final_label: string
  ti_source?: string | null
  registered_domain?: string | null
  tld?: string | null
}

export interface DailyReviewItem {
  id: number
  domain: string
  status: string
  reason?: string | null
  next_check_at?: string | null
  review_count: number
  last_seen_at?: string | null
  created_at?: string | null
  is_due: boolean
}

export interface DomainDetail {
  domain: string
  profile: {
    domain: string
    first_seen: string
    last_seen: string
    total_queries: number
    unique_clients: number
    benign_queries: number
    malicious_queries: number
    review_needed_queries: number
    unknown_queries: number
    query_type_distribution?: Record<string, number>
    last_client_ip?: string | null
    last_label?: string | null
    last_ti_source?: string | null
  }
  top_querying_clients: Array<{
    client_ip: string
    visit_count: number
    benign_visits: number
    malicious_visits: number
    review_needed_visits: number
    unknown_visits: number
    first_seen: string
    last_seen: string
  }>
  threat_intel: {
    reputation?: {
      status: string
      source: string
      confidence?: number | null
      match_scope?: string | null
      matched_domain?: string | null
      times_seen: number
      query_count: number
      first_seen: string
      last_seen: string
      last_verified_at?: string | null
    } | null
    daily_review?: {
      status: string
      review_reason?: string | null
      review_count: number
      first_seen_at: string
      last_seen_at: string
      next_check_at: string
    } | null
    reviewed_clean?: {
      status: string
      verification_source: string
      verified_at: string
      review_count: number
    } | null
  }
  recent_queries: Array<{
    id: number
    timestamp: string
    client_ip: string
    domain: string
    query_type: string
    response_code?: string | null
    final_label: string
    ti_source?: string | null
  }>
}

export interface ClientDetail {
  client_ip: string
  profile: {
    client_ip: string
    first_seen: string
    last_seen: string
    total_queries: number
    unique_domains: number
    benign_queries: number
    malicious_queries: number
    review_needed_queries: number
    unknown_queries: number
    last_domain?: string | null
    last_query_type?: string | null
  }
  top_domains: Array<{
    domain: string
    visit_count: number
    benign_visits: number
    malicious_visits: number
    review_needed_visits: number
    unknown_visits: number
    first_seen: string
    last_seen: string
  }>
  threat_activity: Array<{
    domain: string
    visit_count: number
    activity_category: string
    last_seen: string
  }>
  recent_queries: Array<{
    id: number
    timestamp: string
    client_ip: string
    domain: string
    query_type: string
    response_code?: string | null
    final_label: string
    ti_source?: string | null
  }>
}

export interface VerdictBreakdown {
  benign: number
  malicious: number
  review_needed: number
  unknown: number
}

export interface DashboardKPIs {
  total_queries: number
  total_clients: number
  unique_domains: number
  unique_clients: number
  malicious_domains: number
  unknown_domains: number
  verdict_breakdown: VerdictBreakdown
  malicious_query_percentage: number
}

export interface TimeseriesBucket {
  timestamp: string
  bucket_start?: string
  bucket_end?: string
  total_queries: number
  benign_queries: number
  malicious_queries: number
  review_needed_queries: number
  unknown_queries: number
}

export interface TimeseriesResponse {
  start_time: string
  end_time: string
  bucket_size: string
  bucket_source?: string
  buckets: TimeseriesBucket[]
}

export interface DailyReviewSummaryItem {
  id: number
  domain: string
  status: string
  reason?: string | null
  next_check_at?: string | null
  review_count: number
  is_due: boolean
}

export interface DashboardResponse {
  time_range: {
    start: string | null
    end: string | null
    preset?: string | null
    bucket_label?: string | null
    is_all_time: boolean
  }
  summary: DashboardKPIs
  timeseries: TimeseriesResponse | null
  top_clients: ClientItem[]
  top_domains: DomainItem[]
  top_benign_domains: DomainItem[]
  top_malicious_domains: DomainItem[]
  daily_review_domains: DailyReviewSummaryItem[]
}

export interface DatabaseHealth {
  connected: boolean
  database: string
  latency_ms: number | null
}

export interface AggregationStatus {
  job_name: string
  status: string
  watermark_id: number
  pending_events: number
  total_history_events: number
  total_events_processed: number
  last_run_at: string | null
}

export interface SystemStatusResponse {
  status: string
  service: string
  version: string
  database: DatabaseHealth
  aggregation?: AggregationStatus | null
  timestamp: string
}

export interface DomainAnalyticsResponse {
  window: {
    start: string
    end: string
    duration_minutes: number
  }
  metrics: {
    total_queries: number
    unique_domains: number
    unique_clients: number
    malicious_domains: number
    review_needed_domains: number
    unknown_domains: number
    benign_queries: number
    malicious_queries: number
    review_needed_queries: number
    unknown_queries: number
  }
  timeline: Array<{
    timestamp: string
    queries: number
    benign_queries: number
    malicious_queries: number
    review_needed_queries: number
    unknown_queries: number
  }>
}

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

let inMemoryToken: string | null = null

export async function getAuthToken(): Promise<string | null> {
  if (typeof window !== "undefined") {
    const stored = window.localStorage.getItem("dnsnetra_access_token")
    if (stored) return stored
  }
  if (inMemoryToken) return inMemoryToken

  // Authenticate against FastAPI backend with default administrator credentials
  try {
    const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "admin@security.local", password: "admin" }),
    })
    if (res.ok) {
      const data = (await res.json()) as { access_token?: string }
      if (data.access_token) {
        inMemoryToken = data.access_token
        if (typeof window !== "undefined") {
          window.localStorage.setItem("dnsnetra_access_token", data.access_token)
        }
        return inMemoryToken
      }
    }
  } catch {
    // Backend offline or unreachable
  }
  return null
}

async function apiFetch<T>(
  path: string,
  params: Record<string, string | number | boolean | null | undefined> = {},
  options: { method?: string; body?: unknown } = {}
): Promise<T> {
  const url = new URL(path, API_BASE)
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") {
      url.searchParams.set(k, String(v))
    }
  }

  const headers: Record<string, string> = {
    Accept: "application/json",
  }

  const token = await getAuthToken()
  if (token) {
    headers["Authorization"] = `Bearer ${token}`
  }

  if (options.body) {
    headers["Content-Type"] = "application/json"
  }

  const res = await fetch(url.toString(), {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    // Prevent stale caching on dynamic table queries
    cache: "no-store",
  })

  if (!res.ok) {
    const errorText = await res.text().catch(() => "Unknown error")
    throw new Error(`API error (${res.status}): ${errorText}`)
  }

  return res.json()
}

export const dnsnetraApi = {
  /** List domains */
  async getDomains(params: {
    page?: number
    pageSize?: number
    verdict?: string
    search?: string
    window?: string
    start_time?: string
    end_time?: string
  }): Promise<PaginatedResult<DomainItem>> {
    const hasCustom = Boolean(params.start_time && params.end_time)
    return apiFetch<PaginatedResult<DomainItem>>("/api/v1/domains", {
      page: params.page ?? 1,
      page_size: params.pageSize ?? 25,
      verdict: params.verdict,
      search: params.search,
      window: hasCustom ? undefined : params.window,
      start_time: params.start_time,
      end_time: params.end_time,
    })
  },

  /** Get domain detail (lifetime forensic dossier without temporal params) */
  async getDomainDetail(domain: string): Promise<DomainDetail> {
    return apiFetch<DomainDetail>(`/api/v1/domains/${encodeURIComponent(domain)}`)
  },

  /** Get authoritative domain investigation dossier (strictly no temporal params) */
  async getDomainInvestigation(domain: string): Promise<DomainDetail> {
    return apiFetch<DomainDetail>(`/api/v1/investigation/domains/${encodeURIComponent(domain)}`)
  },

  /** List clients */
  async getClients(params: {
    page?: number
    pageSize?: number
    search?: string
    window?: string
    start_time?: string
    end_time?: string
  }): Promise<PaginatedResult<ClientItem>> {
    const hasCustom = Boolean(params.start_time && params.end_time)
    return apiFetch<PaginatedResult<ClientItem>>("/api/v1/clients", {
      page: params.page ?? 1,
      page_size: params.pageSize ?? 25,
      search: params.search,
      window: hasCustom ? undefined : params.window,
      start_time: params.start_time,
      end_time: params.end_time,
    })
  },

  /** Get client detail (lifetime forensic dossier without temporal params) */
  async getClientDetail(clientIp: string): Promise<ClientDetail> {
    return apiFetch<ClientDetail>(`/api/v1/clients/${encodeURIComponent(clientIp)}`)
  },

  /** Get authoritative client investigation dossier (strictly no temporal params) */
  async getClientInvestigation(clientIp: string): Promise<ClientDetail> {
    return apiFetch<ClientDetail>(`/api/v1/investigation/clients/${encodeURIComponent(clientIp)}`)
  },

  /** List DNS queries log */
  async getQueries(params: {
    page?: number
    pageSize?: number
    client_ip?: string
    domain?: string
    verdict?: string
    query_type?: string
    search?: string
    window?: string
    start_time?: string
    end_time?: string
  }): Promise<PaginatedResult<QueryItem>> {
    const hasCustom = Boolean(params.start_time && params.end_time)
    return apiFetch<PaginatedResult<QueryItem>>("/api/v1/reports/queries", {
      page: params.page ?? 1,
      page_size: params.pageSize ?? 25,
      client_ip: params.client_ip,
      domain: params.domain,
      verdict: params.verdict,
      query_type: params.query_type,
      search: params.search,
      window: hasCustom ? undefined : params.window,
      start_time: params.start_time,
      end_time: params.end_time,
    })
  },

  /** List malicious domains */
  async getMaliciousDomains(params: {
    page?: number
    pageSize?: number
    window?: string
  }): Promise<PaginatedResult<DomainItem>> {
    return apiFetch<PaginatedResult<DomainItem>>("/api/v1/reports/malicious-domains", {
      page: params.page ?? 1,
      page_size: params.pageSize ?? 25,
      window: params.window,
    })
  },

  /** List daily review queue - strictly scoped to review_needed */
  async getDailyReview(params: {
    page?: number
    pageSize?: number
    status?: string
    search?: string
    is_due?: boolean
  }): Promise<PaginatedResult<DailyReviewItem>> {
    return apiFetch<PaginatedResult<DailyReviewItem>>("/api/v1/daily-review", {
      page: params.page ?? 1,
      page_size: params.pageSize ?? 25,
      status: params.status || "review_needed",
      search: params.search,
      is_due: params.is_due,
    })
  },

  /** Override domain verdict (Clean or Malicious) */
  async overrideVerdict(
    domain: string,
    verdict: "clean" | "malicious",
    reason: string
  ): Promise<{ success: boolean; domain: string; verdict: string; message: string }> {
    return apiFetch<{ success: boolean; domain: string; verdict: string; message: string }>(
      `/api/v1/daily-review/${encodeURIComponent(domain)}/verdict`,
      {},
      {
        method: "POST",
        body: { verdict, reason },
      }
    )
  },

  /** Trigger online re-investigation for domain in daily review queue */
  async triggerReview(
    domain: string
  ): Promise<{ success: boolean; domain: string; investigation_result: string; message: string }> {
    return apiFetch<{ success: boolean; domain: string; investigation_result: string; message: string }>(
      `/api/v1/daily-review/${encodeURIComponent(domain)}/trigger`,
      {},
      {
        method: "POST",
      }
    )
  },

  /** Generate direct download URL for query log CSV export */
  getExportCsvUrl(
    params: {
      client_ip?: string
      domain?: string
      verdict?: string
      query_type?: string
      search?: string
      window?: string
      start_time?: string
      end_time?: string
      limit?: number
    } = {}
  ): string {
    const hasCustom = Boolean(params.start_time && params.end_time)
    const url = new URL("/api/v1/reports/export/csv", API_BASE)
    const queryParams: Record<string, string | number | undefined> = {
      client_ip: params.client_ip,
      domain: params.domain,
      verdict: params.verdict,
      query_type: params.query_type,
      search: params.search,
      window: hasCustom ? undefined : params.window,
      start_time: params.start_time,
      end_time: params.end_time,
      limit: params.limit,
    }
    for (const [k, v] of Object.entries(queryParams)) {
      if (v !== undefined && v !== null && v !== "") {
        url.searchParams.set(k, String(v))
      }
    }
    return url.toString()
  },

  /** Stream and download CSV export with bearer authorization */
  async downloadExportCsv(
    params: {
      client_ip?: string
      domain?: string
      verdict?: string
      query_type?: string
      search?: string
      window?: string
      start_time?: string
      end_time?: string
      limit?: number
    } = {}
  ): Promise<void> {
    const token = await getAuthToken()
    const hasCustom = Boolean(params.start_time && params.end_time)
    const url = new URL("/api/v1/reports/export/csv", API_BASE)
    const queryParams: Record<string, string | number | undefined> = {
      client_ip: params.client_ip,
      domain: params.domain,
      verdict: params.verdict,
      query_type: params.query_type,
      search: params.search,
      window: hasCustom ? undefined : params.window,
      start_time: params.start_time,
      end_time: params.end_time,
      limit: params.limit,
    }
    for (const [k, v] of Object.entries(queryParams)) {
      if (v !== undefined && v !== null && v !== "") {
        url.searchParams.set(k, String(v))
      }
    }
    const headers: Record<string, string> = {}
    if (token) {
      headers["Authorization"] = `Bearer ${token}`
    }
    const res = await fetch(url.toString(), { headers })
    if (!res.ok) {
      throw new Error(`Export download failed (${res.status})`)
    }
    const blob = await res.blob()
    const downloadUrl = window.URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = downloadUrl
    a.download = `dnsnetra-export-${Date.now()}.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    window.URL.revokeObjectURL(downloadUrl)
  },

  /** Get complete unified dashboard data */
  async getDashboard(
    params: {
      window?: string
      start_time?: string
      end_time?: string
      bucket?: string
    } = {}
  ): Promise<DashboardResponse> {
    const hasCustom = Boolean(params.start_time && params.end_time)
    return apiFetch<DashboardResponse>("/api/v1/dashboard", {
      window: hasCustom ? undefined : (params.window || "24h"),
      start_time: params.start_time,
      end_time: params.end_time,
      bucket: params.bucket,
    })
  },

  /** Get system health and database status */
  async getSystemStatus(): Promise<SystemStatusResponse> {
    return apiFetch<SystemStatusResponse>("/api/v1/status")
  },

  /** Get domain analytics metrics and timeline */
  async getDomainAnalytics(
    params: {
      window?: string
      start?: string
      end?: string
    } = {}
  ): Promise<DomainAnalyticsResponse> {
    return apiFetch<DomainAnalyticsResponse>("/api/v1/analytics/domains", {
      window: params.window || "24h",
      start: params.start,
      end: params.end,
    })
  },
}
