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

export interface DnsDomainItem {
  domain: string
  registered_domain: string
  query_type: string
  client_ip?: string | null
  first_seen: string
  last_seen: string
  total_queries: number
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

export interface LiveProviderEvidence {
  provider: string
  status: string
  malicious: number
  suspicious: number
  harmless: number
  undetected: number
  total: number
  pulse_count: number
  confidence: number
  error?: string | null
  details?: Record<string, unknown>
}

export interface LiveIndicatorVerdict {
  state: string
  confidence: number
  reasons: string[]
  sources_with_data: number
  sources_queried: number
}

export interface LiveIntelReport {
  indicator: string
  kind: string
  verdict: LiveIndicatorVerdict
  providers: LiveProviderEvidence[]
  registration?: {
    status: string
    source?: string
    registrar?: string | null
    registrar_id?: string | null
    created_at?: string | null
    updated_at?: string | null
    expires_at?: string | null
    domain_status?: string[]
    nameservers?: string[]
    error?: string | null
  } | null
  dns_records?: {
    status: string
    a?: string[]
    aaaa?: string[]
    cname?: string[]
    ns?: string[]
    mx?: Array<{ priority: number; exchange: string }>
    error?: string | null
  } | null
  ip_context?: {
    asn?: number | null
    as_owner?: string | null
    country?: string | null
    network?: string | null
    reputation?: number | null
  } | null
  checked_at: string
}

export interface DomainDetail {
  domain: string
  observed_in_network: boolean
  live_intel?: LiveIntelReport | null
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
  } | null
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
  registration?: {
    status: string
    source?: string
    registrar?: string | null
    registrar_id?: string | null
    created_at?: string | null
    updated_at?: string | null
    expires_at?: string | null
    domain_status?: string[]
    nameservers?: string[]
    error?: string | null
  } | null
  dns_records?: {
    status: string
    a?: string[]
    aaaa?: string[]
    cname?: string[]
    ns?: string[]
    mx?: Array<{ priority: number; exchange: string }>
    error?: string | null
  } | null
}

export interface ClientDetail {
  client_ip: string
  observed_in_network: boolean
  live_intel?: LiveIntelReport | null
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
  } | null
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

let currentApiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

/** Error carrying the HTTP status so callers can distinguish 404 from outages. */
export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = "ApiError"
    this.status = status
  }
}

/** Session is the backend's HttpOnly cookie; an expired one sends the user to /login. */
function redirectToLogin(): void {
  if (typeof window === "undefined") return
  const p = window.location.pathname
  if (p === "/login" || p === "/signup") return
  // `replace` so the expired page is not left in history behind the login form.
  window.location.replace("/login")
}

async function apiFetch<T>(
  path: string,
  params: Record<string, string | number | boolean | null | undefined> = {},
  options: { method?: string; body?: unknown; _isRetry?: boolean } = {}
): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
  }

  if (options.body) {
    headers["Content-Type"] = "application/json"
  }

  const bases = [currentApiBase]
  if (currentApiBase.includes("localhost:8000") || currentApiBase.includes("127.0.0.1:8000")) {
    bases.push(currentApiBase.replace(":8000", ":8001"))
  } else if (currentApiBase.includes("localhost:8001") || currentApiBase.includes("127.0.0.1:8001")) {
    bases.push(currentApiBase.replace(":8001", ":8000"))
  }

  let res: Response | null = null
  for (const base of bases) {
    try {
      const url = new URL(path, base)
      for (const [k, v] of Object.entries(params)) {
        if (v !== undefined && v !== null && v !== "") {
          url.searchParams.set(k, String(v))
        }
      }
      res = await fetch(url.toString(), {
        method: options.method || "GET",
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined,
        credentials: "include",
        cache: "no-store",
      })
      currentApiBase = base
      break
    } catch {
      // try fallback base
    }
  }

  if (!res) {
    throw new Error("Can't reach DNSNetra API. Check connection.")
  }

  if (res.status === 401) {
    redirectToLogin()
  }

  if (!res.ok) {
    const errorText = await res.text().catch(() => "Unknown error")
    throw new ApiError(res.status, `API error (${res.status}): ${errorText}`)
  }

  return res.json()
}

export type SearchCategory = "domains" | "clients" | "queries"

export interface GlobalSearchResult {
  domains: DomainItem[]
  clients: ClientItem[]
  queries: QueryItem[]
  /** Categories whose request failed; the rest of the result is still usable. */
  unavailable?: SearchCategory[]
}

export const dnsnetraApi = {
  /** List domains */
  async getDomains(params: {
    page?: number
    pageSize?: number
    verdict?: string
    search?: string
    sort?: string
    order?: "asc" | "desc"
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
      sort: params.sort,
      order: params.order,
      window: hasCustom ? undefined : params.window,
      start_time: params.start_time,
      end_time: params.end_time,
    })
  },

  /** Get domain detail (lifetime forensic dossier without temporal params) */
  async getDomainDetail(domain: string): Promise<DomainDetail> {
    return apiFetch<DomainDetail>(`/api/v1/domains/${encodeURIComponent(domain)}`)
  },

  /** One row per queried domain for the DNS page */
  async getDnsDomains(params: {
    page?: number
    pageSize?: number
    search?: string
    sort?: string
    order?: "asc" | "desc"
  } = {}): Promise<PaginatedResult<DnsDomainItem>> {
    const page = params.page ?? 1
    const pageSize = params.pageSize ?? 25
    return apiFetch<PaginatedResult<DnsDomainItem>>("/api/v1/dns/domains", {
      limit: pageSize,
      offset: (page - 1) * pageSize,
      search: params.search,
      sort: params.sort,
      order: params.order,
    })
  },

  /** Get authoritative domain investigation dossier (strictly no temporal params) */
  async getDomainInvestigation(domain: string, refresh = false): Promise<DomainDetail> {
    return apiFetch<DomainDetail>(
      `/api/v1/investigation/domains/${encodeURIComponent(domain)}`,
      { refresh: refresh ? true : undefined }
    )
  },

  /** List clients */
  async getClients(params: {
    page?: number
    pageSize?: number
    search?: string
    sort?: string
    order?: "asc" | "desc"
    window?: string
    start_time?: string
    end_time?: string
  }): Promise<PaginatedResult<ClientItem>> {
    const hasCustom = Boolean(params.start_time && params.end_time)
    return apiFetch<PaginatedResult<ClientItem>>("/api/v1/clients", {
      page: params.page ?? 1,
      page_size: params.pageSize ?? 25,
      search: params.search,
      sort: params.sort,
      order: params.order,
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
  async getClientInvestigation(clientIp: string, refresh = false): Promise<ClientDetail> {
    return apiFetch<ClientDetail>(
      `/api/v1/investigation/clients/${encodeURIComponent(clientIp)}`,
      { refresh: refresh ? true : undefined }
    )
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
    sort?: string
    order?: "asc" | "desc"
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
      sort: params.sort,
      order: params.order,
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
    const url = new URL("/api/v1/reports/export/csv", currentApiBase)
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
    const hasCustom = Boolean(params.start_time && params.end_time)
    const url = new URL("/api/v1/reports/export/csv", currentApiBase)
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
    const res = await fetch(url.toString(), { credentials: "include" })
    if (res.status === 401) redirectToLogin()
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

  /** List saved reports (immutable snapshots) */
  async listSavedReports(params: { status?: string; kind?: string; entity?: string; limit?: number; offset?: number } = {}): Promise<import("@/lib/reporting/types").SavedReportList> {
    return apiFetch("/api/v1/reports/saved", params)
  },

  /** Get one saved report with snapshot and review metadata */
  async getSavedReport(publicId: string): Promise<import("@/lib/reporting/types").SavedReportDetail> {
    return apiFetch(`/api/v1/reports/saved/${encodeURIComponent(publicId)}`)
  },

  /** Create an immutable report snapshot from a dossier or query set */
  async createSavedReport(body: {
    kind: "entity_domain" | "entity_client" | "query_set"
    entity?: string
    window?: string
    start_time?: string
    end_time?: string
    filters?: Record<string, unknown>
    title?: string
    refresh?: boolean
  }): Promise<import("@/lib/reporting/types").SavedReportDetail> {
    return apiFetch("/api/v1/reports/saved", {}, { method: "POST", body })
  },

  /** Move a saved report through its review workflow */
  async reviewSavedReport(publicId: string, body: {
    status: "draft" | "needs_review" | "reviewed" | "archived"
    verdict?: string
    conclusion?: string
  }): Promise<import("@/lib/reporting/types").SavedReportDetail> {
    return apiFetch(`/api/v1/reports/saved/${encodeURIComponent(publicId)}/review`, {}, { method: "PATCH", body })
  },

  /** Download a saved report as CSV or XLSX */
  async downloadSavedReport(publicId: string, format: "csv" | "xlsx"): Promise<void> {
    const url = new URL(`/api/v1/reports/saved/${encodeURIComponent(publicId)}/export`, currentApiBase)
    url.searchParams.set("format", format)
    const res = await fetch(url.toString(), { method: "POST", credentials: "include", cache: "no-store" })
    if (res.status === 401) redirectToLogin()
    if (!res.ok) throw new ApiError(res.status, `Export failed (${res.status})`)
    const blob = await res.blob()
    const downloadUrl = URL.createObjectURL(blob)
    const link = document.createElement("a")
    link.href = downloadUrl
    link.download = `dnsnetra_${publicId}.${format}`
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(downloadUrl)
  },

  /** List cases in the investigation queue */
  async listCases(params: { status?: string; priority?: string; unassigned?: boolean; assigned_to_me?: boolean; limit?: number; offset?: number } = {}): Promise<import("@/lib/reporting/types").CaseList> {
    return apiFetch("/api/v1/cases", params)
  },

  /** Get one case with its timeline and linked reports */
  async getCase(publicId: string): Promise<import("@/lib/reporting/types").CaseDetail> {
    return apiFetch(`/api/v1/cases/${encodeURIComponent(publicId)}`)
  },

  /** Open a new case, optionally from an existing report */
  async createCase(body: { title: string; description?: string; priority?: string; entity_type?: string; entity_value?: string; report_id?: string }): Promise<import("@/lib/reporting/types").CaseDetail> {
    return apiFetch("/api/v1/cases", {}, { method: "POST", body })
  },

  /** Move a case through its lifecycle */
  async updateCase(publicId: string, body: Record<string, unknown>): Promise<import("@/lib/reporting/types").CaseDetail> {
    return apiFetch(`/api/v1/cases/${encodeURIComponent(publicId)}`, {}, { method: "PATCH", body })
  },

  /** Append a comment to a case timeline */
  async commentCase(publicId: string, body: string): Promise<import("@/lib/reporting/types").CaseDetail> {
    return apiFetch(`/api/v1/cases/${encodeURIComponent(publicId)}/comments`, {}, { method: "POST", body: { body } })
  },

  /** Link an existing saved report to a case */
  async linkCaseReport(publicId: string, reportPublicId: string): Promise<import("@/lib/reporting/types").CaseDetail> {
    return apiFetch(`/api/v1/cases/${encodeURIComponent(publicId)}/reports`, {}, {
      method: "POST",
      body: { report_public_id: reportPublicId },
    })
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

  /**
   * Search across domains, clients, and queries with exact match priority
   */
  async searchIntelligence(
    query: string,
    limitPerCategory = 5
  ): Promise<GlobalSearchResult> {
    const trimmed = query.trim()
    if (!trimmed) {
      return { domains: [], clients: [], queries: [] }
    }

    const [domainsRes, clientsRes, queriesRes] = await Promise.allSettled([
      this.getDomains({ search: trimmed, pageSize: limitPerCategory * 2 }),
      this.getClients({ search: trimmed, pageSize: limitPerCategory * 2 }),
      this.getQueries({ search: trimmed, pageSize: limitPerCategory * 2 }),
    ])

    const allFailed =
      domainsRes.status === "rejected" &&
      clientsRes.status === "rejected" &&
      queriesRes.status === "rejected"

    if (allFailed) {
      throw new Error("Unable to search DNS intelligence")
    }

    const rawDomains =
      domainsRes.status === "fulfilled" ? domainsRes.value.items ?? [] : []
    const rawClients =
      clientsRes.status === "fulfilled" ? clientsRes.value.items ?? [] : []
    const rawQueries =
      queriesRes.status === "fulfilled" ? queriesRes.value.items ?? [] : []

    const unavailable = [
      domainsRes.status === "rejected" ? "domains" : null,
      clientsRes.status === "rejected" ? "clients" : null,
      queriesRes.status === "rejected" ? "queries" : null,
    ].filter((category): category is SearchCategory => category !== null)

    const lower = trimmed.toLowerCase()

    // 1. Domains: Exact match -> Prefix match -> Query volume
    const sortedDomains = [...rawDomains]
      .sort((a, b) => {
        const aLower = a.domain.toLowerCase()
        const bLower = b.domain.toLowerCase()
        const aExact = aLower === lower
        const bExact = bLower === lower
        if (aExact && !bExact) return -1
        if (!aExact && bExact) return 1
        const aPrefix = aLower.startsWith(lower)
        const bPrefix = bLower.startsWith(lower)
        if (aPrefix && !bPrefix) return -1
        if (!aPrefix && bPrefix) return 1
        return (b.total_queries ?? 0) - (a.total_queries ?? 0)
      })
      .slice(0, limitPerCategory)

    // 2. Clients: Exact match -> Prefix match -> Query volume
    const sortedClients = [...rawClients]
      .sort((a, b) => {
        const aExact = a.client_ip === trimmed
        const bExact = b.client_ip === trimmed
        if (aExact && !bExact) return -1
        if (!aExact && bExact) return 1
        const aPrefix = a.client_ip.startsWith(trimmed)
        const bPrefix = b.client_ip.startsWith(trimmed)
        if (aPrefix && !bPrefix) return -1
        if (!aPrefix && bPrefix) return 1
        return (b.total_queries ?? 0) - (a.total_queries ?? 0)
      })
      .slice(0, limitPerCategory)

    // 3. Queries: Exact match on domain or client_ip first, then chronological
    const sortedQueries = [...rawQueries]
      .sort((a, b) => {
        const aExact =
          a.domain.toLowerCase() === lower || a.client_ip === trimmed
        const bExact =
          b.domain.toLowerCase() === lower || b.client_ip === trimmed
        if (aExact && !bExact) return -1
        if (!aExact && bExact) return 1
        return 0
      })
      .slice(0, limitPerCategory)

    return {
      domains: sortedDomains,
      clients: sortedClients,
      queries: sortedQueries,
      ...(unavailable.length > 0 ? { unavailable } : {}),
    }
  },
}

