import api from "./api";
import {
  DashboardBundleResponse,
  DomainsResponse,
  DomainDetailResponse,
  ClientsResponse,
  ClientDetailResponse,
  SystemStatusData,
  DomainInvestigationResponse,
  ClientInvestigationResponse,
  DomainAnalyticsResponse,
  ReportOverviewResponse,
  ReportPaginatedResponse,
  ReportQueryItem,
  ReportDomainItem,
  ReportMaliciousDomainItem,
  ReportClientItem,
  EntityReportResponse,
} from "../types/api";

// In-flight GET request deduplication map
const inFlightRequests = new Map<string, Promise<any>>();

/**
 * Executes a GET request with in-flight promise deduplication.
 * Re-throws network / API errors so that UI pages display genuine error/offline states.
 */
function dedupedGet<T>(url: string, config?: any): Promise<T> {
  const paramsKey = config?.params ? JSON.stringify(config.params) : "";
  const key = `GET:${url}:${paramsKey}`;

  const existing = inFlightRequests.get(key);
  if (existing) {
    return existing as Promise<T>;
  }

  const promise = api
    .get<T>(url, config)
    .then((res: { data: T }) => res.data)
    .finally(() => {
      inFlightRequests.delete(key);
    });

  inFlightRequests.set(key, promise);
  return promise;
}

export const apiClient = {
  /**
   * Fetches the unified dashboard bundle containing KPI summary,
   * timeseries, threat categories, top domains, top clients, and recent flagged domains.
   */
  async getDashboard(params?: {
    window?: string;
    start_time?: string;
    end_time?: string;
  }): Promise<DashboardBundleResponse> {
    return dedupedGet<DashboardBundleResponse>("/dashboard", {
      params: {
        window: params?.window || undefined,
        start_time: params?.start_time || undefined,
        end_time: params?.end_time || undefined,
      },
    });
  },

  /**
   * Fetches paginated domain list with optional search and label filter.
   */
  async getDomains(params?: {
    page?: number;
    pageSize?: number;
    search?: string;
    label?: string;
    window?: string;
    start_time?: string;
    end_time?: string;
  }): Promise<DomainsResponse> {
    const page = params?.page || 1;
    const pageSize = params?.pageSize || 50;
    const search = params?.search?.toLowerCase();
    const label = params?.label;

    return dedupedGet<DomainsResponse>("/domains", {
      params: {
        page,
        page_size: pageSize,
        search: search || undefined,
        label: label && label !== "all" ? label : undefined,
        window: params?.window || undefined,
        start_time: params?.start_time || undefined,
        end_time: params?.end_time || undefined,
      },
    });
  },

  /**
   * Fetches comprehensive Domain Intelligence Investigation.
   * forceExternal is only sent if explicitly requested by the caller (e.g. manual refresh).
   */
  async getDomainInvestigation(
    domain: string,
    forceExternal = false,
    params?: {
      window?: string;
      start_time?: string;
      end_time?: string;
    }
  ): Promise<DomainInvestigationResponse> {
    return dedupedGet<DomainInvestigationResponse>(
      `/investigation/domain/${encodeURIComponent(domain)}`,
      {
        params: {
          force_external: forceExternal ? true : undefined,
          window: params?.window || undefined,
          start_time: params?.start_time || undefined,
          end_time: params?.end_time || undefined,
        },
      }
    );
  },

  /**
   * Fetches domain detail strictly from PostgreSQL.
   */
  async getDomainDetail(domain: string): Promise<DomainDetailResponse> {
    return dedupedGet<DomainDetailResponse>(`/domains/${encodeURIComponent(domain)}`);
  },

  /**
   * Fetches paginated client list with optional search and time range.
   */
  async getClients(params?: {
    page?: number;
    pageSize?: number;
    search?: string;
    window?: string;
    start_time?: string;
    end_time?: string;
  }): Promise<ClientsResponse> {
    const page = params?.page || 1;
    const pageSize = params?.pageSize || 50;
    const search = params?.search?.toLowerCase();

    return dedupedGet<ClientsResponse>("/clients", {
      params: {
        page,
        page_size: pageSize,
        search: search || undefined,
        window: params?.window || undefined,
        start_time: params?.start_time || undefined,
        end_time: params?.end_time || undefined,
      },
    });
  },

  /**
   * Fetches comprehensive Client Endpoint Investigation.
   */
  async getClientInvestigation(
    clientIp: string,
    params?: {
      window?: string;
      start_time?: string;
      end_time?: string;
    }
  ): Promise<ClientInvestigationResponse> {
    return dedupedGet<ClientInvestigationResponse>(
      `/investigation/client/${encodeURIComponent(clientIp)}`,
      {
        params: {
          window: params?.window || undefined,
          start_time: params?.start_time || undefined,
          end_time: params?.end_time || undefined,
        },
      }
    );
  },

  /**
   * Fetches client intelligence detail strictly from dashboard.db.
   */
  async getClientDetail(clientIp: string): Promise<ClientDetailResponse> {
    return dedupedGet<ClientDetailResponse>(`/clients/${encodeURIComponent(clientIp)}`);
  },

  /**
   * Fetches system status, aggregation watermark, and run audit info.
   */
  async getStatus(): Promise<SystemStatusData> {
    return dedupedGet<SystemStatusData>("/status");
  },

  /**
   * Fetches Time-Window DNS Analytics for preset or custom UTC range.
   */
  async getDomainAnalytics(params?: {
    window?: string;
    start?: string;
    end?: string;
  }): Promise<DomainAnalyticsResponse> {
    return dedupedGet<DomainAnalyticsResponse>("/analytics/domains", {
      params: {
        window: params?.window || (params?.start ? undefined : "60m"),
        start: params?.start || undefined,
        end: params?.end || undefined,
      },
    });
  },

  // ===========================================================================
  // Reports Methods (PostgreSQL Direct Access Layer)
  // ===========================================================================

  /**
   * Fetches report-level summary KPIs and adaptive timeseries.
   */
  async getReports(params?: {
    window?: string;
    start_time?: string;
    end_time?: string;
  }): Promise<ReportOverviewResponse> {
    return dedupedGet<ReportOverviewResponse>("/reports", {
      params: {
        window: params?.window || undefined,
        start_time: params?.start_time || undefined,
        end_time: params?.end_time || undefined,
      },
    });
  },

  /**
   * Fetches paginated DNS query records from domain_query_history.
   */
  async getReportQueries(params?: {
    page?: number;
    pageSize?: number;
    search?: string;
    label?: string;
    window?: string;
    start_time?: string;
    end_time?: string;
  }): Promise<ReportPaginatedResponse<ReportQueryItem>> {
    return dedupedGet<ReportPaginatedResponse<ReportQueryItem>>("/reports/queries", {
      params: {
        page: params?.page || 1,
        page_size: params?.pageSize || 50,
        search: params?.search?.trim() || undefined,
        label: params?.label?.trim() || undefined,
        window: params?.window || undefined,
        start_time: params?.start_time || undefined,
        end_time: params?.end_time || undefined,
      },
    });
  },

  /**
   * Fetches paginated top domains in time range.
   */
  async getReportDomains(params?: {
    page?: number;
    pageSize?: number;
    search?: string;
    window?: string;
    start_time?: string;
    end_time?: string;
  }): Promise<ReportPaginatedResponse<ReportDomainItem>> {
    return dedupedGet<ReportPaginatedResponse<ReportDomainItem>>("/reports/domains", {
      params: {
        page: params?.page || 1,
        page_size: params?.pageSize || 50,
        search: params?.search?.trim() || undefined,
        window: params?.window || undefined,
        start_time: params?.start_time || undefined,
        end_time: params?.end_time || undefined,
      },
    });
  },

  /**
   * Fetches paginated malicious domains (>= 1 malicious query) in time range.
   */
  async getReportMaliciousDomains(params?: {
    page?: number;
    pageSize?: number;
    search?: string;
    window?: string;
    start_time?: string;
    end_time?: string;
  }): Promise<ReportPaginatedResponse<ReportMaliciousDomainItem>> {
    return dedupedGet<ReportPaginatedResponse<ReportMaliciousDomainItem>>("/reports/malicious-domains", {
      params: {
        page: params?.page || 1,
        page_size: params?.pageSize || 50,
        search: params?.search?.trim() || undefined,
        window: params?.window || undefined,
        start_time: params?.start_time || undefined,
        end_time: params?.end_time || undefined,
      },
    });
  },

  /**
   * Fetches paginated client endpoints in time range.
   */
  async getReportClients(params?: {
    page?: number;
    pageSize?: number;
    search?: string;
    window?: string;
    start_time?: string;
    end_time?: string;
  }): Promise<ReportPaginatedResponse<ReportClientItem>> {
    return dedupedGet<ReportPaginatedResponse<ReportClientItem>>("/reports/clients", {
      params: {
        page: params?.page || 1,
        page_size: params?.pageSize || 50,
        search: params?.search?.trim() || undefined,
        window: params?.window || undefined,
        start_time: params?.start_time || undefined,
        end_time: params?.end_time || undefined,
      },
    });
  },

  /**
   * Fetches paginated flagged query events in time range.
   */
  async getReportFlagged(params?: {
    page?: number;
    pageSize?: number;
    search?: string;
    window?: string;
    start_time?: string;
    end_time?: string;
  }): Promise<ReportPaginatedResponse<ReportQueryItem>> {
    return dedupedGet<ReportPaginatedResponse<ReportQueryItem>>("/reports/flagged", {
      params: {
        page: params?.page || 1,
        page_size: params?.pageSize || 50,
        search: params?.search?.trim() || undefined,
        window: params?.window || undefined,
        start_time: params?.start_time || undefined,
        end_time: params?.end_time || undefined,
      },
    });
  },

  /**
   * Fetches entity-centric report for a specific client IP or domain.
   */
  async getEntityReport(params: {
    entity: string;
    entity_type?: "client" | "domain";
    window?: string;
    start_time?: string;
    end_time?: string;
    page?: number;
    pageSize?: number;
  }): Promise<EntityReportResponse> {
    return dedupedGet<EntityReportResponse>("/reports/entity", {
      params: {
        entity: params.entity.trim(),
        entity_type: params.entity_type || undefined,
        window: params.window || undefined,
        start_time: params.start_time || undefined,
        end_time: params.end_time || undefined,
        page: params.page || 1,
        page_size: params.pageSize || 50,
      },
    });
  },

  /**
   * Downloads report dataset as CSV stream matching exact query parameters.
   */
  async exportReportCsv(params: {
    table:
      | "queries"
      | "domains"
      | "malicious-domains"
      | "clients"
      | "flagged"
      | "client-domains"
      | "client-malicious"
      | "client-clean"
      | "client-benign"
      | "client-review-needed"
      | "client-unknown"
      | "client-queries"
      | "domain-clients"
      | "domain-queries";
    entity?: string;
    entity_type?: "client" | "domain";
    window?: string;
    start_time?: string;
    end_time?: string;
    search?: string;
    label?: string;
    limit?: number;
  }): Promise<void> {
    const queryParams = new URLSearchParams();
    queryParams.set("table", params.table);
    if (params.entity) queryParams.set("entity", params.entity);
    if (params.entity_type) queryParams.set("entity_type", params.entity_type);
    if (params.window) queryParams.set("window", params.window);
    if (params.start_time) queryParams.set("start_time", params.start_time);
    if (params.end_time) queryParams.set("end_time", params.end_time);
    if (params.search) queryParams.set("search", params.search);
    if (params.label) queryParams.set("label", params.label);
    if (params.limit) queryParams.set("limit", params.limit.toString());

    const response = await api.get(`/reports/export/csv?${queryParams.toString()}`, {
      responseType: "blob",
    });

    const blob = new Blob([response.data], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    const disposition = response.headers["content-disposition"];
    let filename = `report_${params.table}.csv`;
    if (disposition) {
      const match = disposition.match(/filename="?([^";]+)"?/);
      if (match && match[1]) {
        filename = match[1];
      }
    }
    link.setAttribute("download", filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  },
};

export default apiClient;

