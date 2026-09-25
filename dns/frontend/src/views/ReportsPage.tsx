"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  ChevronRight,
  RotateCcw,
  Download,
  Search,
  ExternalLink,
  ShieldAlert,
  Globe,
  Monitor,
  Activity,
  Layers,
  FileText,
  AlertTriangle,
  CheckCircle2,
  ArrowLeft,
  X,
  AlertCircle,
  Flame,
} from "lucide-react";
import { useTimeRange } from "@/context/TimeRangeContext";
import { GlobalTimeRangePicker } from "@/components/layout/GlobalTimeRangePicker";
import { OverviewKpiCard } from "@/components/dashboard/OverviewKpiCard";
import { VerdictBadge } from "@/components/security/VerdictBadge";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import apiClient from "@/lib/api-client";
import {
  ReportSummaryData,
  ReportQueryItem,
  ReportDomainItem,
  ReportMaliciousDomainItem,
  ReportClientItem,
  ClientReportData,
  DomainReportData,
} from "@/types/api";
import { cn } from "@/lib/utils";

type GlobalReportTab = "queries" | "domains" | "malicious-domains" | "clients" | "flagged";
type ClientReportTab = "queried-domains" | "malicious-domains" | "benign-domains" | "clean-domains" | "review-needed-domains" | "unknown-domains" | "query-history";
type DomainReportTab = "querying-clients" | "query-history";

interface TabMeta {
  page: number;
  pageSize: number;
  total: number;
  pages: number;
}

const DEFAULT_META: TabMeta = {
  page: 1,
  pageSize: 50,
  total: 0,
  pages: 0,
};

export const ReportsPage: React.FC = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { timeRange, range, isLive, registerRefreshHandler } = useTimeRange();

  // Mode: Global Report vs Entity Report
  const [entitySearchInput, setEntitySearchInput] = useState<string>("");
  const [activeEntity, setActiveEntity] = useState<{
    identifier: string;
    type: "client" | "domain";
  } | null>(null);

  // Global Active Tab
  const [globalTab, setGlobalTab] = useState<GlobalReportTab>("queries");

  // Entity Active Tabs
  const [clientTab, setClientTab] = useState<ClientReportTab>("queried-domains");
  const [domainTab, setDomainTab] = useState<DomainReportTab>("querying-clients");

  // Refresh and Exporting state
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [exporting, setExporting] = useState<boolean>(false);
  const [apiError, setApiError] = useState<string | null>(null);

  // Global Datasets
  const [summary, setSummary] = useState<ReportSummaryData | null>(null);
  const [summaryLoading, setSummaryLoading] = useState<boolean>(true);

  const [queries, setQueries] = useState<ReportQueryItem[]>([]);
  const [queriesMeta, setQueriesMeta] = useState<TabMeta>(DEFAULT_META);
  const [queriesSearch, setQueriesSearch] = useState("");
  const [queriesLabel, setQueriesLabel] = useState<string>("All");
  const [queriesLoading, setQueriesLoading] = useState(false);

  const [domains, setDomains] = useState<ReportDomainItem[]>([]);
  const [domainsMeta, setDomainsMeta] = useState<TabMeta>(DEFAULT_META);
  const [domainsSearch, setDomainsSearch] = useState("");
  const [domainsLoading, setDomainsLoading] = useState(false);

  const [malDomains, setMalDomains] = useState<ReportMaliciousDomainItem[]>([]);
  const [malDomainsMeta, setMalDomainsMeta] = useState<TabMeta>(DEFAULT_META);
  const [malDomainsSearch, setMalDomainsSearch] = useState("");
  const [malDomainsLoading, setMalDomainsLoading] = useState(false);

  const [clients, setClients] = useState<ReportClientItem[]>([]);
  const [clientsMeta, setClientsMeta] = useState<TabMeta>(DEFAULT_META);
  const [clientsSearch, setClientsSearch] = useState("");
  const [clientsLoading, setClientsLoading] = useState(false);

  const [flagged, setFlagged] = useState<ReportQueryItem[]>([]);
  const [flaggedMeta, setFlaggedMeta] = useState<TabMeta>(DEFAULT_META);
  const [flaggedSearch, setFlaggedSearch] = useState("");
  const [flaggedLoading, setFlaggedLoading] = useState(false);

  // Entity Datasets
  const [clientReport, setClientReport] = useState<ClientReportData | null>(null);
  const [domainReport, setDomainReport] = useState<DomainReportData | null>(null);
  const [entityLoading, setEntityLoading] = useState<boolean>(false);
  const [entityHistoryPage, setEntityHistoryPage] = useState<number>(1);
  const [entityHistoryPageSize] = useState<number>(50);

  // Correct parameter resolution:
  // When isCustom is false -> pass window (e.g. "7d", "24h", "6h") and omit start/end
  // When isCustom is true -> pass start_time and end_time
  const timeParams = useMemo(() => {
    if (timeRange.isCustom && timeRange.startDate && timeRange.endDate) {
      return {
        start_time: timeRange.startDate.toISOString(),
        end_time: timeRange.endDate.toISOString(),
        window: undefined,
      };
    }
    return {
      window: timeRange.preset || range || "24h",
      start_time: undefined,
      end_time: undefined,
    };
  }, [timeRange.isCustom, timeRange.startDate, timeRange.endDate, timeRange.preset, range]);

  // -------------------------------------------------------------------------
  // Fetch Global Summary
  // -------------------------------------------------------------------------
  const fetchSummary = useCallback(async () => {
    try {
      setSummaryLoading(true);
      setApiError(null);
      const res = await apiClient.getReports(timeParams);
      if (res && res.data && res.data.summary) {
        setSummary(res.data.summary);
      }
    } catch (err: any) {
      console.error("Failed to fetch reports summary:", err);
      setApiError(err?.message || "Failed to load telemetry summary from server.");
    } finally {
      setSummaryLoading(false);
    }
  }, [timeParams]);

  // -------------------------------------------------------------------------
  // Fetch Global Tables
  // -------------------------------------------------------------------------
  const fetchQueries = useCallback(
    async (page = queriesMeta.page, pageSize = queriesMeta.pageSize) => {
      try {
        setQueriesLoading(true);
        setApiError(null);
        const res = await apiClient.getReportQueries({
          page,
          pageSize,
          search: queriesSearch || undefined,
          label: queriesLabel === "All" ? undefined : queriesLabel,
          ...timeParams,
        });
        if (res && res.data) {
          setQueries(res.data);
          setQueriesMeta({
            page: res.meta.page,
            pageSize: res.meta.page_size,
            total: res.meta.total,
            pages: res.meta.pages,
          });
        }
      } catch (err: any) {
        console.error("Failed to fetch queries:", err);
        setApiError(err?.message || "Failed to load DNS queries.");
      } finally {
        setQueriesLoading(false);
      }
    },
    [queriesMeta.page, queriesMeta.pageSize, queriesSearch, queriesLabel, timeParams]
  );

  const fetchDomains = useCallback(
    async (page = domainsMeta.page, pageSize = domainsMeta.pageSize) => {
      try {
        setDomainsLoading(true);
        setApiError(null);
        const res = await apiClient.getReportDomains({
          page,
          pageSize,
          search: domainsSearch || undefined,
          ...timeParams,
        });
        if (res && res.data) {
          setDomains(res.data);
          setDomainsMeta({
            page: res.meta.page,
            pageSize: res.meta.page_size,
            total: res.meta.total,
            pages: res.meta.pages,
          });
        }
      } catch (err: any) {
        console.error("Failed to fetch domains:", err);
        setApiError(err?.message || "Failed to load domain aggregations.");
      } finally {
        setDomainsLoading(false);
      }
    },
    [domainsMeta.page, domainsMeta.pageSize, domainsSearch, timeParams]
  );

  const fetchMalDomains = useCallback(
    async (page = malDomainsMeta.page, pageSize = malDomainsMeta.pageSize) => {
      try {
        setMalDomainsLoading(true);
        setApiError(null);
        const res = await apiClient.getReportMaliciousDomains({
          page,
          pageSize,
          search: malDomainsSearch || undefined,
          ...timeParams,
        });
        if (res && res.data) {
          setMalDomains(res.data);
          setMalDomainsMeta({
            page: res.meta.page,
            pageSize: res.meta.page_size,
            total: res.meta.total,
            pages: res.meta.pages,
          });
        }
      } catch (err: any) {
        console.error("Failed to fetch malicious domains:", err);
        setApiError(err?.message || "Failed to load malicious domains.");
      } finally {
        setMalDomainsLoading(false);
      }
    },
    [malDomainsMeta.page, malDomainsMeta.pageSize, malDomainsSearch, timeParams]
  );

  const fetchClients = useCallback(
    async (page = clientsMeta.page, pageSize = clientsMeta.pageSize) => {
      try {
        setClientsLoading(true);
        setApiError(null);
        const res = await apiClient.getReportClients({
          page,
          pageSize,
          search: clientsSearch || undefined,
          ...timeParams,
        });
        if (res && res.data) {
          setClients(res.data);
          setClientsMeta({
            page: res.meta.page,
            pageSize: res.meta.page_size,
            total: res.meta.total,
            pages: res.meta.pages,
          });
        }
      } catch (err: any) {
        console.error("Failed to fetch clients:", err);
        setApiError(err?.message || "Failed to load client activity.");
      } finally {
        setClientsLoading(false);
      }
    },
    [clientsMeta.page, clientsMeta.pageSize, clientsSearch, timeParams]
  );

  const fetchFlagged = useCallback(
    async (page = flaggedMeta.page, pageSize = flaggedMeta.pageSize) => {
      try {
        setFlaggedLoading(true);
        setApiError(null);
        const res = await apiClient.getReportFlagged({
          page,
          pageSize,
          search: flaggedSearch || undefined,
          ...timeParams,
        });
        if (res && res.data) {
          setFlagged(res.data);
          setFlaggedMeta({
            page: res.meta.page,
            pageSize: res.meta.page_size,
            total: res.meta.total,
            pages: res.meta.pages,
          });
        }
      } catch (err: any) {
        console.error("Failed to fetch flagged queries:", err);
        setApiError(err?.message || "Failed to load flagged events.");
      } finally {
        setFlaggedLoading(false);
      }
    },
    [flaggedMeta.page, flaggedMeta.pageSize, flaggedSearch, timeParams]
  );

  // -------------------------------------------------------------------------
  // Fetch Entity Report (Client IP or Domain)
  // -------------------------------------------------------------------------
  const fetchEntityReport = useCallback(
    async (page = entityHistoryPage) => {
      if (!activeEntity) return;
      try {
        setEntityLoading(true);
        setApiError(null);
        const res = await apiClient.getEntityReport({
          entity: activeEntity.identifier,
          entity_type: activeEntity.type,
          page,
          pageSize: entityHistoryPageSize,
          ...timeParams,
        });

        if (res && res.data) {
          if (res.data.summary.entity_type === "client") {
            setClientReport(res.data as ClientReportData);
            setDomainReport(null);
          } else {
            setDomainReport(res.data as DomainReportData);
            setClientReport(null);
          }
        }
      } catch (err: any) {
        console.error("Failed to fetch entity report:", err);
        setApiError(err?.message || `Failed to generate report for ${activeEntity.identifier}.`);
      } finally {
        setEntityLoading(false);
      }
    },
    [activeEntity, entityHistoryPage, entityHistoryPageSize, timeParams]
  );

  // -------------------------------------------------------------------------
  // Switch to Entity Mode
  // -------------------------------------------------------------------------
  const handleSelectEntity = (rawIdentifier: string, forcedType?: "client" | "domain") => {
    const clean = rawIdentifier.trim();
    if (!clean) return;

    let type: "client" | "domain" = forcedType || "domain";
    if (!forcedType) {
      const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(clean) || clean.includes(":");
      type = isIp ? "client" : "domain";
    }

    setActiveEntity({ identifier: clean, type });
    setEntitySearchInput(clean);
    setEntityHistoryPage(1);
    if (type === "client") setClientTab("queried-domains");
    else setDomainTab("querying-clients");

    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      params.set("entity", clean);
      params.set("entity_type", type);
      router.replace(`/reports?${params.toString()}`, { scroll: false });
    }
  };

  const handleClearEntity = () => {
    setActiveEntity(null);
    setEntitySearchInput("");
    setClientReport(null);
    setDomainReport(null);
    setApiError(null);

    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      params.delete("entity");
      params.delete("entity_type");
      params.delete("type");
      const newQuery = params.toString();
      router.replace(newQuery ? `/reports?${newQuery}` : "/reports", { scroll: false });
    }
  };

  // Synchronize URL search parameters (?entity=...&entity_type=...) on mount/change
  useEffect(() => {
    const urlEntity = searchParams?.get("entity");
    const urlType = searchParams?.get("entity_type") || searchParams?.get("type");
    if (urlEntity && urlEntity.trim()) {
      const clean = urlEntity.trim();
      const detectedType: "client" | "domain" =
        urlType === "client" || urlType === "domain"
          ? urlType
          : (clean.includes(":") || /^(\d{1,3}\.){3}\d{1,3}$/.test(clean) ? "client" : "domain");
      setActiveEntity((prev) => {
        if (prev?.identifier === clean && prev?.type === detectedType) return prev;
        return { identifier: clean, type: detectedType };
      });
      setEntitySearchInput(clean);
    }
  }, [searchParams]);

  // -------------------------------------------------------------------------
  // Unified Refresh All
  // -------------------------------------------------------------------------
  const refreshAll = useCallback(async () => {
    setIsRefreshing(true);
    if (activeEntity) {
      await fetchEntityReport(1);
    } else {
      await Promise.all([
        fetchSummary(),
        globalTab === "queries" ? fetchQueries(1) : Promise.resolve(),
        globalTab === "domains" ? fetchDomains(1) : Promise.resolve(),
        globalTab === "malicious-domains" ? fetchMalDomains(1) : Promise.resolve(),
        globalTab === "clients" ? fetchClients(1) : Promise.resolve(),
        globalTab === "flagged" ? fetchFlagged(1) : Promise.resolve(),
      ]);
    }
    setIsRefreshing(false);
  }, [activeEntity, fetchEntityReport, fetchSummary, globalTab, fetchQueries, fetchDomains, fetchMalDomains, fetchClients, fetchFlagged]);

  // Register with Global Refresh Handler
  useEffect(() => {
    return registerRefreshHandler(refreshAll);
  }, [registerRefreshHandler, refreshAll]);

  // React to Time Range Changes
  useEffect(() => {
    if (activeEntity) {
      fetchEntityReport(1);
    } else {
      fetchSummary();
      if (globalTab === "queries") fetchQueries(1);
      else if (globalTab === "domains") fetchDomains(1);
      else if (globalTab === "malicious-domains") fetchMalDomains(1);
      else if (globalTab === "clients") fetchClients(1);
      else if (globalTab === "flagged") fetchFlagged(1);
    }
  }, [timeParams, activeEntity]); // eslint-disable-line react-hooks/exhaustive-deps

  // React to Tab Switch (Global Mode)
  useEffect(() => {
    if (activeEntity) return;
    if (globalTab === "queries") fetchQueries(1);
    else if (globalTab === "domains") fetchDomains(1);
    else if (globalTab === "malicious-domains") fetchMalDomains(1);
    else if (globalTab === "clients") fetchClients(1);
    else if (globalTab === "flagged") fetchFlagged(1);
  }, [globalTab]); // eslint-disable-line react-hooks/exhaustive-deps

  // -------------------------------------------------------------------------
  // CSV Export Handler
  // -------------------------------------------------------------------------
  const handleExportCsv = async () => {
    try {
      setExporting(true);
      if (activeEntity) {
        // Entity export
        let tableTarget: any = "client-domains";
        if (activeEntity.type === "client") {
          if (clientTab === "queried-domains") tableTarget = "client-domains";
          else if (clientTab === "malicious-domains") tableTarget = "client-malicious";
          else if (clientTab === "clean-domains" || clientTab === "benign-domains") tableTarget = "client-benign";
          else if (clientTab === "review-needed-domains") tableTarget = "client-review-needed";
          else if (clientTab === "unknown-domains") tableTarget = "client-unknown";
          else tableTarget = "client-queries";
        } else {
          if (domainTab === "querying-clients") tableTarget = "domain-clients";
          else tableTarget = "domain-queries";
        }

        await apiClient.exportReportCsv({
          table: tableTarget,
          entity: activeEntity.identifier,
          entity_type: activeEntity.type,
          limit: 5000,
          ...timeParams,
        });
      } else {
        // Global export
        await apiClient.exportReportCsv({
          table: globalTab,
          search:
            globalTab === "queries"
              ? queriesSearch || undefined
              : globalTab === "domains"
              ? domainsSearch || undefined
              : globalTab === "malicious-domains"
              ? malDomainsSearch || undefined
              : globalTab === "clients"
              ? clientsSearch || undefined
              : flaggedSearch || undefined,
          label: globalTab === "queries" && queriesLabel !== "All" ? queriesLabel : undefined,
          limit: 5000,
          ...timeParams,
        });
      }
    } catch (err) {
      console.error("Failed to export CSV:", err);
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-5 select-none pb-12">
      {/* 1. Page Header & Breadcrumbs */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <nav
            aria-label="Breadcrumb"
            className="flex items-center gap-1.5 text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mb-1"
          >
            <span
              onClick={() => router.push("/")}
              className="hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6] transition-colors cursor-pointer"
            >
              Home
            </span>
            <ChevronRight className="w-3 h-3 text-[#9C9C9C]" />
            <span
              onClick={handleClearEntity}
              className={cn(
                "transition-colors",
                activeEntity
                  ? "hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6] cursor-pointer"
                  : "text-[#1A1A1A] dark:text-[#F3F4F6] font-medium"
              )}
            >
              Operational Reports
            </span>
            {activeEntity && (
              <>
                <ChevronRight className="w-3 h-3 text-[#9C9C9C]" />
                <span className="text-[#1A1A1A] dark:text-[#F3F4F6] font-medium">
                  {activeEntity.type === "client" ? "Client IP Report" : "Domain Report"}
                </span>
              </>
            )}
          </nav>

          <div className="flex items-center gap-3">
            <h1 className="text-[24px] sm:text-[26px] font-semibold tracking-tight text-[#1A1A1A] dark:text-[#F3F4F6]">
              {activeEntity
                ? `${activeEntity.type === "client" ? "Client Report" : "Domain Report"}: ${activeEntity.identifier}`
                : "Security Telemetry & Operational Reports"}
            </h1>
            <span className="flex items-center gap-1.5 text-[12px] font-medium text-emerald-600 dark:text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              {isLive ? "Operational" : "Historical Window"}
            </span>
          </div>
          <p className="text-xs text-[#6B6B6B] dark:text-[#9CA3AF] mt-0.5">
            {activeEntity
              ? `Deep time-scoped telemetry analysis for ${activeEntity.identifier} from PostgreSQL event history.`
              : "Structured query forensics, entity aggregations, top talkers, and verifiable audit records."}
          </p>
        </div>

        {/* Global Controls */}
        <div className="flex flex-wrap items-center gap-2 self-stretch sm:self-auto justify-end">
          <GlobalTimeRangePicker />

          {/* Refresh Button */}
          <button
            type="button"
            onClick={refreshAll}
            disabled={isRefreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-white dark:bg-[#121826] border border-[#D9D9D9] dark:border-[#2D3A54] hover:border-[#9C9C9C] text-[#1A1A1A] dark:text-[#F3F4F6] text-[13px] font-medium rounded-[6px] shadow-2xs transition-colors cursor-pointer disabled:opacity-50"
          >
            <RotateCcw className={cn("w-3.5 h-3.5", isRefreshing && "animate-spin text-blue-500")} />
            <span>Refresh</span>
          </button>

          {/* Export CSV Button */}
          <button
            type="button"
            onClick={handleExportCsv}
            disabled={exporting}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-primary hover:bg-primary/90 text-primary-foreground text-[13px] font-medium rounded-[6px] shadow-xs transition-colors cursor-pointer disabled:opacity-60"
          >
            {exporting ? (
              <RotateCcw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Download className="w-3.5 h-3.5" />
            )}
            <span>{exporting ? "Exporting..." : "Export CSV"}</span>
          </button>
        </div>
      </div>

      {/* 2. Search & Entity Dispatcher Toolbar */}
      <div className="bg-white dark:bg-[#121826] border border-[#EBEBEB] dark:border-[#1E283D] rounded-[10px] p-3 shadow-2xs">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSelectEntity(entitySearchInput);
          }}
          className="flex flex-wrap items-center gap-2.5"
        >
          <div className="relative flex-1 min-w-[280px]">
            <Search className="absolute left-3 top-2.5 w-4 h-4 text-[#9C9C9C]" />
            <input
              type="text"
              placeholder="Enter Client IP (e.g. 192.168.1.104) or Domain (e.g. stackoverflow.com) to generate entity report..."
              value={entitySearchInput}
              onChange={(e) => setEntitySearchInput(e.target.value)}
              className="w-full pl-9 pr-8 py-2 bg-white dark:bg-[#121826] border border-[#D9D9D9] dark:border-[#2D3A54] rounded-[6px] text-xs text-[#1A1A1A] dark:text-[#F3F4F6] placeholder:text-[#9C9C9C] focus:outline-hidden focus:ring-1 focus:ring-[#2F6FED] font-mono"
            />
            {entitySearchInput && (
              <button
                type="button"
                onClick={() => setEntitySearchInput("")}
                className="absolute right-2.5 top-2.5 text-[#9C9C9C] hover:text-[#1A1A1A] dark:hover:text-white"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <button
            type="submit"
            className="px-4 py-2 bg-[#2F6FED] hover:bg-[#255ED4] text-white text-xs font-medium rounded-[6px] transition-colors cursor-pointer flex items-center gap-1.5"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Generate Entity Report</span>
          </button>

          {activeEntity && (
            <button
              type="button"
              onClick={handleClearEntity}
              className="px-3 py-2 bg-neutral-100 dark:bg-[#1C2638] hover:bg-neutral-200 dark:hover:bg-[#243147] text-[#1A1A1A] dark:text-[#F3F4F6] text-xs font-medium rounded-[6px] transition-colors cursor-pointer flex items-center gap-1.5"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Global Overview</span>
            </button>
          )}
        </form>
      </div>

      {/* 3. API Connection Error Alert */}
      {apiError && (
        <div className="p-3.5 rounded-[8px] bg-red-500/10 border border-red-500/30 text-red-600 dark:text-red-400 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{apiError}</span>
          </div>
          <button
            type="button"
            onClick={refreshAll}
            className="px-2.5 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-600 dark:text-red-300 font-medium rounded text-[11px] transition-colors cursor-pointer"
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* =================================================================== */}
      {/* MODE A: ENTITY REPORT (Client IP or Domain)                         */}
      {/* =================================================================== */}
      {activeEntity ? (
        <div className="space-y-4">
          {/* Active Entity Info Banner */}
          <div className="p-3 bg-neutral-50 dark:bg-[#161F33]/40 border border-[#EBEBEB] dark:border-[#1E283D] rounded-[8px] flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2.5">
              {activeEntity.type === "client" ? (
                <Monitor className="w-4 h-4 text-blue-500" />
              ) : (
                <Globe className="w-4 h-4 text-indigo-500" />
              )}
              <span className="text-[11px] uppercase tracking-wider font-semibold text-muted-foreground">ENTITY:</span>
              <span className="font-mono text-sm font-semibold text-foreground">
                {activeEntity.identifier}
              </span>
              <span className="text-[11px] uppercase tracking-wider font-semibold text-muted-foreground ml-2">TYPE:</span>
              <Badge variant="outline" className="text-[11px] uppercase font-mono font-medium">
                {activeEntity.type === "client" ? "CLIENT IP" : "DOMAIN"}
              </Badge>
              <Badge variant="secondary" className="text-[10px]">
                Time-Scoped: {timeRange.label}
              </Badge>
            </div>
            <button
              type="button"
              onClick={handleClearEntity}
              className="text-xs text-[#2F6FED] hover:underline flex items-center gap-1 cursor-pointer font-medium"
            >
              <ArrowLeft className="w-3 h-3" />
              Exit Entity Report
            </button>
          </div>

          {/* Client Entity View */}
          {activeEntity.type === "client" && (
            <>
              {/* Client KPIs */}
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
                <OverviewKpiCard
                  title="Total Queries"
                  value={entityLoading ? "..." : (clientReport?.summary.total_queries ?? 0).toLocaleString()}
                  className="h-[84px]"
                />
                <OverviewKpiCard
                  title="Unique Domains"
                  value={entityLoading ? "..." : (clientReport?.summary.unique_domains ?? 0).toLocaleString()}
                  className="h-[84px]"
                />
                <OverviewKpiCard
                  title="Benign Domains"
                  value={entityLoading ? "..." : ((clientReport?.summary.benign_domains ?? clientReport?.summary.clean_domains) ?? 0).toLocaleString()}
                  className="h-[84px]"
                />
                <OverviewKpiCard
                  title="Malicious Domains"
                  value={entityLoading ? "..." : (clientReport?.summary.malicious_domains ?? 0).toLocaleString()}
                  className="h-[84px]"
                />
                <OverviewKpiCard
                  title="Review Needed"
                  value={entityLoading ? "..." : ((clientReport?.summary.review_needed_domains ?? clientReport?.summary.suspicious_domains) ?? 0).toLocaleString()}
                  className="h-[84px]"
                />
                <OverviewKpiCard
                  title="Threat Exposure"
                  value={entityLoading ? "..." : `${(clientReport?.summary.threat_percentage ?? 0).toFixed(2)}%`}
                  className="h-[84px]"
                />
              </div>

              {/* Client Tabs */}
              <div className="border-b border-[#EBEBEB] dark:border-[#1E283D]">
                <div className="flex items-center gap-1 overflow-x-auto no-scrollbar">
                  <button
                    type="button"
                    onClick={() => setClientTab("queried-domains")}
                    className={cn(
                      "flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap cursor-pointer",
                      clientTab === "queried-domains"
                        ? "border-[#2F6FED] text-[#2F6FED] dark:text-blue-400 font-semibold"
                        : "border-transparent text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                    )}
                  >
                    <Globe className="w-3.5 h-3.5" />
                    <span>Most Queried Domains</span>
                    {clientReport && clientReport.most_queried_domains.length > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-muted text-muted-foreground">
                        {clientReport.most_queried_domains.length}
                      </span>
                    )}
                  </button>

                  <button
                    type="button"
                    onClick={() => setClientTab("malicious-domains")}
                    className={cn(
                      "flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap cursor-pointer",
                      clientTab === "malicious-domains"
                        ? "border-red-500 text-red-500 dark:text-red-400 font-semibold"
                        : "border-transparent text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                    )}
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>Malicious Domains</span>
                    {clientReport && clientReport.malicious_domains.length > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-red-500/10 text-red-500 font-semibold">
                        {clientReport.malicious_domains.length}
                      </span>
                    )}
                  </button>

                  <button
                    type="button"
                    onClick={() => setClientTab("benign-domains")}
                    className={cn(
                      "flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap cursor-pointer",
                      clientTab === "benign-domains" || clientTab === "clean-domains"
                        ? "border-emerald-500 text-emerald-600 dark:text-emerald-400 font-semibold"
                        : "border-transparent text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                    )}
                  >
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Benign Domains</span>
                    {clientReport && (clientReport.benign_domains || clientReport.clean_domains || []).length > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-emerald-500/10 text-emerald-600 font-semibold">
                        {(clientReport.benign_domains || clientReport.clean_domains || []).length}
                      </span>
                    )}
                  </button>

                  <button
                    type="button"
                    onClick={() => setClientTab("review-needed-domains")}
                    className={cn(
                      "flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap cursor-pointer",
                      clientTab === "review-needed-domains"
                        ? "border-amber-500 text-amber-600 dark:text-amber-400 font-semibold"
                        : "border-transparent text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                    )}
                  >
                    <Flame className="w-3.5 h-3.5" />
                    <span>Review Needed Domains</span>
                    {clientReport && (clientReport.review_needed_domains || []).length > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-amber-500/10 text-amber-600 font-semibold">
                        {(clientReport.review_needed_domains || []).length}
                      </span>
                    )}
                  </button>

                  <button
                    type="button"
                    onClick={() => setClientTab("unknown-domains")}
                    className={cn(
                      "flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap cursor-pointer",
                      clientTab === "unknown-domains"
                        ? "border-purple-500 text-purple-600 dark:text-purple-400 font-semibold"
                        : "border-transparent text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                    )}
                  >
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Unknown Domains</span>
                    {clientReport && (clientReport.unknown_domains || []).length > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-purple-500/10 text-purple-600 font-semibold">
                        {(clientReport.unknown_domains || []).length}
                      </span>
                    )}
                  </button>

                  <button
                    type="button"
                    onClick={() => setClientTab("query-history")}
                    className={cn(
                      "flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap cursor-pointer",
                      clientTab === "query-history"
                        ? "border-[#2F6FED] text-[#2F6FED] dark:text-blue-400 font-semibold"
                        : "border-transparent text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                    )}
                  >
                    <FileText className="w-3.5 h-3.5" />
                    <span>Complete Query History</span>
                    {clientReport && clientReport.meta.total > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-muted text-muted-foreground">
                        {clientReport.meta.total.toLocaleString()}
                      </span>
                    )}
                  </button>
                </div>
              </div>

              {/* Client Data Presentation */}
              <div className="bg-white dark:bg-[#121826] border border-[#EBEBEB] dark:border-[#1E283D] rounded-[12px] shadow-2xs overflow-hidden">
                {clientTab === "queried-domains" && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-[#F9FAFB] dark:bg-[#151C2C] text-[#6B6B6B] dark:text-[#9CA3AF] border-b border-[#EBEBEB] dark:border-[#1E283D]">
                        <tr>
                          <th className="px-4 py-2.5 font-medium">Domain</th>
                          <th className="px-4 py-2.5 font-medium text-right">Queries</th>
                          <th className="px-4 py-2.5 font-medium text-right">Malicious</th>
                          <th className="px-4 py-2.5 font-medium text-right">Benign</th>
                          <th className="px-4 py-2.5 font-medium text-right">Review Needed</th>
                          <th className="px-4 py-2.5 font-medium text-right">Unknown</th>
                          <th className="px-4 py-2.5 font-medium">First Seen</th>
                          <th className="px-4 py-2.5 font-medium">Last Seen</th>
                          <th className="px-4 py-2.5 font-medium">Latest Verdict</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70 font-mono">
                        {entityLoading ? (
                          Array.from({ length: 6 }).map((_, i) => (
                            <tr key={i} className="animate-pulse">
                              <td colSpan={9} className="px-4 py-3">
                                <Skeleton className="h-4 w-full" />
                              </td>
                            </tr>
                          ))
                        ) : !clientReport || clientReport.most_queried_domains.length === 0 ? (
                          <tr>
                            <td colSpan={9} className="px-4 py-12 text-center text-[#9C9C9C] font-sans">
                              <p className="text-sm font-medium">No queried domains recorded for this client in the selected time range.</p>
                            </td>
                          </tr>
                        ) : (
                          clientReport.most_queried_domains.map((d) => (
                            <tr key={d.domain} className="hover:bg-neutral-50/70 dark:hover:bg-[#161F33]/50 transition-colors">
                              <td className="px-4 py-2.5 font-medium text-foreground max-w-[260px] truncate">
                                <span
                                  onClick={() => handleSelectEntity(d.domain, "domain")}
                                  className="hover:text-[#2F6FED] hover:underline cursor-pointer"
                                  title={d.domain}
                                >
                                  {d.domain}
                                </span>
                              </td>
                              <td className="px-4 py-2.5 text-right font-semibold text-foreground">
                                {d.query_count.toLocaleString()}
                              </td>
                              <td className="px-4 py-2.5 text-right">
                                {d.malicious_queries > 0 ? (
                                  <span className="text-red-500 font-bold">{d.malicious_queries}</span>
                                ) : (
                                  <span className="text-muted-foreground">0</span>
                                )}
                              </td>
                              <td className="px-4 py-2.5 text-right text-muted-foreground">
                                {((d.benign_queries ?? d.clean_queries) ?? 0).toLocaleString()}
                              </td>
                              <td className="px-4 py-2.5 text-right text-muted-foreground">
                                {((d.review_needed_queries ?? d.suspicious_queries) ?? 0).toLocaleString()}
                              </td>
                              <td className="px-4 py-2.5 text-right text-muted-foreground">
                                {(d.unknown_queries ?? 0).toLocaleString()}
                              </td>
                              <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{d.first_seen || "—"}</td>
                              <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{d.last_seen || "—"}</td>
                              <td className="px-4 py-2.5 font-sans">
                                <VerdictBadge verdict={d.latest_verdict} />
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                )}

                {clientTab === "malicious-domains" && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-[#F9FAFB] dark:bg-[#151C2C] text-[#6B6B6B] dark:text-[#9CA3AF] border-b border-[#EBEBEB] dark:border-[#1E283D]">
                        <tr>
                          <th className="px-4 py-2.5 font-medium">Domain</th>
                          <th className="px-4 py-2.5 font-medium text-right">Total Queries</th>
                          <th className="px-4 py-2.5 font-medium text-right">Malicious Events</th>
                          <th className="px-4 py-2.5 font-medium">Verdict</th>
                          <th className="px-4 py-2.5 font-medium">Threat Source</th>
                          <th className="px-4 py-2.5 font-medium">First Seen</th>
                          <th className="px-4 py-2.5 font-medium">Last Seen</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70 font-mono">
                        {entityLoading ? (
                          Array.from({ length: 6 }).map((_, i) => (
                            <tr key={i} className="animate-pulse">
                              <td colSpan={7} className="px-4 py-3">
                                <Skeleton className="h-4 w-full" />
                              </td>
                            </tr>
                          ))
                        ) : !clientReport || clientReport.malicious_domains.length === 0 ? (
                          <tr>
                            <td colSpan={7} className="px-4 py-12 text-center text-[#9C9C9C] font-sans">
                              <p className="text-sm font-medium">Zero malicious domains queried by this client in this interval.</p>
                              <p className="text-xs text-muted-foreground mt-1">All activity remained clean.</p>
                            </td>
                          </tr>
                        ) : (
                          clientReport.malicious_domains.map((d) => (
                            <tr key={d.domain} className="hover:bg-neutral-50/70 dark:hover:bg-[#161F33]/50 transition-colors">
                              <td className="px-4 py-2.5 font-medium text-foreground max-w-[260px] truncate">
                                <span
                                  onClick={() => handleSelectEntity(d.domain, "domain")}
                                  className="hover:text-red-500 hover:underline cursor-pointer"
                                  title={d.domain}
                                >
                                  {d.domain}
                                </span>
                              </td>
                              <td className="px-4 py-2.5 text-right font-semibold text-foreground">
                                {d.query_count.toLocaleString()}
                              </td>
                              <td className="px-4 py-2.5 text-right text-red-500 font-bold">
                                {d.malicious_queries.toLocaleString()}
                              </td>
                              <td className="px-4 py-2.5 font-sans">
                                <VerdictBadge verdict={d.latest_verdict} />
                              </td>
                              <td className="px-4 py-2.5 text-[11px] font-sans text-muted-foreground">
                                {d.ti_source}
                              </td>
                              <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{d.first_seen || "—"}</td>
                              <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{d.last_seen || "—"}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                )}

                {(clientTab === "clean-domains" || clientTab === "benign-domains") && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-[#F9FAFB] dark:bg-[#151C2C] text-[#6B6B6B] dark:text-[#9CA3AF] border-b border-[#EBEBEB] dark:border-[#1E283D]">
                        <tr>
                          <th className="px-4 py-2.5 font-medium">Domain</th>
                          <th className="px-4 py-2.5 font-medium text-right">Queries</th>
                          <th className="px-4 py-2.5 font-medium">Verdict</th>
                          <th className="px-4 py-2.5 font-medium">First Seen</th>
                          <th className="px-4 py-2.5 font-medium">Last Seen</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70 font-mono">
                        {entityLoading ? (
                          Array.from({ length: 6 }).map((_, i) => (
                            <tr key={i} className="animate-pulse">
                              <td colSpan={5} className="px-4 py-3">
                                <Skeleton className="h-4 w-full" />
                              </td>
                            </tr>
                          ))
                        ) : !clientReport || (clientReport.benign_domains || clientReport.clean_domains || []).length === 0 ? (
                          <tr>
                            <td colSpan={5} className="px-4 py-12 text-center text-[#9C9C9C] font-sans">
                              <p className="text-sm font-medium">No benign domains recorded in this interval.</p>
                            </td>
                          </tr>
                        ) : (
                          (clientReport.benign_domains || clientReport.clean_domains || []).map((d) => (
                            <tr key={d.domain} className="hover:bg-neutral-50/70 dark:hover:bg-[#161F33]/50 transition-colors">
                              <td className="px-4 py-2.5 font-medium text-foreground max-w-[260px] truncate">
                                <span
                                  onClick={() => handleSelectEntity(d.domain, "domain")}
                                  className="hover:text-[#2F6FED] hover:underline cursor-pointer"
                                  title={d.domain}
                                >
                                  {d.domain}
                                </span>
                              </td>
                              <td className="px-4 py-2.5 text-right font-semibold text-foreground">
                                {d.query_count.toLocaleString()}
                              </td>
                              <td className="px-4 py-2.5 font-sans">
                                <VerdictBadge verdict={d.latest_verdict} />
                              </td>
                              <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{d.first_seen || "—"}</td>
                              <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{d.last_seen || "—"}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                )}

                {clientTab === "review-needed-domains" && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-[#F9FAFB] dark:bg-[#151C2C] text-[#6B6B6B] dark:text-[#9CA3AF] border-b border-[#EBEBEB] dark:border-[#1E283D]">
                        <tr>
                          <th className="px-4 py-2.5 font-medium">Domain</th>
                          <th className="px-4 py-2.5 font-medium text-right">Queries</th>
                          <th className="px-4 py-2.5 font-medium">Verdict</th>
                          <th className="px-4 py-2.5 font-medium">First Seen</th>
                          <th className="px-4 py-2.5 font-medium">Last Seen</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70 font-mono">
                        {entityLoading ? (
                          Array.from({ length: 6 }).map((_, i) => (
                            <tr key={i} className="animate-pulse">
                              <td colSpan={5} className="px-4 py-3">
                                <Skeleton className="h-4 w-full" />
                              </td>
                            </tr>
                          ))
                        ) : !clientReport || (clientReport.review_needed_domains || []).length === 0 ? (
                          <tr>
                            <td colSpan={5} className="px-4 py-12 text-center text-[#9C9C9C] font-sans">
                              <p className="text-sm font-medium">No review needed domains recorded in this interval.</p>
                            </td>
                          </tr>
                        ) : (
                          (clientReport.review_needed_domains || []).map((d) => (
                            <tr key={d.domain} className="hover:bg-neutral-50/70 dark:hover:bg-[#161F33]/50 transition-colors">
                              <td className="px-4 py-2.5 font-medium text-foreground max-w-[260px] truncate">
                                <span
                                  onClick={() => handleSelectEntity(d.domain, "domain")}
                                  className="hover:text-[#2F6FED] hover:underline cursor-pointer"
                                  title={d.domain}
                                >
                                  {d.domain}
                                </span>
                              </td>
                              <td className="px-4 py-2.5 text-right font-semibold text-foreground">
                                {d.query_count.toLocaleString()}
                              </td>
                              <td className="px-4 py-2.5 font-sans">
                                <VerdictBadge verdict={d.latest_verdict} />
                              </td>
                              <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{d.first_seen || "—"}</td>
                              <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{d.last_seen || "—"}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                )}

                {clientTab === "unknown-domains" && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-[#F9FAFB] dark:bg-[#151C2C] text-[#6B6B6B] dark:text-[#9CA3AF] border-b border-[#EBEBEB] dark:border-[#1E283D]">
                        <tr>
                          <th className="px-4 py-2.5 font-medium">Domain</th>
                          <th className="px-4 py-2.5 font-medium text-right">Queries</th>
                          <th className="px-4 py-2.5 font-medium">Verdict</th>
                          <th className="px-4 py-2.5 font-medium">First Seen</th>
                          <th className="px-4 py-2.5 font-medium">Last Seen</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70 font-mono">
                        {entityLoading ? (
                          Array.from({ length: 6 }).map((_, i) => (
                            <tr key={i} className="animate-pulse">
                              <td colSpan={5} className="px-4 py-3">
                                <Skeleton className="h-4 w-full" />
                              </td>
                            </tr>
                          ))
                        ) : !clientReport || (clientReport.unknown_domains || []).length === 0 ? (
                          <tr>
                            <td colSpan={5} className="px-4 py-12 text-center text-[#9C9C9C] font-sans">
                              <p className="text-sm font-medium">No unknown domains recorded in this interval.</p>
                            </td>
                          </tr>
                        ) : (
                          (clientReport.unknown_domains || []).map((d) => (
                            <tr key={d.domain} className="hover:bg-neutral-50/70 dark:hover:bg-[#161F33]/50 transition-colors">
                              <td className="px-4 py-2.5 font-medium text-foreground max-w-[260px] truncate">
                                <span
                                  onClick={() => handleSelectEntity(d.domain, "domain")}
                                  className="hover:text-[#2F6FED] hover:underline cursor-pointer"
                                  title={d.domain}
                                >
                                  {d.domain}
                                </span>
                              </td>
                              <td className="px-4 py-2.5 text-right font-semibold text-foreground">
                                {d.query_count.toLocaleString()}
                              </td>
                              <td className="px-4 py-2.5 font-sans">
                                <VerdictBadge verdict={d.latest_verdict} />
                              </td>
                              <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{d.first_seen || "—"}</td>
                              <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{d.last_seen || "—"}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                )}

                {clientTab === "query-history" && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-[#F9FAFB] dark:bg-[#151C2C] text-[#6B6B6B] dark:text-[#9CA3AF] border-b border-[#EBEBEB] dark:border-[#1E283D]">
                        <tr>
                          <th className="px-4 py-2.5 font-medium">Timestamp</th>
                          <th className="px-4 py-2.5 font-medium">Domain</th>
                          <th className="px-4 py-2.5 font-medium text-center">Type</th>
                          <th className="px-4 py-2.5 font-medium">Verdict</th>
                          <th className="px-4 py-2.5 font-medium">Threat Source</th>
                          <th className="px-4 py-2.5 font-medium text-right">RCode</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70 font-mono">
                        {entityLoading ? (
                          Array.from({ length: 6 }).map((_, i) => (
                            <tr key={i} className="animate-pulse">
                              <td colSpan={6} className="px-4 py-3">
                                <Skeleton className="h-4 w-full" />
                              </td>
                            </tr>
                          ))
                        ) : !clientReport || clientReport.query_history.length === 0 ? (
                          <tr>
                            <td colSpan={6} className="px-4 py-12 text-center text-[#9C9C9C] font-sans">
                              <p className="text-sm font-medium">No individual DNS query history for this client in this window.</p>
                            </td>
                          </tr>
                        ) : (
                          clientReport.query_history.map((q) => (
                            <tr key={q.id} className="hover:bg-neutral-50/70 dark:hover:bg-[#161F33]/50 transition-colors">
                              <td className="px-4 py-2.5 text-muted-foreground text-[11px] whitespace-nowrap">{q.timestamp}</td>
                              <td className="px-4 py-2.5 font-medium text-foreground max-w-[240px] truncate">
                                <span
                                  onClick={() => handleSelectEntity(q.domain, "domain")}
                                  className="hover:text-[#2F6FED] hover:underline cursor-pointer"
                                  title={q.domain}
                                >
                                  {q.domain}
                                </span>
                              </td>
                              <td className="px-4 py-2.5 text-center text-[10px]">
                                <span className="px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-semibold">
                                  {q.query_type}
                                </span>
                              </td>
                              <td className="px-4 py-2.5 font-sans">
                                <VerdictBadge verdict={q.final_label} />
                              </td>
                              <td className="px-4 py-2.5 text-[11px] font-sans text-muted-foreground">{q.ti_source || "—"}</td>
                              <td className="px-4 py-2.5 text-right text-[11px] text-muted-foreground">{q.response_code || "NOERROR"}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </>
          )}

          {/* Domain Entity View */}
          {activeEntity.type === "domain" && (
            <>
              {/* Domain KPIs */}
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
                <OverviewKpiCard
                  title="Total Queries"
                  value={entityLoading ? "..." : (domainReport?.summary.total_queries ?? 0).toLocaleString()}
                  className="h-[84px]"
                />
                <OverviewKpiCard
                  title="Unique Clients"
                  value={entityLoading ? "..." : (domainReport?.summary.unique_clients ?? 0).toLocaleString()}
                  className="h-[84px]"
                />
                <OverviewKpiCard
                  title="Benign Queries"
                  value={entityLoading ? "..." : ((domainReport?.summary.benign_queries ?? domainReport?.summary.clean_queries) ?? 0).toLocaleString()}
                  className="h-[84px]"
                />
                <OverviewKpiCard
                  title="Malicious Queries"
                  value={entityLoading ? "..." : (domainReport?.summary.malicious_queries ?? 0).toLocaleString()}
                  className="h-[84px]"
                />
                <OverviewKpiCard
                  title="Review Needed"
                  value={entityLoading ? "..." : ((domainReport?.summary.review_needed_queries ?? domainReport?.summary.suspicious_queries) ?? 0).toLocaleString()}
                  className="h-[84px]"
                />
                <OverviewKpiCard
                  title="Threat Rate"
                  value={entityLoading ? "..." : `${(domainReport?.summary.threat_percentage ?? 0).toFixed(2)}%`}
                  className="h-[84px]"
                />
              </div>

              {/* Domain Tabs */}
              <div className="border-b border-[#EBEBEB] dark:border-[#1E283D]">
                <div className="flex items-center gap-1 overflow-x-auto no-scrollbar">
                  <button
                    type="button"
                    onClick={() => setDomainTab("querying-clients")}
                    className={cn(
                      "flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap cursor-pointer",
                      domainTab === "querying-clients"
                        ? "border-[#2F6FED] text-[#2F6FED] dark:text-blue-400 font-semibold"
                        : "border-transparent text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                    )}
                  >
                    <Monitor className="w-3.5 h-3.5" />
                    <span>Clients Querying This Domain</span>
                    {domainReport && domainReport.clients_querying.length > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-muted text-muted-foreground">
                        {domainReport.clients_querying.length}
                      </span>
                    )}
                  </button>

                  <button
                    type="button"
                    onClick={() => setDomainTab("query-history")}
                    className={cn(
                      "flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap cursor-pointer",
                      domainTab === "query-history"
                        ? "border-[#2F6FED] text-[#2F6FED] dark:text-blue-400 font-semibold"
                        : "border-transparent text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                    )}
                  >
                    <FileText className="w-3.5 h-3.5" />
                    <span>Complete Query History</span>
                    {domainReport && domainReport.meta.total > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-muted text-muted-foreground">
                        {domainReport.meta.total.toLocaleString()}
                      </span>
                    )}
                  </button>
                </div>
              </div>

              {/* Domain Data Presentation */}
              <div className="bg-white dark:bg-[#121826] border border-[#EBEBEB] dark:border-[#1E283D] rounded-[12px] shadow-2xs overflow-hidden">
                {domainTab === "querying-clients" && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-[#F9FAFB] dark:bg-[#151C2C] text-[#6B6B6B] dark:text-[#9CA3AF] border-b border-[#EBEBEB] dark:border-[#1E283D]">
                        <tr>
                          <th className="px-4 py-2.5 font-medium">Client IP</th>
                          <th className="px-4 py-2.5 font-medium text-right">Total Queries</th>
                          <th className="px-4 py-2.5 font-medium text-right">Malicious</th>
                          <th className="px-4 py-2.5 font-medium text-right">Benign</th>
                          <th className="px-4 py-2.5 font-medium text-right">Review Needed</th>
                          <th className="px-4 py-2.5 font-medium text-right">Unknown</th>
                          <th className="px-4 py-2.5 font-medium">First Seen</th>
                          <th className="px-4 py-2.5 font-medium">Last Seen</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70 font-mono">
                        {entityLoading ? (
                          Array.from({ length: 6 }).map((_, i) => (
                            <tr key={i} className="animate-pulse">
                              <td colSpan={8} className="px-4 py-3">
                                <Skeleton className="h-4 w-full" />
                              </td>
                            </tr>
                          ))
                        ) : !domainReport || domainReport.clients_querying.length === 0 ? (
                          <tr>
                            <td colSpan={8} className="px-4 py-12 text-center text-[#9C9C9C] font-sans">
                              <p className="text-sm font-medium">No clients queried this domain during the selected time period.</p>
                            </td>
                          </tr>
                        ) : (
                          domainReport.clients_querying.map((c) => (
                            <tr key={c.client_ip} className="hover:bg-neutral-50/70 dark:hover:bg-[#161F33]/50 transition-colors">
                              <td className="px-4 py-2.5 font-medium text-foreground">
                                <span
                                  onClick={() => handleSelectEntity(c.client_ip, "client")}
                                  className="hover:text-[#2F6FED] hover:underline cursor-pointer"
                                >
                                  {c.client_ip}
                                </span>
                              </td>
                              <td className="px-4 py-2.5 text-right font-semibold text-foreground">
                                {c.query_count.toLocaleString()}
                              </td>
                              <td className="px-4 py-2.5 text-right">
                                {c.malicious_queries > 0 ? (
                                  <span className="text-red-500 font-bold">{c.malicious_queries}</span>
                                ) : (
                                  <span className="text-muted-foreground">0</span>
                                )}
                              </td>
                              <td className="px-4 py-2.5 text-right text-muted-foreground">
                                {((c.benign_queries ?? c.clean_queries) ?? 0).toLocaleString()}
                              </td>
                              <td className="px-4 py-2.5 text-right text-muted-foreground">
                                {((c.review_needed_queries ?? c.suspicious_queries) ?? 0).toLocaleString()}
                              </td>
                              <td className="px-4 py-2.5 text-right text-muted-foreground">
                                {(c.unknown_queries ?? 0).toLocaleString()}
                              </td>
                              <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{c.first_seen || "—"}</td>
                              <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{c.last_seen || "—"}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                )}

                {domainTab === "query-history" && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-[#F9FAFB] dark:bg-[#151C2C] text-[#6B6B6B] dark:text-[#9CA3AF] border-b border-[#EBEBEB] dark:border-[#1E283D]">
                        <tr>
                          <th className="px-4 py-2.5 font-medium">Timestamp</th>
                          <th className="px-4 py-2.5 font-medium">Client IP</th>
                          <th className="px-4 py-2.5 font-medium text-center">Type</th>
                          <th className="px-4 py-2.5 font-medium">Verdict</th>
                          <th className="px-4 py-2.5 font-medium">Threat Source</th>
                          <th className="px-4 py-2.5 font-medium text-right">RCode</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70 font-mono">
                        {entityLoading ? (
                          Array.from({ length: 6 }).map((_, i) => (
                            <tr key={i} className="animate-pulse">
                              <td colSpan={6} className="px-4 py-3">
                                <Skeleton className="h-4 w-full" />
                              </td>
                            </tr>
                          ))
                        ) : !domainReport || domainReport.query_history.length === 0 ? (
                          <tr>
                            <td colSpan={6} className="px-4 py-12 text-center text-[#9C9C9C] font-sans">
                              <p className="text-sm font-medium">No individual query records observed for this domain in this window.</p>
                            </td>
                          </tr>
                        ) : (
                          domainReport.query_history.map((q) => (
                            <tr key={q.id} className="hover:bg-neutral-50/70 dark:hover:bg-[#161F33]/50 transition-colors">
                              <td className="px-4 py-2.5 text-muted-foreground text-[11px] whitespace-nowrap">{q.timestamp}</td>
                              <td className="px-4 py-2.5 font-medium text-foreground">
                                <span
                                  onClick={() => handleSelectEntity(q.client_ip, "client")}
                                  className="hover:text-[#2F6FED] hover:underline cursor-pointer"
                                >
                                  {q.client_ip}
                                </span>
                              </td>
                              <td className="px-4 py-2.5 text-center text-[10px]">
                                <span className="px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-semibold">
                                  {q.query_type}
                                </span>
                              </td>
                              <td className="px-4 py-2.5 font-sans">
                                <VerdictBadge verdict={q.final_label} />
                              </td>
                              <td className="px-4 py-2.5 text-[11px] font-sans text-muted-foreground">{q.ti_source || "—"}</td>
                              <td className="px-4 py-2.5 text-right text-[11px] text-muted-foreground">{q.response_code || "NOERROR"}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      ) : (
        /* ================================================================= */
        /* MODE B: GLOBAL OPERATIONAL REPORT                                 */
        /* ================================================================= */
        <div className="space-y-4">
          {/* Summary KPI Cards Row */}
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3 sm:gap-3.5">
            <OverviewKpiCard
              title="Total Queries"
              value={summaryLoading ? "..." : (summary?.total_queries ?? 0).toLocaleString()}
              className="h-[84px]"
            />
            <OverviewKpiCard
              title="Malicious Queries"
              value={summaryLoading ? "..." : (summary?.malicious_queries ?? 0).toLocaleString()}
              className="h-[84px]"
            />
            <OverviewKpiCard
              title="Threat Rate"
              value={summaryLoading ? "..." : `${(summary?.threat_percentage ?? 0).toFixed(2)}%`}
              className="h-[84px]"
            />
            <OverviewKpiCard
              title="Unique Domains"
              value={summaryLoading ? "..." : (summary?.unique_domains ?? 0).toLocaleString()}
              className="h-[84px]"
            />
            <OverviewKpiCard
              title="Unique Clients"
              value={summaryLoading ? "..." : (summary?.unique_clients ?? 0).toLocaleString()}
              className="h-[84px]"
            />
          </div>

          {/* Table Navigation Tabs */}
          <div className="border-b border-[#EBEBEB] dark:border-[#1E283D]">
            <div className="flex items-center gap-1 overflow-x-auto no-scrollbar">
              <button
                type="button"
                onClick={() => setGlobalTab("queries")}
                className={cn(
                  "flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap cursor-pointer",
                  globalTab === "queries"
                    ? "border-[#2F6FED] text-[#2F6FED] dark:text-blue-400 font-semibold"
                    : "border-transparent text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                )}
              >
                <FileText className="w-3.5 h-3.5" />
                <span>DNS Queries</span>
                {queriesMeta.total > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-muted text-muted-foreground">
                    {queriesMeta.total.toLocaleString()}
                  </span>
                )}
              </button>

              <button
                type="button"
                onClick={() => setGlobalTab("domains")}
                className={cn(
                  "flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap cursor-pointer",
                  globalTab === "domains"
                    ? "border-[#2F6FED] text-[#2F6FED] dark:text-blue-400 font-semibold"
                    : "border-transparent text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                )}
              >
                <Globe className="w-3.5 h-3.5" />
                <span>Top Domains</span>
                {domainsMeta.total > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-muted text-muted-foreground">
                    {domainsMeta.total.toLocaleString()}
                  </span>
                )}
              </button>

              <button
                type="button"
                onClick={() => setGlobalTab("malicious-domains")}
                className={cn(
                  "flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap cursor-pointer",
                  globalTab === "malicious-domains"
                    ? "border-red-500 text-red-500 dark:text-red-400 font-semibold"
                    : "border-transparent text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                )}
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>Malicious Domains</span>
                {malDomainsMeta.total > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-red-500/10 text-red-500 font-semibold">
                    {malDomainsMeta.total.toLocaleString()}
                  </span>
                )}
              </button>

              <button
                type="button"
                onClick={() => setGlobalTab("clients")}
                className={cn(
                  "flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap cursor-pointer",
                  globalTab === "clients"
                    ? "border-[#2F6FED] text-[#2F6FED] dark:text-blue-400 font-semibold"
                    : "border-transparent text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                )}
              >
                <Monitor className="w-3.5 h-3.5" />
                <span>Client Activity</span>
                {clientsMeta.total > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-muted text-muted-foreground">
                    {clientsMeta.total.toLocaleString()}
                  </span>
                )}
              </button>

              <button
                type="button"
                onClick={() => setGlobalTab("flagged")}
                className={cn(
                  "flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap cursor-pointer",
                  globalTab === "flagged"
                    ? "border-amber-500 text-amber-600 dark:text-amber-400 font-semibold"
                    : "border-transparent text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                )}
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Flagged Queries</span>
                {flaggedMeta.total > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-amber-500/10 text-amber-600 dark:text-amber-400 font-semibold">
                    {flaggedMeta.total.toLocaleString()}
                  </span>
                )}
              </button>
            </div>
          </div>

          {/* Active Global Table Presentation */}
          <div className="bg-white dark:bg-[#121826] border border-[#EBEBEB] dark:border-[#1E283D] rounded-[12px] shadow-2xs overflow-hidden">
            {/* Table Search & Filter Bar */}
            <div className="p-3 border-b border-[#EBEBEB] dark:border-[#1E283D] flex flex-wrap items-center justify-between gap-3 bg-neutral-50/50 dark:bg-[#161F33]/30">
              <div className="flex flex-wrap items-center gap-2.5 flex-1 min-w-[280px]">
                <div className="relative flex-1 max-w-sm">
                  <Search className="absolute left-2.5 top-2.5 w-3.5 h-3.5 text-[#9C9C9C]" />
                  <input
                    type="text"
                    placeholder={
                      globalTab === "clients"
                        ? "Filter by client IP (e.g. 192.168.1.1)..."
                        : "Filter domain or client IP..."
                    }
                    value={
                      globalTab === "queries"
                        ? queriesSearch
                        : globalTab === "domains"
                        ? domainsSearch
                        : globalTab === "malicious-domains"
                        ? malDomainsSearch
                        : globalTab === "clients"
                        ? clientsSearch
                        : flaggedSearch
                    }
                    onChange={(e) => {
                      const val = e.target.value;
                      if (globalTab === "queries") setQueriesSearch(val);
                      else if (globalTab === "domains") setDomainsSearch(val);
                      else if (globalTab === "malicious-domains") setMalDomainsSearch(val);
                      else if (globalTab === "clients") setClientsSearch(val);
                      else setFlaggedSearch(val);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        if (globalTab === "queries") fetchQueries(1);
                        else if (globalTab === "domains") fetchDomains(1);
                        else if (globalTab === "malicious-domains") fetchMalDomains(1);
                        else if (globalTab === "clients") fetchClients(1);
                        else fetchFlagged(1);
                      }
                    }}
                    className="w-full pl-8 pr-3 py-1.5 bg-white dark:bg-[#121826] border border-[#D9D9D9] dark:border-[#2D3A54] rounded-[6px] text-xs text-[#1A1A1A] dark:text-[#F3F4F6] placeholder:text-[#9C9C9C] focus:outline-hidden focus:ring-1 focus:ring-[#2F6FED]"
                  />
                </div>

                {globalTab === "queries" && (
                  <div className="flex items-center gap-1">
                    <span className="text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF]">Verdict:</span>
                    <select
                      value={queriesLabel}
                      onChange={(e) => setQueriesLabel(e.target.value)}
                      className="px-2 py-1.5 bg-white dark:bg-[#121826] border border-[#D9D9D9] dark:border-[#2D3A54] rounded-[6px] text-xs text-[#1A1A1A] dark:text-[#F3F4F6] cursor-pointer"
                    >
                      <option value="All">All Verdicts</option>
                      <option value="Malicious">Malicious</option>
                      <option value="Benign">Benign</option>
                      <option value="Review Needed">Review Needed</option>
                      <option value="Unknown">Unknown</option>
                    </select>
                  </div>
                )}
              </div>

              <Badge variant="outline" className="font-mono text-[11px]">
                {globalTab === "queries"
                  ? `${queriesMeta.total.toLocaleString()} ${queriesMeta.total === 1 ? "event" : "events"}`
                  : globalTab === "domains"
                  ? `${domainsMeta.total.toLocaleString()} ${domainsMeta.total === 1 ? "domain" : "domains"}`
                  : globalTab === "malicious-domains"
                  ? `${malDomainsMeta.total.toLocaleString()} malicious`
                  : globalTab === "clients"
                  ? `${clientsMeta.total.toLocaleString()} ${clientsMeta.total === 1 ? "endpoint" : "endpoints"}`
                  : `${flaggedMeta.total.toLocaleString()} flagged`}
              </Badge>
            </div>

            {/* TAB 1: DNS Queries */}
            {globalTab === "queries" && (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-[#F9FAFB] dark:bg-[#151C2C] text-[#6B6B6B] dark:text-[#9CA3AF] border-b border-[#EBEBEB] dark:border-[#1E283D]">
                    <tr>
                      <th className="px-4 py-2.5 font-medium">Timestamp</th>
                      <th className="px-4 py-2.5 font-medium">Client IP</th>
                      <th className="px-4 py-2.5 font-medium">Domain</th>
                      <th className="px-4 py-2.5 font-medium text-center">Type</th>
                      <th className="px-4 py-2.5 font-medium">Verdict</th>
                      <th className="px-4 py-2.5 font-medium">Threat Source</th>
                      <th className="px-4 py-2.5 font-medium text-right">RCode</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70 font-mono">
                    {queriesLoading ? (
                      Array.from({ length: 8 }).map((_, i) => (
                        <tr key={i} className="animate-pulse">
                          <td colSpan={7} className="px-4 py-3">
                            <Skeleton className="h-4 w-full" />
                          </td>
                        </tr>
                      ))
                    ) : queries.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="px-4 py-12 text-center text-[#9C9C9C] font-sans">
                          <p className="text-sm font-medium">No DNS query records observed in this time range.</p>
                          <p className="text-xs text-muted-foreground mt-1">
                            Try expanding the global time range or adjusting search filters.
                          </p>
                        </td>
                      </tr>
                    ) : (
                      queries.map((q) => (
                        <tr key={q.id} className="hover:bg-neutral-50/70 dark:hover:bg-[#161F33]/50 transition-colors">
                          <td className="px-4 py-2.5 text-[#6B6B6B] dark:text-[#9CA3AF] whitespace-nowrap text-[11px]">
                            {q.timestamp}
                          </td>
                          <td className="px-4 py-2.5 text-[#1A1A1A] dark:text-[#F3F4F6] font-medium">
                            <span
                              onClick={() => handleSelectEntity(q.client_ip, "client")}
                              className="hover:text-[#2F6FED] hover:underline cursor-pointer"
                              title="Click to view Client Report"
                            >
                              {q.client_ip}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 text-[#1A1A1A] dark:text-[#F3F4F6] font-medium max-w-[240px] truncate">
                            <span
                              onClick={() => handleSelectEntity(q.domain, "domain")}
                              className="hover:text-[#2F6FED] hover:underline cursor-pointer"
                              title="Click to view Domain Report"
                            >
                              {q.domain}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 text-center text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF]">
                            <span className="px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-semibold text-[10px]">
                              {q.query_type}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 font-sans">
                            <VerdictBadge verdict={q.final_label} />
                          </td>
                          <td className="px-4 py-2.5 text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF] font-sans">
                            {q.ti_source || "—"}
                          </td>
                          <td className="px-4 py-2.5 text-right text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF]">
                            {q.response_code || "NOERROR"}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {/* TAB 2: Top Domains */}
            {globalTab === "domains" && (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-[#F9FAFB] dark:bg-[#151C2C] text-[#6B6B6B] dark:text-[#9CA3AF] border-b border-[#EBEBEB] dark:border-[#1E283D]">
                    <tr>
                      <th className="px-4 py-2.5 font-medium">Domain</th>
                      <th className="px-4 py-2.5 font-medium text-right">Queries</th>
                      <th className="px-4 py-2.5 font-medium text-right">Unique Clients</th>
                      <th className="px-4 py-2.5 font-medium text-right">Malicious</th>
                      <th className="px-4 py-2.5 font-medium">First Seen</th>
                      <th className="px-4 py-2.5 font-medium">Last Seen</th>
                      <th className="px-4 py-2.5 font-medium">Latest Verdict</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70 font-mono">
                    {domainsLoading ? (
                      Array.from({ length: 8 }).map((_, i) => (
                        <tr key={i} className="animate-pulse">
                          <td colSpan={7} className="px-4 py-3">
                            <Skeleton className="h-4 w-full" />
                          </td>
                        </tr>
                      ))
                    ) : domains.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="px-4 py-12 text-center text-[#9C9C9C] font-sans">
                          <p className="text-sm font-medium">No domain aggregations recorded in this time range.</p>
                        </td>
                      </tr>
                    ) : (
                      domains.map((d) => (
                        <tr key={d.domain} className="hover:bg-neutral-50/70 dark:hover:bg-[#161F33]/50 transition-colors">
                          <td className="px-4 py-2.5 text-[#1A1A1A] dark:text-[#F3F4F6] font-medium max-w-[260px] truncate">
                            <span
                              onClick={() => handleSelectEntity(d.domain, "domain")}
                              className="hover:text-[#2F6FED] hover:underline cursor-pointer"
                              title="Click to view Domain Report"
                            >
                              {d.domain}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 text-right font-semibold text-[#1A1A1A] dark:text-[#F3F4F6]">
                            {d.query_count.toLocaleString()}
                          </td>
                          <td className="px-4 py-2.5 text-right text-[#6B6B6B] dark:text-[#9CA3AF]">
                            {d.unique_clients.toLocaleString()}
                          </td>
                          <td className="px-4 py-2.5 text-right">
                            {d.malicious_queries > 0 ? (
                              <span className="text-red-500 font-bold">{d.malicious_queries.toLocaleString()}</span>
                            ) : (
                              <span className="text-[#9C9C9C]">0</span>
                            )}
                          </td>
                          <td className="px-4 py-2.5 text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF]">{d.first_seen || "—"}</td>
                          <td className="px-4 py-2.5 text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF]">{d.last_seen || "—"}</td>
                          <td className="px-4 py-2.5 font-sans">
                            <VerdictBadge verdict={d.latest_verdict} />
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {/* TAB 3: Malicious Domains */}
            {globalTab === "malicious-domains" && (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-[#F9FAFB] dark:bg-[#151C2C] text-[#6B6B6B] dark:text-[#9CA3AF] border-b border-[#EBEBEB] dark:border-[#1E283D]">
                    <tr>
                      <th className="px-4 py-2.5 font-medium">Domain</th>
                      <th className="px-4 py-2.5 font-medium text-right">Queries</th>
                      <th className="px-4 py-2.5 font-medium text-right">Unique Clients</th>
                      <th className="px-4 py-2.5 font-medium text-right">Malicious Events</th>
                      <th className="px-4 py-2.5 font-medium">Latest Verdict</th>
                      <th className="px-4 py-2.5 font-medium">Threat Source</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70 font-mono">
                    {malDomainsLoading ? (
                      Array.from({ length: 8 }).map((_, i) => (
                        <tr key={i} className="animate-pulse">
                          <td colSpan={6} className="px-4 py-3">
                            <Skeleton className="h-4 w-full" />
                          </td>
                        </tr>
                      ))
                    ) : malDomains.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="px-4 py-12 text-center text-[#9C9C9C] font-sans">
                          <p className="text-sm font-medium">Zero malicious domains detected in this time range.</p>
                          <p className="text-xs text-muted-foreground mt-1">
                            All observed DNS activity within this window remained benign.
                          </p>
                        </td>
                      </tr>
                    ) : (
                      malDomains.map((d) => (
                        <tr key={d.domain} className="hover:bg-neutral-50/70 dark:hover:bg-[#161F33]/50 transition-colors">
                          <td className="px-4 py-2.5 text-[#1A1A1A] dark:text-[#F3F4F6] font-medium max-w-[260px] truncate">
                            <span
                              onClick={() => handleSelectEntity(d.domain, "domain")}
                              className="hover:text-red-500 hover:underline cursor-pointer"
                              title="Click to view Domain Report"
                            >
                              {d.domain}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 text-right text-[#1A1A1A] dark:text-[#F3F4F6]">
                            {d.query_count.toLocaleString()}
                          </td>
                          <td className="px-4 py-2.5 text-right text-[#6B6B6B] dark:text-[#9CA3AF]">
                            {d.unique_clients.toLocaleString()}
                          </td>
                          <td className="px-4 py-2.5 text-right text-red-500 font-bold">
                            {d.malicious_queries.toLocaleString()}
                          </td>
                          <td className="px-4 py-2.5 font-sans">
                            <VerdictBadge verdict={d.latest_verdict} />
                          </td>
                          <td className="px-4 py-2.5 text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF] font-sans">
                            {d.ti_source || "internal"}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {/* TAB 4: Client Activity */}
            {globalTab === "clients" && (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-[#F9FAFB] dark:bg-[#151C2C] text-[#6B6B6B] dark:text-[#9CA3AF] border-b border-[#EBEBEB] dark:border-[#1E283D]">
                    <tr>
                      <th className="px-4 py-2.5 font-medium">Client IP</th>
                      <th className="px-4 py-2.5 font-medium text-right">Total Queries</th>
                      <th className="px-4 py-2.5 font-medium text-right">Unique Domains</th>
                      <th className="px-4 py-2.5 font-medium text-right">Malicious Queries</th>
                      <th className="px-4 py-2.5 font-medium">First Seen</th>
                      <th className="px-4 py-2.5 font-medium">Last Seen</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70 font-mono">
                    {clientsLoading ? (
                      Array.from({ length: 8 }).map((_, i) => (
                        <tr key={i} className="animate-pulse">
                          <td colSpan={6} className="px-4 py-3">
                            <Skeleton className="h-4 w-full" />
                          </td>
                        </tr>
                      ))
                    ) : clients.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="px-4 py-12 text-center text-[#9C9C9C] font-sans">
                          <p className="text-sm font-medium">No client activity recorded in this time range.</p>
                        </td>
                      </tr>
                    ) : (
                      clients.map((c) => (
                        <tr key={c.client_ip} className="hover:bg-neutral-50/70 dark:hover:bg-[#161F33]/50 transition-colors">
                          <td className="px-4 py-2.5 text-[#1A1A1A] dark:text-[#F3F4F6] font-medium">
                            <span
                              onClick={() => handleSelectEntity(c.client_ip, "client")}
                              className="hover:text-[#2F6FED] hover:underline cursor-pointer"
                              title="Click to view Client Report"
                            >
                              {c.client_ip}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 text-right font-semibold text-[#1A1A1A] dark:text-[#F3F4F6]">
                            {c.query_count.toLocaleString()}
                          </td>
                          <td className="px-4 py-2.5 text-right text-[#6B6B6B] dark:text-[#9CA3AF]">
                            {c.unique_domains.toLocaleString()}
                          </td>
                          <td className="px-4 py-2.5 text-right">
                            {c.malicious_queries > 0 ? (
                              <span className="text-red-500 font-bold">{c.malicious_queries.toLocaleString()}</span>
                            ) : (
                              <span className="text-[#9C9C9C]">0</span>
                            )}
                          </td>
                          <td className="px-4 py-2.5 text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF]">{c.first_seen || "—"}</td>
                          <td className="px-4 py-2.5 text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF]">{c.last_seen || "—"}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {/* TAB 5: Flagged Queries */}
            {globalTab === "flagged" && (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-[#F9FAFB] dark:bg-[#151C2C] text-[#6B6B6B] dark:text-[#9CA3AF] border-b border-[#EBEBEB] dark:border-[#1E283D]">
                    <tr>
                      <th className="px-4 py-2.5 font-medium">Timestamp</th>
                      <th className="px-4 py-2.5 font-medium">Client IP</th>
                      <th className="px-4 py-2.5 font-medium">Domain</th>
                      <th className="px-4 py-2.5 font-medium text-center">Type</th>
                      <th className="px-4 py-2.5 font-medium">Verdict</th>
                      <th className="px-4 py-2.5 font-medium">Threat Source</th>
                      <th className="px-4 py-2.5 font-medium text-right">RCode</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70 font-mono">
                    {flaggedLoading ? (
                      Array.from({ length: 8 }).map((_, i) => (
                        <tr key={i} className="animate-pulse">
                          <td colSpan={7} className="px-4 py-3">
                            <Skeleton className="h-4 w-full" />
                          </td>
                        </tr>
                      ))
                    ) : flagged.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="px-4 py-12 text-center text-[#9C9C9C] font-sans">
                          <p className="text-sm font-medium">No flagged threat queries in this time range.</p>
                          <p className="text-xs text-muted-foreground mt-1">
                            Zero DNS events were classified as malicious.
                          </p>
                        </td>
                      </tr>
                    ) : (
                      flagged.map((f) => (
                        <tr key={f.id} className="hover:bg-neutral-50/70 dark:hover:bg-[#161F33]/50 transition-colors">
                          <td className="px-4 py-2.5 text-[#6B6B6B] dark:text-[#9CA3AF] whitespace-nowrap text-[11px]">
                            {f.timestamp}
                          </td>
                          <td className="px-4 py-2.5 text-[#1A1A1A] dark:text-[#F3F4F6] font-medium">
                            <span
                              onClick={() => handleSelectEntity(f.client_ip, "client")}
                              className="hover:text-red-500 hover:underline cursor-pointer"
                              title="Click to view Client Report"
                            >
                              {f.client_ip}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 text-[#1A1A1A] dark:text-[#F3F4F6] font-medium max-w-[240px] truncate">
                            <span
                              onClick={() => handleSelectEntity(f.domain, "domain")}
                              className="hover:text-red-500 hover:underline cursor-pointer"
                              title="Click to view Domain Report"
                            >
                              {f.domain}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 text-center text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF]">
                            <span className="px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-semibold text-[10px]">
                              {f.query_type}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 font-sans">
                            <VerdictBadge verdict={f.final_label} />
                          </td>
                          <td className="px-4 py-2.5 text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF] font-sans">
                            {f.ti_source || "internal"}
                          </td>
                          <td className="px-4 py-2.5 text-right text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF]">
                            {f.response_code || "NOERROR"}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {/* Pagination Controls */}
            <div className="p-3 border-t border-[#EBEBEB] dark:border-[#1E283D] flex flex-wrap items-center justify-between gap-3 text-xs text-[#6B6B6B] dark:text-[#9CA3AF] bg-neutral-50/30 dark:bg-[#161F33]/20">
              <div>
                {(() => {
                  const meta =
                    globalTab === "queries"
                      ? queriesMeta
                      : globalTab === "domains"
                      ? domainsMeta
                      : globalTab === "malicious-domains"
                      ? malDomainsMeta
                      : globalTab === "clients"
                      ? clientsMeta
                      : flaggedMeta;

                  if (meta.total === 0) return <span>Showing 0 of 0 records</span>;
                  const startIdx = (meta.page - 1) * meta.pageSize + 1;
                  const endIdx = Math.min(meta.page * meta.pageSize, meta.total);
                  return (
                    <span>
                      Showing <strong className="text-foreground">{startIdx}</strong> to{" "}
                      <strong className="text-foreground">{endIdx}</strong> of{" "}
                      <strong className="text-foreground">{meta.total.toLocaleString()}</strong> records
                    </span>
                  );
                })()}
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={
                    (globalTab === "queries"
                      ? queriesMeta.page
                      : globalTab === "domains"
                      ? domainsMeta.page
                      : globalTab === "malicious-domains"
                      ? malDomainsMeta.page
                      : globalTab === "clients"
                      ? clientsMeta.page
                      : flaggedMeta.page) <= 1
                  }
                  onClick={() => {
                    if (globalTab === "queries") fetchQueries(queriesMeta.page - 1);
                    else if (globalTab === "domains") fetchDomains(domainsMeta.page - 1);
                    else if (globalTab === "malicious-domains") fetchMalDomains(malDomainsMeta.page - 1);
                    else if (globalTab === "clients") fetchClients(clientsMeta.page - 1);
                    else fetchFlagged(flaggedMeta.page - 1);
                  }}
                  className="px-2.5 py-1 bg-white dark:bg-[#121826] border border-[#D9D9D9] dark:border-[#2D3A54] rounded-[6px] hover:border-[#9C9C9C] text-xs transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Previous
                </button>

                <span className="font-mono text-[11px]">
                  Page{" "}
                  {globalTab === "queries"
                    ? queriesMeta.page
                    : globalTab === "domains"
                    ? domainsMeta.page
                    : globalTab === "malicious-domains"
                    ? malDomainsMeta.page
                    : globalTab === "clients"
                    ? clientsMeta.page
                    : flaggedMeta.page}{" "}
                  of{" "}
                  {Math.max(
                    1,
                    globalTab === "queries"
                      ? queriesMeta.pages
                      : globalTab === "domains"
                      ? domainsMeta.pages
                      : globalTab === "malicious-domains"
                      ? malDomainsMeta.pages
                      : globalTab === "clients"
                      ? clientsMeta.pages
                      : flaggedMeta.pages
                  )}
                </span>

                <button
                  type="button"
                  disabled={
                    (globalTab === "queries"
                      ? queriesMeta.page >= queriesMeta.pages
                      : globalTab === "domains"
                      ? domainsMeta.page >= domainsMeta.pages
                      : globalTab === "malicious-domains"
                      ? malDomainsMeta.page >= malDomainsMeta.pages
                      : globalTab === "clients"
                      ? clientsMeta.page >= clientsMeta.pages
                      : flaggedMeta.page >= flaggedMeta.pages)
                  }
                  onClick={() => {
                    if (globalTab === "queries") fetchQueries(queriesMeta.page + 1);
                    else if (globalTab === "domains") fetchDomains(domainsMeta.page + 1);
                    else if (globalTab === "malicious-domains") fetchMalDomains(malDomainsMeta.page + 1);
                    else if (globalTab === "clients") fetchClients(clientsMeta.page + 1);
                    else fetchFlagged(flaggedMeta.page + 1);
                  }}
                  className="px-2.5 py-1 bg-white dark:bg-[#121826] border border-[#D9D9D9] dark:border-[#2D3A54] rounded-[6px] hover:border-[#9C9C9C] text-xs transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ReportsPage;
