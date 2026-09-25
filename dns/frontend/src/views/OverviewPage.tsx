"use client";

import React, { useState, useEffect, useCallback, useMemo, useRef } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import type { ColumnDef } from "@tanstack/react-table";
import {
  Play,
  RefreshCw,
  ArrowRight,
} from "lucide-react";
import apiClient from "@/lib/api-client";
import type {
  DashboardBundleData,
  DomainItem,
  TopDomain,
} from "@/types/api";
import { OverviewKpiCard } from "@/components/dashboard/OverviewKpiCard";
import { DNSQueriesOverTimeChart } from "@/components/charts/DNSQueriesOverTimeChart";
import { VerdictDistributionChart } from "@/components/charts/VerdictDistributionChart";
import {
  DNSDetectionBarChart,
  type DailyDNSQueryData,
  buildDailyDNSQueryTimeline,
} from "@/components/charts/DNSDetectionBarChart";
import {
  DataTable,
  DataTableEmpty,
  createDomainColumn,
  createVerdictColumn,
  createCountColumn,
  createTimestampColumn,
} from "@/components/data-table";
import { useDataTable } from "@/hooks/use-data-table";
import { GlobalTimeRangePicker } from "@/components/layout/GlobalTimeRangePicker";
import { useTimeRange } from "@/context/TimeRangeContext";
import { formatNumber } from "@/lib/format";

// ---------------------------------------------------------------------------
// Normalization Helper: TopDomain -> DomainItem
// ---------------------------------------------------------------------------
function toDomainItem(td: TopDomain): DomainItem {
  const normLabel = (td.label || "benign").toLowerCase();
  return {
    domain: td.domain,
    total_queries: td.query_count,
    query_count: td.query_count,
    unique_clients: 1,
    threat_count: normLabel === "malicious" ? td.query_count : 0,
    malicious_count: normLabel === "malicious" ? td.query_count : 0,
    suspicious_count: 0,
    clean_count: normLabel === "benign" ? td.query_count : 0,
    last_label: td.label || "Benign",
    label: normLabel,
    threat_score: td.threat_score,
    confidence: null,
    last_ti_source: null,
    label_reason: null,
    first_seen: null,
    last_seen: td.last_seen || null,
  };
}

// ---------------------------------------------------------------------------
// Reusable Dashboard Table Card using existing DataTable component
// ---------------------------------------------------------------------------
interface OverviewDomainTableProps {
  title: string;
  subtitle?: string;
  viewAllHref: string;
  data: DomainItem[];
  loading: boolean;
  error: string | null;
  tableId: string;
  emptyTitle: string;
  emptyDescription: string;
}

const OverviewDomainTable: React.FC<OverviewDomainTableProps> = ({
  title,
  subtitle,
  viewAllHref,
  data,
  loading,
  error,
  tableId,
  emptyTitle,
  emptyDescription,
}) => {
  const router = useRouter();

  const columns = useMemo<ColumnDef<DomainItem>[]>(
    () => [
      createDomainColumn<DomainItem>({
        accessorKey: "domain",
        id: "domain",
        title: "Domain",
        linkToInvestigation: true,
        required: true,
        defaultVisible: true,
      }),
      createVerdictColumn<DomainItem>({
        accessorKey: "label",
        id: "label",
        title: "Verdict",
        align: "left",
      }),
      createCountColumn<DomainItem>({
        accessorKey: "query_count",
        id: "query_count",
        title: "Queries",
        align: "right",
      }),
      createTimestampColumn<DomainItem>({
        accessorKey: "last_seen",
        id: "last_seen",
        title: "Last Seen",
        align: "right",
      }),
    ],
    []
  );

  const { table } = useDataTable<DomainItem>({
    data,
    columns,
    pageCount: 1,
    tableId,
    enableUrlSync: false,
    clearOnDefault: true,
    manualPagination: false,
    manualSorting: false,
    manualFiltering: false,
    defaultDensity: "compact",
  });

  return (
    <div className="flex flex-col justify-between rounded-[12px] p-4 sm:p-5 bg-white dark:bg-[#121826] border border-[#EBEBEB] dark:border-[#1E283D] shadow-2xs">
      <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#EBEBEB] dark:border-[#1E283D]">
        <div>
          <h2 className="text-[15px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em]">
            {title}
          </h2>
          {subtitle && (
            <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mt-0.5">
              {subtitle}
            </p>
          )}
        </div>
        <Link
          href={viewAllHref}
          className="text-[12px] font-medium text-[#2F6FED] hover:underline flex items-center gap-1 group cursor-pointer"
        >
          <span>View all</span>
          <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
        </Link>
      </div>

      <div className="flex-1 min-w-0">
        <DataTable<DomainItem>
          table={table}
          loading={loading}
          error={error}
          withPagination={false}
          density="compact"
          onRowClick={(row) => {
            router.push(`/investigate/domains/${encodeURIComponent(row.original.domain)}`);
          }}
          emptyState={
            <DataTableEmpty
              title={emptyTitle}
              description={emptyDescription}
            />
          }
        />
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Main Overview Page Component
// ---------------------------------------------------------------------------
export const OverviewPage: React.FC = () => {
  const router = useRouter();
  const { isLive, range, timeRange, registerRefreshHandler } = useTimeRange();

  // State Management
  const [dashboardBundle, setDashboardBundle] = useState<DashboardBundleData | null>(null);
  const [totalClientsCount, setTotalClientsCount] = useState<number | null>(null);
  const [topDomains, setTopDomains] = useState<DomainItem[]>([]);
  const [benignDomains, setBenignDomains] = useState<DomainItem[]>([]);
  const [maliciousDomains, setMaliciousDomains] = useState<DomainItem[]>([]);
  const [maliciousDomainsCount, setMaliciousDomainsCount] = useState<number | null>(null);
  const [reviewNeededDomains, setReviewNeededDomains] = useState<DomainItem[]>([]);
  const [reviewNeededCount, setReviewNeededCount] = useState<number | null>(null);
  const [unknownDomainsCount, setUnknownDomainsCount] = useState<number | null>(null);
  const [timeseries7d, setTimeseries7d] = useState<any[]>([]);

  const [initialLoading, setInitialLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Stale-request tracking to discard out-of-order responses during rapid time range switches
  const requestSeq = useRef(0);

  // Core Data Fetcher with silent background refreshes
  const fetchDashboardData = useCallback(
    async (isSilent = false) => {
      const seq = ++requestSeq.current;
      try {
        if (!isSilent) {
          setInitialLoading(true);
        }
        setIsRefreshing(true);
        setError(null);

        const startIso = timeRange.startDate ? timeRange.startDate.toISOString() : undefined;
        const endIso = timeRange.endDate ? timeRange.endDate.toISOString() : undefined;
        const windowParam = timeRange.isCustom ? undefined : timeRange.preset;

        const is7d = windowParam === "7d";
        const dashboard7dPromise = is7d
          ? Promise.resolve(null)
          : apiClient.getDashboard({ window: "7d" });

        const [
          dashboardRes,
          dashboard7dRes,
          clientsRes,
          topDomainsRes,
          benignRes,
          maliciousRes,
          reviewNeededRes,
          unknownRes,
        ] = await Promise.all([
          apiClient.getDashboard({
            window: windowParam,
            start_time: startIso,
            end_time: endIso,
          }),
          dashboard7dPromise,
          apiClient.getClients({ page: 1, pageSize: 1 }),
          apiClient.getDomains({
            page: 1,
            pageSize: 10,
            // Strictly NO label filter: all-status top domains by query count
            window: windowParam,
            start_time: startIso,
            end_time: endIso,
          }),
          apiClient.getDomains({
            page: 1,
            pageSize: 10,
            label: "benign",
            window: windowParam,
            start_time: startIso,
            end_time: endIso,
          }),
          apiClient.getDomains({
            page: 1,
            pageSize: 10,
            label: "malicious",
            window: windowParam,
            start_time: startIso,
            end_time: endIso,
          }),
          apiClient.getDomains({
            page: 1,
            pageSize: 10,
            label: "review_needed",
            window: windowParam,
            start_time: startIso,
            end_time: endIso,
          }),
          apiClient.getDomains({
            page: 1,
            pageSize: 1,
            label: "unknown",
            window: windowParam,
            start_time: startIso,
            end_time: endIso,
          }),
        ]);

        if (seq !== requestSeq.current) return;

        if (dashboardRes?.data) {
          setDashboardBundle(dashboardRes.data);
        }
        const raw7d = is7d
          ? dashboardRes?.data?.timeseries
          : dashboard7dRes?.data?.timeseries;
        if (raw7d) {
          setTimeseries7d(raw7d);
        }
        if (clientsRes?.meta?.total !== undefined) {
          setTotalClientsCount(clientsRes.meta.total);
        }
        if (topDomainsRes?.data) {
          setTopDomains(topDomainsRes.data.slice(0, 10));
        }
        if (benignRes?.data) {
          setBenignDomains(benignRes.data.slice(0, 10));
        }
        if (maliciousRes?.data) {
          setMaliciousDomains(maliciousRes.data.slice(0, 10));
          setMaliciousDomainsCount(maliciousRes.meta.total);
        }
        if (reviewNeededRes?.data) {
          setReviewNeededDomains(reviewNeededRes.data.slice(0, 10));
          setReviewNeededCount(reviewNeededRes.meta.total);
        }
        if (unknownRes?.meta?.total !== undefined) {
          setUnknownDomainsCount(unknownRes.meta.total);
        }
      } catch (err: any) {
        if (seq !== requestSeq.current) return;
        console.error("Failed to load dashboard data:", err);
        setError(err?.message || "Failed to load dashboard data");
      } finally {
        if (seq === requestSeq.current) {
          setInitialLoading(false);
          setIsRefreshing(false);
        }
      }
    },
    [timeRange.startDate, timeRange.endDate, timeRange.preset, timeRange.isCustom]
  );

  // Initial load and time window change
  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  // Register with TimeRangeContext refresh handler for manual button clicks or live triggers
  useEffect(() => {
    const unregister = registerRefreshHandler(async () => {
      await fetchDashboardData(true);
    });
    return () => unregister();
  }, [registerRefreshHandler, fetchDashboardData]);

  // Derived Summary Values
  const summary = dashboardBundle?.summary;

  const totalQueriesVal = summary?.total_queries !== undefined ? formatNumber(summary.total_queries) : "0";
  const totalClientsVal = totalClientsCount !== null ? formatNumber(totalClientsCount) : "—";
  const uniqueDomainsVal = summary?.unique_domains !== undefined ? formatNumber(summary.unique_domains) : "0";
  const uniqueClientsVal = summary?.unique_clients !== undefined ? formatNumber(summary.unique_clients) : "0";
  const maliciousDomainsVal = maliciousDomainsCount !== null ? formatNumber(maliciousDomainsCount) : "0";
  const unknownDomainsVal = unknownDomainsCount !== null ? formatNumber(unknownDomainsCount) : "0";

  // Exactly Six KPI Cards
  const kpis = useMemo(
    () => [
      {
        id: "kpi-total-queries",
        title: "Total Queries",
        value: totalQueriesVal,
        route: `/analytics/dns?metric=queries&timeRange=${range}`,
      },
      {
        id: "kpi-total-clients",
        title: "Total Clients",
        value: totalClientsVal,
        route: `/investigate/clients`,
      },
      {
        id: "kpi-unique-domains",
        title: "Unique Domains",
        value: uniqueDomainsVal,
        route: `/investigate/domains?timeRange=${range}`,
      },
      {
        id: "kpi-unique-clients",
        title: "Unique Clients",
        value: uniqueClientsVal,
        route: `/investigate/clients?timeRange=${range}`,
      },
      {
        id: "kpi-malicious-domains",
        title: "Malicious Domains",
        value: maliciousDomainsVal,
        route: `/investigate/domains?label=malicious&timeRange=${range}`,
      },
      {
        id: "kpi-unknown-domains",
        title: "Unknown Domains",
        value: unknownDomainsVal,
        route: `/investigate/domains?label=unknown&timeRange=${range}`,
      },
    ],
    [
      totalQueriesVal,
      totalClientsVal,
      uniqueDomainsVal,
      uniqueClientsVal,
      maliciousDomainsVal,
      unknownDomainsVal,
      range,
    ]
  );

  // Top Domains (All-status ranking by query volume without label filter, max 10 rows)
  const topDomainItems: DomainItem[] = useMemo(() => {
    if (topDomains.length > 0) return topDomains.slice(0, 10);
    if (!dashboardBundle?.top_domains) return [];
    return dashboardBundle.top_domains.slice(0, 10).map(toDomainItem);
  }, [topDomains, dashboardBundle?.top_domains]);

  // 7-day daily timeline specifically for the 3D stacked bar chart
  const daily7dData: DailyDNSQueryData[] = useMemo(() => {
    return buildDailyDNSQueryTimeline(timeseries7d, 7);
  }, [timeseries7d]);

  // Verdict Distribution Counts for Donut Chart
  const totalQueriesCount = summary?.total_queries || 0;
  const maliciousQueriesCount = summary?.total_threats || 0;
  const reviewNeededQueriesCount = reviewNeededCount || 0;
  const unknownQueriesCount = unknownDomainsCount || 0;
  const cleanQueriesCount = Math.max(
    0,
    totalQueriesCount - maliciousQueriesCount - reviewNeededQueriesCount - unknownQueriesCount
  );

  return (
    <div className="space-y-5 pb-12">
      {/* ================================================================== */}
      {/* 1. DASHBOARD HEADER & BREADCRUMBS                                  */}
      {/* ================================================================== */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          {/* Breadcrumb representing Overview as Home destination */}
          <nav
            aria-label="Breadcrumb"
            className="flex items-center gap-1.5 text-[12px] text-muted-foreground mb-1"
          >
            <Link
              href="/overview"
              className="text-foreground font-medium hover:underline transition-colors cursor-pointer"
            >
              Overview / Security Telemetry
            </Link>
          </nav>

          {/* Main Heading & Semantic Status Indicator */}
          <div className="flex items-center gap-3">
            <h1 className="text-[22px] sm:text-[24px] font-bold tracking-tight text-foreground">
              DNS Threat Detection
            </h1>
            <span className="flex items-center gap-1.5 text-[11px] font-medium text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 dark:bg-emerald-500/20 px-2 py-0.5 rounded-full border border-emerald-500/30">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              {isLive ? "Live Streaming" : "Operational"}
            </span>
          </div>
        </div>

        {/* Header Right Actions */}
        <div className="flex flex-wrap items-center gap-2 self-stretch sm:self-auto justify-end">
          {/* Refresh Action */}
          <button
            type="button"
            onClick={() => fetchDashboardData(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-card border border-border/80 hover:bg-accent text-foreground text-[13px] font-medium rounded-md shadow-xs transition-colors cursor-pointer"
          >
            {isRefreshing ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-primary" />
            ) : (
              <Play className="w-3.5 h-3.5 text-muted-foreground fill-current" />
            )}
            <span>Refresh</span>
          </button>

          {/* Time Range Selector */}
          <GlobalTimeRangePicker />
        </div>
      </div>

      {/* ================================================================== */}
      {/* 2. EXACTLY SIX KPI CARDS                                           */}
      {/* ================================================================== */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3 sm:gap-3.5">
        {kpis.map((kpi) => (
          <OverviewKpiCard
            key={kpi.id}
            title={kpi.title}
            value={kpi.value}
            onClick={() => router.push(kpi.route)}
            ariaLabel={`View ${kpi.title} detailed analytics`}
          />
        ))}
      </div>

      {/* ================================================================== */}
      {/* 3. WORKING REAL-DATA CHART: QUERIES OVER TIME                      */}
      {/* ================================================================== */}
      <div className="rounded-xl p-5 bg-card border border-border/80 dark:border-white/[0.08] shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h2 className="text-[16px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em]">
                Queries Over Time
              </h2>
              <span className="flex items-center gap-1 text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                Live Telemetry
              </span>
            </div>
            <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mt-0.5">
              DNS query and threat activity aggregated over the selected window
            </p>
          </div>

          {/* Chart Legends */}
          <div className="flex items-center gap-4 text-[12px]">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#2F6FED]" />
              <span className="text-[#1A1A1A] dark:text-[#F3F4F6] font-medium">Total</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#10B981]" />
              <span className="text-[#1A1A1A] dark:text-[#F3F4F6] font-medium">Clean</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#EF4444]" />
              <span className="text-[#1A1A1A] dark:text-[#F3F4F6] font-medium">Malicious</span>
            </div>
          </div>
        </div>

        <DNSQueriesOverTimeChart
          timeseries={dashboardBundle?.timeseries}
          isLoading={initialLoading}
          height={360}
          preset={range}
        />
      </div>

      {/* ================================================================== */}
      {/* 4. VISUAL ROW: 3D STACKED BAR (7-DAY) & VERDICT DISTRIBUTION       */}
      {/* ================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 items-stretch">
        {/* A. 3D Stacked Bar Chart: DNS Queries — Last 7 Days */}
        <div className="flex flex-col justify-between rounded-[12px] p-5 bg-white dark:bg-[#121826] border border-[#EBEBEB] dark:border-[#1E283D] shadow-2xs">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between pb-3 mb-3 border-b border-[#EBEBEB] dark:border-[#1E283D] gap-2">
            <div>
              <h2 className="text-[15px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em]">
                DNS Queries — Last 7 Days
              </h2>
              <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mt-0.5">
                Daily query verdict breakdown
              </p>
            </div>
            {/* Legend for the 4 stacked categories */}
            <div className="flex flex-wrap items-center gap-3 text-xs">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#10B981]" />
                <span className="text-[#6B6B6B] dark:text-[#9CA3AF] font-medium">Clean</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#EF4444]" />
                <span className="text-[#6B6B6B] dark:text-[#9CA3AF] font-medium">Malicious</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#F59E0B]" />
                <span className="text-[#6B6B6B] dark:text-[#9CA3AF] font-medium">Review Needed</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-[#64748B]" />
                <span className="text-[#6B6B6B] dark:text-[#9CA3AF] font-medium">Unknown</span>
              </div>
            </div>
          </div>

          <div className="flex-1 flex flex-col justify-center min-h-[300px]">
            <DNSDetectionBarChart
              title=""
              description=""
              data={daily7dData}
              daysCount={7}
              isLoading={initialLoading}
              showSummaryBadges={false}
              aspectRatio="1.9 / 1"
              className="border-0 bg-transparent p-0 shadow-none dark:bg-transparent"
            />
          </div>
        </div>

        {/* B. Pie/Donut Chart: Verdict Distribution */}
        <div className="flex flex-col justify-between rounded-[12px] p-5 bg-white dark:bg-[#121826] border border-[#EBEBEB] dark:border-[#1E283D] shadow-2xs">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-[#EBEBEB] dark:border-[#1E283D]">
            <div>
              <h2 className="text-[15px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em]">
                Verdict Distribution
              </h2>
              <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mt-0.5">
                DNS query classifications across observed traffic
              </p>
            </div>
          </div>

          <div className="flex-1 flex flex-col justify-center min-h-[300px]">
            <VerdictDistributionChart
              clean={cleanQueriesCount}
              malicious={maliciousQueriesCount}
              reviewNeeded={reviewNeededQueriesCount}
              unknown={unknownQueriesCount}
              loading={initialLoading}
            />
          </div>
        </div>
      </div>

      {/* ================================================================== */}
      {/* 5. FOUR CORE DASHBOARD TABLES (STRICTLY MAXIMUM 10 ROWS EACH)      */}
      {/* ================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Table 1: Top Domains (All-Status, Query Volume DESC) */}
        <OverviewDomainTable
          title="Top Domains"
          subtitle="Most frequently queried domains"
          viewAllHref="/investigate/domains"
          data={topDomainItems}
          loading={initialLoading}
          error={error}
          tableId="overview-top-domains"
          emptyTitle="No domains observed"
          emptyDescription="No domain query activity recorded for this period."
        />

        {/* Table 2: Top Whitelisted Domains (Canonical Benign) */}
        <OverviewDomainTable
          title="Top Whitelisted Domains"
          subtitle="Highest-volume benign domains"
          viewAllHref="/investigate/domains?label=benign"
          data={benignDomains}
          loading={initialLoading}
          error={error}
          tableId="overview-top-whitelisted"
          emptyTitle="No whitelisted domains"
          emptyDescription="No benign domain activity recorded for this period."
        />

        {/* Table 3: Top Malicious Domains (Canonical Malicious) */}
        <OverviewDomainTable
          title="Top Malicious Domains"
          subtitle="Highest-volume confirmed threat domains"
          viewAllHref="/investigate/domains?label=malicious"
          data={maliciousDomains}
          loading={initialLoading}
          error={error}
          tableId="overview-top-malicious"
          emptyTitle="No malicious domains"
          emptyDescription="No malicious domain detections recorded for this period."
        />

        {/* Table 4: Daily Review (Canonical Review Needed, Analyst Queue) */}
        <OverviewDomainTable
          title="Daily Review"
          subtitle="Domains requiring analyst review"
          viewAllHref="/investigate/domains?label=review_needed"
          data={reviewNeededDomains}
          loading={initialLoading}
          error={error}
          tableId="overview-daily-review"
          emptyTitle="No domains to review"
          emptyDescription="No unknown domains currently queued for analyst review."
        />
      </div>
    </div>
  );
};

export default OverviewPage;
