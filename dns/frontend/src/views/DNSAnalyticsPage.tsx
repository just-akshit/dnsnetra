"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  ChevronRight,
  Plus,
  Filter,
  Play,
  ChevronDown,
  RefreshCw,
} from "lucide-react";
import apiClient from "@/lib/api-client";
import { DashboardBundleData } from "@/types/api";
import { StatTriptych, SparklinePoint } from "@/components/analytics/StatTriptych";
import { QueriesOverTimeCard, TimeSeriesPoint } from "@/components/analytics/QueriesOverTimeCard";
import { ProcessingTimeCard } from "@/components/analytics/ProcessingTimeCard";
import {
  DNSDetectionBarChart,
  DailyDNSQueryData,
  buildDailyDNSQueryTimeline,
  getDaysCountFromRange,
} from "@/components/charts/DNSDetectionBarChart";
import { useTimeRange } from "@/context/TimeRangeContext";
import { GlobalFilterBar } from "@/components/layout/GlobalFilterBar";
import { GlobalTimeRangePicker } from "@/components/layout/GlobalTimeRangePicker";
import { cn } from "@/lib/utils";

export const DNSAnalyticsPage: React.FC = () => {
  const [data, setData] = useState<DashboardBundleData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [showFilterDropdown, setShowFilterDropdown] = useState(false);
  const { timeRange, registerRefreshHandler } = useTimeRange();

  const fetchTelemetry = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const startIso = timeRange.startDate ? timeRange.startDate.toISOString() : undefined;
      const endIso = timeRange.endDate ? timeRange.endDate.toISOString() : undefined;
      const res = await apiClient.getDashboard({
        start_time: startIso,
        end_time: endIso,
        window: timeRange.isCustom ? undefined : timeRange.preset,
      });
      setData(res.data);
    } catch (err: any) {
      console.error("Failed to load telemetry:", err);
      setError(err.response?.data?.detail || err.message || "Failed to load telemetry");
    } finally {
      setLoading(false);
    }
  }, [timeRange.startDate, timeRange.endDate, timeRange.preset, timeRange.isCustom]);

  useEffect(() => {
    fetchTelemetry();
  }, [fetchTelemetry]);

  useEffect(() => {
    const unregister = registerRefreshHandler(fetchTelemetry);
    return () => unregister();
  }, [registerRefreshHandler, fetchTelemetry]);

  const summary = data?.summary;
  const rawTimeseries = data?.timeseries || [];

  const totalQueries = summary?.total_queries ?? 0;
  const blockedPct = summary?.threats_blocked_pct ?? 0;
  const cacheHitRate = summary ? Math.max(0, 100 - blockedPct) : 0;

  // Compute active days from global time range picker
  const activeDays = useMemo(() => {
    if (timeRange.isCustom && timeRange.startDate && timeRange.endDate) {
      const diffMs = Math.abs(timeRange.endDate.getTime() - timeRange.startDate.getTime());
      const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
      return Math.max(1, Math.min(365, diffDays));
    }
    return getDaysCountFromRange(timeRange.preset);
  }, [timeRange]);

  // Transform live timeseries into line chart points
  const queriesTimeline: TimeSeriesPoint[] = useMemo(() => {
    if (rawTimeseries.length > 0) {
      return rawTimeseries.map((pt) => ({
        time: pt.time_bucket.length > 10 ? pt.time_bucket.substring(11, 16) : pt.time_bucket,
        queries: pt.total_queries,
      }));
    }
    return [];
  }, [rawTimeseries]);

  // Build continuous daily timeline for the active time range
  const dailyQueryTimeline: DailyDNSQueryData[] = useMemo(() => {
    return buildDailyDNSQueryTimeline(rawTimeseries, activeDays);
  }, [rawTimeseries, activeDays]);

  const queriesSparkline: SparklinePoint[] = useMemo(() => {
    return queriesTimeline.map((p) => ({ value: p.queries }));
  }, [queriesTimeline]);

  return (
    <div className="space-y-5 select-none pb-12">
      {/* 1. Breadcrumb Row (44px, 13px text) */}
      <div className="flex items-center justify-between text-[13px] text-[#6B6B6B] dark:text-[#9CA3AF]">
        <nav aria-label="Breadcrumb" className="flex items-center gap-1.5">
          <span className="hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6] transition-colors cursor-pointer">
            Dashboards
          </span>
          <ChevronRight className="w-3.5 h-3.5 text-[#9C9C9C]" />
          <span className="text-[#1A1A1A] dark:text-[#F3F4F6] font-medium">
            DNS Analytics
          </span>
        </nav>
      </div>

      {/* 2. Top Control & Action Bar (32px interactive items) */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#EBEBEB] dark:border-[#1E283D] pb-3">
        {/* Left: Filter dropdown toggle */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setShowFilterDropdown(!showFilterDropdown)}
            className="flex items-center gap-2 px-3 py-1.5 bg-[#FFFFFF] dark:bg-[#121826] border border-[#D9D9D9] dark:border-[#2D3A54] hover:border-[#9C9C9C] text-[#1A1A1A] dark:text-[#F3F4F6] text-[13px] font-medium rounded-[6px] shadow-2xs transition-colors cursor-pointer"
          >
            <Filter className="w-3.5 h-3.5 text-[#6B6B6B] dark:text-[#9CA3AF]" />
            <span>Filter</span>
            <ChevronDown className="w-3 h-3 text-[#9C9C9C]" />
          </button>

          {showFilterDropdown && (
            <div className="absolute left-0 top-full mt-2 z-40 bg-white dark:bg-[#121826] border border-[#EBEBEB] dark:border-[#1E283D] rounded-[8px] shadow-lg p-2.5 min-w-[280px]">
              <GlobalFilterBar />
            </div>
          )}
        </div>

        {/* Right: Actions */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Live Refresh */}
          <button
            type="button"
            onClick={fetchTelemetry}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#FFFFFF] dark:bg-[#121826] border border-[#D9D9D9] dark:border-[#2D3A54] hover:border-[#9C9C9C] text-[#1A1A1A] dark:text-[#F3F4F6] text-[13px] font-medium rounded-[6px] shadow-2xs transition-colors cursor-pointer"
          >
            {loading ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#2F6FED]" />
            ) : (
              <Play className="w-3.5 h-3.5 text-[#6B6B6B] dark:text-[#9CA3AF] fill-current" />
            )}
            <span>Refresh</span>
          </button>

          {/* Time Range Selector */}
          <GlobalTimeRangePicker />
        </div>
      </div>

      {/* 3. Section Title & Description */}
      <div className="space-y-1">
        <h1 className="text-[20px] font-semibold tracking-tight text-[#1A1A1A] dark:text-[#F3F4F6]">
          DNS Analytics & Operations
        </h1>
        <p className="text-[13px] text-[#6B6B6B] dark:text-[#9CA3AF]">
          Live telemetry stream, resolution metrics, and cache performance metrics across all internal resolvers.
        </p>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-4 rounded-md bg-destructive/10 border border-destructive/20 text-xs text-destructive">
          {error}
        </div>
      )}

      {/* 4. Stat Triptych Component */}
      <StatTriptych
        totalQueries={totalQueries}
        queriesSparkline={queriesSparkline}
        avgProcessingTime={0}
        processingSparkline={[]}
        cacheHitRate={cacheHitRate}
        cacheSparkline={[]}
        isEmpty={!loading && totalQueries === 0}
        className="w-full"
      />

      {/* 5. LARGE CONTAINER — EXISTING LINE CHART (Queries Over Time) */}
      <QueriesOverTimeCard
        data={queriesTimeline}
        totalValue={totalQueries}
        isEmpty={!loading && queriesTimeline.length === 0}
        className="w-full"
      />

      {/* 6. SECONDARY ANALYTICS CHARTS GRID (SMALL ADJACENT CONTAINERS) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* SMALL CONTAINER: 3D STACKED DAILY DNS QUERY VOLUME BAR CHART */}
        <DNSDetectionBarChart
          title="DNS Query Volume"
          description="Daily DNS queries over time"
          data={dailyQueryTimeline}
          daysCount={activeDays}
          isLoading={loading}
          aspectRatio="2.2 / 1"
          className="w-full"
        />

        {/* SMALL CONTAINER: Processing Time Card */}
        <ProcessingTimeCard
          data={[]}
          p50Value={0}
          p99Value={0}
          isEmpty={true}
        />
      </div>
    </div>
  );
};

export default DNSAnalyticsPage;
