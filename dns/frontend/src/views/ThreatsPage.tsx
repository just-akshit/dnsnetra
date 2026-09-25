"use client";

import React, { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Flame,
  Globe,
  Radio,
  ExternalLink,
  ChevronRight,
  TrendingUp,
} from "lucide-react";
import apiClient from "@/lib/api-client";
import { DashboardBundleData, RecentFlaggedDomain } from "@/types/api";
import { VerdictBadge } from "@/components/security/VerdictBadge";
import { Skeleton } from "@/components/ui/skeleton";
import { TopThreatCategoriesCard, ThreatCategoryItem } from "@/components/dashboard/TopThreatCategoriesCard";
import { QueryDistributionCard, QueryDistributionItem } from "@/components/dashboard/QueryDistributionCard";
import { ThreatPostureCard } from "@/components/dashboard/ThreatPostureCard";
import { formatNumber, formatFullTimestamp } from "@/lib/format";

export const ThreatsPage: React.FC = () => {
  const router = useRouter();
  const [data, setData] = useState<DashboardBundleData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchThreatData = useCallback(async (isManual = false) => {
    if (isManual) setIsRefreshing(true);
    else setLoading(true);
    setError(null);
    try {
      const res = await apiClient.getDashboard();
      setData(res.data);
    } catch (err: any) {
      console.error("Error fetching threats intelligence:", err);
      setError(err.response?.data?.detail || err.message || "Failed to load threats intelligence");
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchThreatData();
  }, [fetchThreatData]);

  const summary = data?.summary;
  const recentFlagged = data?.recent_flagged || [];
  const rawCategories = data?.categories || [];

  // Transform threat categories for chart from real backend telemetry
  const threatCategories: ThreatCategoryItem[] = useMemo(() => {
    if (rawCategories.length > 0) {
      const colors = ["#EF4444", "#F97316", "#DC2626", "#8B5CF6", "#F59E0B", "#3B82F6"];
      return rawCategories.map((cat, idx) => ({
        category: cat.category.split(" ")[0] || cat.category,
        count: cat.count,
        color: colors[idx % colors.length],
        pct: `${cat.pct.toFixed(1)}%`,
      }));
    }
    return [];
  }, [rawCategories]);

  // Transform query distribution from real summary metrics
  const queryDistribution: QueryDistributionItem[] = useMemo(() => {
    const total = summary?.total_queries || 0;
    const threats = summary?.total_threats || 0;
    const clean = Math.max(0, total - threats);

    if (total === 0) return [];

    return [
      { name: "Clean Traffic", value: clean, color: "#10B981", pct: `${((clean / total) * 100).toFixed(1)}%` },
      { name: "Threat Queries", value: threats, color: "#EF4444", pct: `${((threats / total) * 100).toFixed(1)}%` },
    ];
  }, [summary]);

  return (
    <div className="space-y-6 pb-12">
      {/* 1. Header Row */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-foreground">
              Threat Analytics & Intelligence
            </h1>
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-500/15 text-red-500 border border-red-500/20">
              {formatNumber(summary?.total_threats ?? 0)} Threats Flagged
            </span>
          </div>
          <p className="text-xs text-muted-foreground">
            Correlated threat classifications, malicious domain distributions, and automated protection outcomes.
          </p>
        </div>

        <button
          onClick={() => fetchThreatData(true)}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-border/80 bg-background hover:bg-accent text-xs font-medium text-foreground transition-colors cursor-pointer disabled:opacity-50 shadow-xs"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin text-blue-500" : "text-muted-foreground"}`} />
          <span>{isRefreshing ? "Refreshing..." : "Refresh Feed"}</span>
        </button>
      </div>

      {/* 2. Top Analytics Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="p-4 rounded-lg bg-card border border-border/70 shadow-xs space-y-1">
          <span className="text-xs text-muted-foreground font-medium">Total Flagged Threats</span>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-destructive tabular-nums">
              {formatNumber(summary?.total_threats ?? 0)}
            </span>
            <span className="text-xs text-destructive font-medium flex items-center gap-0.5">
              <ShieldAlert className="w-3.5 h-3.5" /> High
            </span>
          </div>
          <span className="text-[11px] text-muted-foreground">In active evaluation window</span>
        </div>

        <div className="p-4 rounded-lg bg-card border border-border/70 shadow-xs space-y-1">
          <span className="text-xs text-muted-foreground font-medium">Threat Traffic Ratio</span>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-destructive tabular-nums">
              {(summary?.threats_blocked_pct ?? 0).toFixed(1)}%
            </span>
            <span className="text-xs text-destructive font-medium flex items-center gap-0.5">
              <Flame className="w-3.5 h-3.5" /> Blocked
            </span>
          </div>
          <span className="text-[11px] text-muted-foreground">Automated sinkhole & drop rate</span>
        </div>

        <div className="p-4 rounded-lg bg-card border border-border/70 shadow-xs space-y-1">
          <span className="text-xs text-muted-foreground font-medium">Unique Malicious Domains</span>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-foreground tabular-nums">
              {formatNumber(rawCategories.reduce((acc, c) => acc + c.count, 0) || (summary?.total_threats ?? 0))}
            </span>
            <span className="text-xs text-muted-foreground font-mono">TI feeds</span>
          </div>
          <span className="text-[11px] text-muted-foreground">URLhaus, ThreatFox & OTX</span>
        </div>

        <div className="p-4 rounded-lg bg-card border border-border/70 shadow-xs space-y-1">
          <span className="text-xs text-muted-foreground font-medium">Affected Internal Hosts</span>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-amber-500 tabular-nums">
              {data?.top_clients?.filter((c) => (c.malicious_query_count ?? 0) > 0).length ?? 0}
            </span>
            <span className="text-xs text-amber-500 font-medium">Under Monitoring</span>
          </div>
          <span className="text-[11px] text-muted-foreground">Hosts making C2 / DGA queries</span>
        </div>
      </div>

      {/* 3. Threat Distribution & Category Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <TopThreatCategoriesCard data={threatCategories} />
        <QueryDistributionCard data={queryDistribution} />
      </div>

      {/* 4. Live Flagged Threats Feed Table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-foreground tracking-tight">
            Real-Time Threat Detection Log
          </h2>
          <span className="text-xs text-muted-foreground font-mono">
            {recentFlagged.length} recent detections
          </span>
        </div>

        <div className="bg-card border border-border/70 rounded-lg shadow-xs overflow-hidden">
          {loading ? (
            <div className="p-4 space-y-2">
              {[...Array(5)].map((_, i) => (
                <Skeleton key={i} className="h-8 w-full rounded" />
              ))}
            </div>
          ) : error ? (
            <div className="p-6 text-center text-xs text-destructive">{error}</div>
          ) : recentFlagged.length === 0 ? (
            <div className="p-6 text-center text-xs text-muted-foreground">No recent threats recorded.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-muted/40 text-muted-foreground border-b border-border/50">
                  <tr>
                    <th className="px-4 py-2.5 font-medium">Domain</th>
                    <th className="px-4 py-2.5 font-medium text-right">Verdict</th>
                    <th className="px-4 py-2.5 font-medium">Detection Signature / Reason</th>
                    <th className="px-4 py-2.5 font-medium">TI Source</th>
                    <th className="px-4 py-2.5 font-medium text-right">Timestamp</th>
                    <th className="px-4 py-2.5 font-medium text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/30">
                  {recentFlagged.map((threat, idx) => (
                    <tr
                      key={idx}
                      onClick={() => router.push(`/investigate/domains/${encodeURIComponent(threat.domain)}`)}
                      className="hover:bg-muted/30 cursor-pointer transition-colors"
                    >
                      <td className="px-4 py-2.5 font-mono font-medium text-destructive truncate max-w-[200px]">
                        {threat.domain}
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <VerdictBadge verdict={threat.label} />
                      </td>
                      <td className="px-4 py-2.5 text-foreground truncate max-w-[280px]">
                        {threat.label_reason || "Direct heuristic match"}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-muted-foreground text-[11px]">
                        {threat.ti_source || "URLhaus"}
                      </td>
                      <td className="px-4 py-2.5 text-right text-muted-foreground text-[11px] font-mono whitespace-nowrap">
                        {formatFullTimestamp(threat.flagged_at)}
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            router.push(`/investigate/domains/${encodeURIComponent(threat.domain)}`);
                          }}
                          className="inline-flex items-center gap-1 text-[11px] text-blue-500 hover:text-blue-600 font-medium cursor-pointer"
                        >
                          <span>Investigate</span>
                          <ChevronRight className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ThreatsPage;
