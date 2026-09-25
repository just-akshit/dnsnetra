"use client";

import React, { useEffect, useState, useCallback, useRef } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  Copy,
  Check,
  RotateCcw,
} from "lucide-react";
import apiClient from "@/lib/api-client";
import { GlobalTimeRangePicker } from "@/components/layout/GlobalTimeRangePicker";
import { useTimeRange } from "@/context/TimeRangeContext";
import { ClientInvestigationData } from "@/types/api";
import { Skeleton } from "@/components/ui/skeleton";
import {
  ClientActivityTable,
  ClientDestinationsTable,
} from "@/components/investigation";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export const ClientDetailPage: React.FC = () => {
  const router = useRouter();
  const params = useParams();
  const rawClientIp = params?.clientIp as string | undefined;
  const clientIp = rawClientIp ? decodeURIComponent(rawClientIp) : undefined;
  const { timeRange, registerRefreshHandler } = useTimeRange();

  const [data, setData] = useState<ClientInvestigationData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Stale-request tracking
  const requestSeq = useRef(0);
  const hasLoadedRef = useRef(false);

  const fetchClientInvestigation = useCallback(
    async (isSilent = false) => {
      if (!clientIp) return;
      const seq = ++requestSeq.current;

      if (!isSilent && !hasLoadedRef.current) {
        setLoading(true);
      }
      setError(null);

      try {
        const startIso =
          timeRange.isCustom && timeRange.startDate
            ? timeRange.startDate.toISOString()
            : undefined;
        const endIso =
          timeRange.isCustom && timeRange.endDate
            ? timeRange.endDate.toISOString()
            : undefined;

        const res = await apiClient.getClientInvestigation(clientIp, {
          start_time: startIso,
          end_time: endIso,
          window: timeRange.isCustom ? undefined : timeRange.preset,
        });

        if (seq !== requestSeq.current) return;
        setData(res.data);
        hasLoadedRef.current = true;
      } catch (err: any) {
        if (seq !== requestSeq.current) return;
        console.error("Error loading client investigation:", err);
        setError(
          err.response?.data?.detail ||
            err.message ||
            "Failed to load client forensics data",
        );
      } finally {
        if (seq === requestSeq.current) {
          setLoading(false);
        }
      }
    },
    [clientIp, timeRange.startDate, timeRange.endDate, timeRange.preset, timeRange.isCustom],
  );

  useEffect(() => {
    fetchClientInvestigation();
  }, [fetchClientInvestigation]);

  useEffect(() => {
    const unregister = registerRefreshHandler(() => fetchClientInvestigation(true));
    return () => unregister();
  }, [registerRefreshHandler, fetchClientInvestigation]);

  const handleCopy = () => {
    if (!clientIp) return;
    navigator.clipboard.writeText(clientIp);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  if (loading && !data) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-5 w-24 rounded" />
        <Skeleton className="h-28 w-full rounded-md" />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Skeleton className="h-64 rounded-md" />
          <Skeleton className="h-64 rounded-md" />
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="space-y-3">
        <Link
          href="/investigate/clients"
          className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Clients</span>
        </Link>
        <div className="p-6 text-center bg-card border border-border/70 rounded-md space-y-2">
          <p className="text-xs text-destructive font-medium">{error}</p>
          <Button
            size="sm"
            onClick={() => fetchClientInvestigation()}
            className="text-xs font-medium cursor-pointer"
          >
            Retry
          </Button>
        </div>
      </div>
    );
  }

  const summary = data?.summary;
  const topDomains = data?.top_domains || [];
  const recentActivity = data?.recent_activity || [];
  const hasThreats =
    (summary?.malicious_queries || 0) > 0 ||
    summary?.risk_status === "THREATS_DETECTED";

  const totalQueries = summary?.total_queries || 0;
  const uniqueDomains = summary?.unique_domains || 0;
  const maliciousQueries = summary?.malicious_queries || 0;
  // Use canonical backend count if present, fallback safely
  const cleanQueries =
    (summary as any)?.benign_queries ??
    (summary as any)?.clean_queries ??
    Math.max(0, totalQueries - maliciousQueries);

  const maliciousDomainsCount = topDomains.filter(
    (d) => d.label === "malicious",
  ).length;
  const reviewNeededDomainsCount = topDomains.filter(
    (d) => d.label === "review_needed",
  ).length;

  return (
    <div className="space-y-6 pb-12">
      {/* Top Navigation */}
      <div className="flex items-center justify-between">
        <Link
          href="/investigate/clients"
          className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Client Endpoints</span>
        </Link>

        <div className="flex items-center gap-2">
          <GlobalTimeRangePicker />
          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchClientInvestigation()}
            disabled={loading}
            className="h-8 gap-1.5 text-xs cursor-pointer"
          >
            <RotateCcw className={cn("size-3.5", loading && "animate-spin")} />
            <span className="hidden sm:inline">Refresh</span>
          </Button>
        </div>
      </div>

      {/* Header Banner */}
      <div className="p-5 bg-card border border-border/70 rounded-lg shadow-sm space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-bold font-mono text-foreground tracking-tight">
            {clientIp}
          </h1>

          <button
            type="button"
            onClick={handleCopy}
            title="Copy client IP"
            className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
          >
            {copied ? (
              <Check className="w-4 h-4 text-emerald-500" />
            ) : (
              <Copy className="w-4 h-4" />
            )}
          </button>

          <span
            className={cn(
              "inline-flex items-center px-2.5 py-0.5 rounded text-xs font-semibold font-mono",
              hasThreats
                ? "bg-red-500/15 text-red-500 border border-red-500/30"
                : "bg-emerald-500/15 text-emerald-500 border border-emerald-500/30",
            )}
          >
            {hasThreats ? "THREATS DETECTED" : "CLEAN ENDPOINT"}
          </span>
        </div>

        {/* 4 Core Summary Metrics */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
          <div className="p-3 rounded-md bg-muted/30 border border-border/40">
            <span className="text-[11px] text-muted-foreground block">
              Total Queries
            </span>
            <span className="text-lg font-bold font-mono text-foreground">
              {totalQueries.toLocaleString()}
            </span>
          </div>
          <div className="p-3 rounded-md bg-muted/30 border border-border/40">
            <span className="text-[11px] text-muted-foreground block">
              Unique Domains
            </span>
            <span className="text-lg font-bold font-mono text-foreground">
              {uniqueDomains.toLocaleString()}
            </span>
          </div>
          <div className="p-3 rounded-md bg-muted/30 border border-border/40">
            <span className="text-[11px] text-muted-foreground block">
              Malicious Queries
            </span>
            <span
              className={cn(
                "text-lg font-bold font-mono",
                maliciousQueries > 0 ? "text-destructive" : "text-foreground",
              )}
            >
              {maliciousQueries.toLocaleString()}
            </span>
          </div>
          <div className="p-3 rounded-md bg-muted/30 border border-border/40">
            <span className="text-[11px] text-muted-foreground block">
              Clean Queries
            </span>
            <span className="text-lg font-bold font-mono text-emerald-600 dark:text-emerald-400">
              {cleanQueries.toLocaleString()}
            </span>
          </div>
        </div>
      </div>

      {/* 2. Threat Summary Section (Immediate Threat Assessment) */}
      <div className="space-y-2.5">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Threat Summary
          </h2>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5">
          <div className="p-3.5 rounded-lg bg-card border border-border/70 shadow-2xs flex items-center justify-between">
            <div>
              <span className="text-xs text-muted-foreground block font-medium">
                Malicious Queries
              </span>
              <span className="text-xl font-bold font-mono text-destructive mt-0.5 block">
                {maliciousQueries.toLocaleString()}
              </span>
            </div>
            <span className="text-[11px] font-medium text-muted-foreground bg-muted/40 px-2 py-0.5 rounded">
              queries
            </span>
          </div>
          <div className="p-3.5 rounded-lg bg-card border border-border/70 shadow-2xs flex items-center justify-between">
            <div>
              <span className="text-xs text-muted-foreground block font-medium">
                Malicious Domains
              </span>
              <span
                className={cn(
                  "text-xl font-bold font-mono mt-0.5 block",
                  maliciousDomainsCount > 0
                    ? "text-destructive"
                    : "text-foreground",
                )}
              >
                {maliciousDomainsCount.toLocaleString()}
              </span>
            </div>
            <span className="text-[11px] font-medium text-muted-foreground bg-muted/40 px-2 py-0.5 rounded">
              destinations
            </span>
          </div>
          <div className="p-3.5 rounded-lg bg-card border border-border/70 shadow-2xs flex items-center justify-between">
            <div>
              <span className="text-xs text-muted-foreground block font-medium">
                Review-needed Domains
              </span>
              <span
                className={cn(
                  "text-xl font-bold font-mono mt-0.5 block",
                  reviewNeededDomainsCount > 0
                    ? "text-amber-500"
                    : "text-foreground",
                )}
              >
                {reviewNeededDomainsCount.toLocaleString()}
              </span>
            </div>
            <span className="text-[11px] font-medium text-muted-foreground bg-muted/40 px-2 py-0.5 rounded">
              in queue
            </span>
          </div>
        </div>
      </div>

      {/* 3. Investigation Area: Top Destinations & Recent Queries */}
      <div className="space-y-2.5">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Investigation
        </h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 items-start">
          <ClientDestinationsTable topDomains={topDomains} />
          <ClientActivityTable recentActivity={recentActivity} />
        </div>
      </div>
    </div>
  );
};

export default ClientDetailPage;
