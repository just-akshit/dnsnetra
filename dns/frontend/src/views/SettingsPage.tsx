"use client";

import React, { useEffect, useState, useCallback } from "react";
import {
  RefreshCw,
} from "lucide-react";
import apiClient from "@/lib/api-client";
import { SystemStatusData } from "@/types/api";
import { DashboardWidget } from "@/components/dashboard/DashboardWidget";
import { MetricWidget } from "@/components/dashboard/MetricWidget";
import { Skeleton } from "@/components/ui/skeleton";

export const SettingsPage: React.FC = () => {
  const [status, setStatus] = useState<SystemStatusData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchStatus = useCallback(async (isManual = false) => {
    if (isManual) setIsRefreshing(true);
    else setLoading(true);
    setError(null);
    try {
      const res = await apiClient.getStatus();
      setStatus(res);
    } catch (err: any) {
      console.error("Error fetching system status:", err);
      setError(err.response?.data?.detail || err.message || "Failed to load system settings");
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  if (loading && !status) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-6 w-32 rounded" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
          <Skeleton className="h-28 rounded-md" />
          <Skeleton className="h-28 rounded-md" />
          <Skeleton className="h-28 rounded-md" />
        </div>
      </div>
    );
  }

  const aggregation = status?.aggregation;
  const lastRun = status?.last_run;
  const dbAvailable = status?.dashboard_db_available;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold tracking-tight text-foreground">
          Settings
        </h1>

        <button
          onClick={() => fetchStatus(true)}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded border border-border bg-background hover:bg-accent text-xs font-medium text-foreground transition-colors cursor-pointer disabled:opacity-50"
        >
          <RefreshCw className={`w-3 h-3 ${isRefreshing ? "animate-spin text-blue-500" : "text-muted-foreground"}`} />
          <span>{isRefreshing ? "Checking..." : "Refresh"}</span>
        </button>
      </div>

      {error && (
        <div className="p-3 rounded-md bg-destructive/10 border border-destructive/20 text-xs text-destructive">
          {error}
        </div>
      )}

      {/* Metric Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5">
        <MetricWidget
          title="Read Model"
          value={dbAvailable ? "Online" : "Offline"}
          trend="dashboard.db"
        />

        <MetricWidget
          title="Watermark"
          value={`#${aggregation?.last_watermark_id ?? 0}`}
          trend="Last event checkpoint"
        />

        <MetricWidget
          title="Pipeline"
          value={lastRun?.status === "success" ? "Healthy" : lastRun?.status || "Healthy"}
          trend={lastRun?.duration_ms ? `${lastRun.duration_ms}ms runtime` : "Incremental"}
        />
      </div>

      {/* Diagnostics Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3.5">
        <DashboardWidget
          title="Aggregation state"
        >
          <div className="space-y-2.5 text-xs">
            <div className="flex items-center justify-between pb-2 border-b border-border/40">
              <span className="text-muted-foreground">Stream</span>
              <span className="font-medium text-foreground">{aggregation?.name || "dashboard"}</span>
            </div>

            <div className="flex items-center justify-between pb-2 border-b border-border/40">
              <span className="text-muted-foreground">Watermark Event ID</span>
              <span className="font-mono text-primary">#{aggregation?.last_watermark_id ?? 0}</span>
            </div>

            <div className="flex items-center justify-between pb-2 border-b border-border/40">
              <span className="text-muted-foreground">Watermark Timestamp</span>
              <span className="font-mono text-foreground text-[11px]">
                {aggregation?.last_watermark_ts ? aggregation.last_watermark_ts.substring(0, 19).replace("T", " ") : "Full scan"}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Last Updated</span>
              <span className="text-muted-foreground font-mono text-[11px]">
                {aggregation?.updated_at ? aggregation.updated_at.substring(0, 19).replace("T", " ") : "-"}
              </span>
            </div>
          </div>
        </DashboardWidget>

        <DashboardWidget
          title="Execution audit"
        >
          <div className="space-y-2.5 text-xs">
            <div className="flex items-center justify-between pb-2 border-b border-border/40">
              <span className="text-muted-foreground">Run ID</span>
              <span className="font-mono text-foreground text-[11px] truncate max-w-[200px]">{lastRun?.run_id || "-"}</span>
            </div>

            <div className="flex items-center justify-between pb-2 border-b border-border/40">
              <span className="text-muted-foreground">Status</span>
              <span className="font-medium text-emerald-500 uppercase">{lastRun?.status || "SUCCESS"}</span>
            </div>

            <div className="flex items-center justify-between pb-2 border-b border-border/40">
              <span className="text-muted-foreground">Duration</span>
              <span className="text-foreground">{lastRun?.duration_ms ? `${lastRun.duration_ms}ms` : "-"}</span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Events Processed</span>
              <span className="text-foreground">{(lastRun?.rows_processed ?? 0).toLocaleString()}</span>
            </div>
          </div>
        </DashboardWidget>
      </div>
    </div>
  );
};

export default SettingsPage;
