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

export const SystemPage: React.FC = () => {
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
      setError(err.response?.data?.detail || err.message || "Failed to load system engine status");
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
      <div className="space-y-6">
        <div className="h-6 w-48 bg-muted rounded animate-pulse" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Skeleton className="h-48 rounded-xl" />
          <Skeleton className="h-48 rounded-xl" />
          <Skeleton className="h-48 rounded-xl" />
        </div>
      </div>
    );
  }

  const aggregation = status?.aggregation;
  const lastRun = status?.last_run;
  const dbAvailable = status?.dashboard_db_available;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground font-sans">
            System & Engine Health
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Real-time pipeline state, SQLite read model status, and incremental aggregation checkpoints.
          </p>
        </div>

        <button
          onClick={() => fetchStatus(true)}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-border bg-secondary hover:bg-accent text-xs font-medium text-foreground transition-all cursor-pointer disabled:opacity-50 self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin text-blue-500" : "text-muted-foreground"}`} />
          <span>{isRefreshing ? "Checking..." : "Refresh Engine Status"}</span>
        </button>
      </div>

      {/* Metric Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <MetricWidget
          title="SQLite Read Model"
          value={dbAvailable ? "ONLINE" : "UNAVAILABLE"}
          trend="dashboard.db"
          isThreat={!dbAvailable}
        />

        <MetricWidget
          title="Watermark Checkpoint"
          value={`#${aggregation?.last_watermark_id ?? 0}`}
          trend="Last processed event ID"
        />

        <MetricWidget
          title="Aggregator Engine"
          value={lastRun?.status === "success" ? "SYNCED" : lastRun?.status || "HEALTHY"}
          trend={lastRun?.duration_ms ? `${lastRun.duration_ms}ms runtime` : "Incremental mode"}
        />
      </div>

      {/* Detailed System Diagnostics Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Aggregation Watermark State */}
        <DashboardWidget
          title="Watermark & Checkpoint State"
          description="Incremental pipeline synchronization position"
        >
          <div className="space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between pb-2 border-b border-border/40">
              <span className="text-muted-foreground">Aggregation Stream:</span>
              <span className="font-semibold text-foreground">{aggregation?.name || "dashboard"}</span>
            </div>

            <div className="flex items-center justify-between pb-2 border-b border-border/40">
              <span className="text-muted-foreground">Watermark Event ID:</span>
              <span className="font-semibold text-primary">#{aggregation?.last_watermark_id ?? 0}</span>
            </div>

            <div className="flex items-center justify-between pb-2 border-b border-border/40">
              <span className="text-muted-foreground">Watermark Timestamp:</span>
              <span className="text-foreground">
                {aggregation?.last_watermark_ts ? aggregation.last_watermark_ts.substring(0, 19).replace("T", " ") : "Genesis (Full Scan)"}
              </span>
            </div>

            <div className="flex items-center justify-between pt-1">
              <span className="text-muted-foreground">Checkpoint Last Updated:</span>
              <span className="text-muted-foreground">
                {aggregation?.updated_at ? aggregation.updated_at.substring(0, 19).replace("T", " ") : "-"}
              </span>
            </div>
          </div>
        </DashboardWidget>

        {/* Last Run Audit Details */}
        <DashboardWidget
          title="Last Execution Run Audit"
          description="Performance telemetry for recent aggregation cycle"
        >
          <div className="space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between pb-2 border-b border-border/40">
              <span className="text-muted-foreground">Run ID:</span>
              <span className="text-foreground truncate max-w-[200px]">{lastRun?.run_id || "-"}</span>
            </div>

            <div className="flex items-center justify-between pb-2 border-b border-border/40">
              <span className="text-muted-foreground">Status:</span>
              <span className="font-bold text-emerald-500 uppercase">{lastRun?.status || "SUCCESS"}</span>
            </div>

            <div className="flex items-center justify-between pb-2 border-b border-border/40">
              <span className="text-muted-foreground">Duration:</span>
              <span className="text-foreground">{lastRun?.duration_ms ? `${lastRun.duration_ms}ms` : "-"}</span>
            </div>

            <div className="flex items-center justify-between pb-2 border-b border-border/40">
              <span className="text-muted-foreground">Events Processed:</span>
              <span className="text-foreground">{(lastRun?.rows_processed ?? 0).toLocaleString()} events</span>
            </div>

            <div className="flex items-center justify-between pt-1">
              <span className="text-muted-foreground">Batches Completed:</span>
              <span className="text-foreground">{lastRun?.batches_processed ?? 0} batches</span>
            </div>
          </div>
        </DashboardWidget>
      </div>
    </div>
  );
};

export default SystemPage;
