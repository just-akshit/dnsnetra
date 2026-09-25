import React, { useEffect, useState, useCallback } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import apiClient from "@/lib/api-client";
import { DomainAnalyticsData } from "@/types/api";
import { MetricWidget } from "@/components/dashboard/MetricWidget";
import { ChartWidget } from "@/components/dashboard/ChartWidget";
import { cn } from "@/lib/utils";

const PRESET_OPTIONS = [
  { label: "5m", value: "5m" },
  { label: "15m", value: "15m" },
  { label: "30m", value: "30m" },
  { label: "1h", value: "60m" },
];

export const AnalyticsPage: React.FC = () => {
  const [selectedPreset, setSelectedPreset] = useState<string>("15m");
  const [data, setData] = useState<DomainAnalyticsData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAnalytics = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.getDomainAnalytics({ window: selectedPreset });
      setData(res.data);
    } catch (err: any) {
      console.error("Failed to load analytics:", err);
      setError(err.response?.data?.detail || err.message || "Failed to load analytics");
    } finally {
      setLoading(false);
    }
  }, [selectedPreset]);

  useEffect(() => {
    fetchAnalytics();
  }, [fetchAnalytics]);

  const metrics = data?.metrics;
  const timeline = data?.timeline || [];

  const totalQueries = metrics?.total_queries ?? 0;
  const maliciousDomains = metrics?.malicious_domains ?? 0;
  const uniqueApex = metrics?.unique_registered_domains ?? 0;
  const uniqueClients = metrics?.unique_clients ?? 0;

  return (
    <div className="space-y-4">
      {/* Header & Window Selectors */}
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold tracking-tight text-foreground">
          Analytics
        </h1>

        <div className="flex items-center gap-1 bg-muted/40 p-0.5 rounded border border-border/70">
          {PRESET_OPTIONS.map((opt) => {
            const isSelected = selectedPreset === opt.value;
            return (
              <button
                key={opt.value}
                onClick={() => setSelectedPreset(opt.value)}
                className={cn(
                  "px-2 py-0.5 text-xs rounded font-medium transition-colors cursor-pointer",
                  isSelected
                    ? "bg-primary text-primary-foreground font-semibold"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                {opt.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <MetricWidget
          title="Queries"
          value={totalQueries}
          trend={`${selectedPreset} window`}
        />

        <MetricWidget
          title="Apex Domains"
          value={uniqueApex}
          trend={`${metrics?.unique_fqdns ?? 0} FQDNs`}
        />

        <MetricWidget
          title="Malicious"
          value={maliciousDomains}
          isThreat={maliciousDomains > 0}
          trend={maliciousDomains > 0 ? "Flagged threats" : "Clean traffic"}
        />

        <MetricWidget
          title="Clients"
          value={uniqueClients}
          trend="Querying clients"
        />
      </div>

      {/* Timeline Visualization */}
      <ChartWidget
        title="Query timeline"
        height={240}
        loading={loading}
        error={error}
        empty={timeline.length === 0}
        emptyMessage="No query telemetry in this window."
      >
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={timeline} margin={{ top: 8, right: 8, left: -24, bottom: 0 }}>
            <defs>
              <linearGradient id="areaTimeline" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#2563EB" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#2563EB" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="currentColor" className="text-border/30" vertical={false} />
            <XAxis
              dataKey="timestamp"
              stroke="currentColor"
              className="text-muted-foreground text-[11px]"
              tickLine={false}
              axisLine={false}
              tickFormatter={(val) => (val && val.length > 10 ? val.substring(11, 16) : val)}
            />
            <YAxis stroke="currentColor" className="text-muted-foreground text-[11px]" tickLine={false} axisLine={false} />
            <Tooltip
              contentStyle={{
                backgroundColor: "var(--popover)",
                borderColor: "var(--border)",
                borderRadius: "0.375rem",
                fontSize: "12px",
                padding: "6px 10px",
              }}
            />
            <Area
              type="monotone"
              dataKey="queries"
              stroke="#2563EB"
              strokeWidth={1.5}
              fillOpacity={1}
              fill="url(#areaTimeline)"
              name="Queries"
            />
          </AreaChart>
        </ResponsiveContainer>
      </ChartWidget>
    </div>
  );
};

export default AnalyticsPage;
