"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Clock,
  Globe,
  Activity,
  Users,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  Calendar,
  Layers,
  Info,
  ChevronDown,
  Sparkles,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import apiClient from "../../lib/api-client";
import { DomainAnalyticsData, TimelineBucket } from "../../types/api";

const PRESET_OPTIONS = [
  { label: "Last 5 min", value: "5m", minutes: 5 },
  { label: "Last 10 min", value: "10m", minutes: 10 },
  { label: "Last 15 min", value: "15m", minutes: 15 },
  { label: "Last 30 min", value: "30m", minutes: 30 },
  { label: "Last 45 min", value: "45m", minutes: 45 },
  { label: "Last 1 hour", value: "60m", minutes: 60 },
  { label: "Custom Range", value: "custom", minutes: null },
];

export const TimeWindowAnalytics: React.FC = () => {
  const [selectedPreset, setSelectedPreset] = useState<string>("15m");
  const [data, setData] = useState<DomainAnalyticsData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Custom range state (UTC ISO strings)
  const [customStart, setCustomStart] = useState<string>("");
  const [customEnd, setCustomEnd] = useState<string>("");
  const [showCustomModal, setShowCustomModal] = useState<boolean>(false);

  const fetchAnalytics = useCallback(
    async (isManual = false) => {
      if (isManual) setIsRefreshing(true);
      else setLoading(true);
      setError(null);

      try {
        let res;
        if (selectedPreset === "custom") {
          if (!customStart || !customEnd) {
            setError("Please provide both start and end timestamps for custom range.");
            setLoading(false);
            setIsRefreshing(false);
            return;
          }
          res = await apiClient.getDomainAnalytics({
            start: new Date(customStart).toISOString(),
            end: new Date(customEnd).toISOString(),
          });
        } else {
          res = await apiClient.getDomainAnalytics({ window: selectedPreset });
        }

        setData(res.data);
      } catch (err: any) {
        console.error("Failed to load time-window analytics:", err);
        setError(
          err.response?.data?.detail || err.message || "Failed to load time-window DNS analytics"
        );
      } finally {
        setLoading(false);
        setIsRefreshing(false);
      }
    },
    [selectedPreset, customStart, customEnd]
  );

  useEffect(() => {
    fetchAnalytics();
    // Auto-refresh every 30 seconds for presets
    if (selectedPreset !== "custom") {
      const interval = setInterval(() => {
        fetchAnalytics(true);
      }, 30000);
      return () => clearInterval(interval);
    }
  }, [fetchAnalytics, selectedPreset]);

  // Format custom date input defaults
  const handleOpenCustom = () => {
    if (!customStart || !customEnd) {
      const now = new Date();
      const past = new Date(now.getTime() - 60 * 60 * 1000); // 1 hour ago
      setCustomEnd(now.toISOString().slice(0, 16));
      setCustomStart(past.toISOString().slice(0, 16));
    }
    setShowCustomModal(true);
  };

  const handleApplyCustom = () => {
    if (new Date(customStart) >= new Date(customEnd)) {
      setError("Start time must be strictly before end time.");
      return;
    }
    setSelectedPreset("custom");
    setShowCustomModal(false);
  };

  const metrics = data?.metrics;
  const windowInfo = data?.window;
  const timeline = data?.timeline || [];

  return (
    <div className="glass-card p-6 bg-gradient-to-b from-card/90 to-background/90 border border-border/80 rounded-2xl shadow-xl space-y-6">
      {/* Header & Window Controls */}
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4 border-b border-border/50 pb-5">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono font-semibold uppercase tracking-wider text-brand-blue bg-brand-blue/10 px-2.5 py-0.5 rounded-full border border-brand-blue/30 flex items-center gap-1.5">
              <Sparkles className="w-3 h-3 text-brand-blue" />
              Phase 4.2 Analytics
            </span>
            <span className="text-xs text-slate-400 font-mono">
              Database-Side Dynamic Telemetry Aggregation
            </span>
          </div>
          <h2 className="text-xl font-bold tracking-tight text-foreground font-mono mt-1 flex items-center gap-2">
            Time-Window DNS Telemetry
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Observational intelligence on domains, unique apex origins, queries, and client activity over discrete UTC intervals.
          </p>
        </div>

        {/* Window Selector & Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Preset Buttons */}
          <div className="inline-flex rounded-xl bg-secondary/80 p-1 border border-border/60 shadow-inner">
            {PRESET_OPTIONS.map((opt) => {
              const isCustom = opt.value === "custom";
              const isActive = selectedPreset === opt.value;
              return (
                <button
                  key={opt.value}
                  onClick={() => {
                    if (isCustom) {
                      handleOpenCustom();
                    } else {
                      setSelectedPreset(opt.value);
                    }
                  }}
                  className={`px-3 py-1.5 text-xs font-mono font-medium rounded-lg transition-all cursor-pointer ${
                    isActive
                      ? "bg-brand-blue text-white shadow-md font-semibold"
                      : "text-slate-400 hover:text-foreground hover:bg-secondary/60"
                  }`}
                >
                  {opt.label}
                </button>
              );
            })}
          </div>

          {/* Manual Refresh Button */}
          <button
            onClick={() => fetchAnalytics(true)}
            disabled={isRefreshing || loading}
            title="Refresh rolling window to current server time"
            className="flex items-center space-x-1.5 text-xs font-mono px-3 py-1.5 rounded-xl bg-secondary hover:bg-muted border border-border transition-colors cursor-pointer disabled:opacity-50 text-foreground"
          >
            <RefreshCw
              className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin text-brand-blue" : "text-slate-400"}`}
            />
            <span className="hidden sm:inline">{isRefreshing ? "Syncing..." : "Refresh"}</span>
          </button>
        </div>
      </div>

      {/* Active Time Window Info Badge */}
      {windowInfo && (
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 rounded-xl bg-secondary/40 border border-border/40 text-xs font-mono">
          <div className="flex items-center space-x-2 text-slate-300">
            <Clock className="w-3.5 h-3.5 text-brand-blue" />
            <span>Active Window:</span>
            <span className="font-semibold text-foreground bg-secondary/80 px-2 py-0.5 rounded border border-border/50">
              {windowInfo.start.replace("T", " ").replace("Z", "")}
            </span>
            <span className="text-slate-500">→</span>
            <span className="font-semibold text-foreground bg-secondary/80 px-2 py-0.5 rounded border border-border/50">
              {windowInfo.end.replace("T", " ").replace("Z", "")}
            </span>
            <span className="text-brand-blue font-semibold">
              ({windowInfo.duration_minutes} min)
            </span>
          </div>

          <div className="flex items-center space-x-2 text-slate-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block animate-pulse" />
            <span>Server-side UTC half-open interval [start, end)</span>
          </div>
        </div>
      )}

      {/* Error Display */}
      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={() => fetchAnalytics(true)}
            className="underline hover:text-red-300 cursor-pointer"
          >
            Retry
          </button>
        </div>
      )}

      {/* 6 Key Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {/* KPI 1: Domains Observed (Primary - Unique Registered Domains) */}
        <div className="glass-card p-4 relative overflow-hidden bg-gradient-to-br from-brand-blue/10 via-card/80 to-card/40 border border-brand-blue/30 rounded-xl flex flex-col justify-between">
          <div className="flex justify-between items-start">
            <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-brand-blue">
              Domains Observed
            </span>
            <div className="p-2 bg-brand-blue/20 rounded-lg text-brand-blue">
              <Globe className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <h3 className="text-2xl font-bold font-mono text-foreground tracking-tight">
              {loading && !data ? "..." : (metrics?.unique_registered_domains ?? 0).toLocaleString()}
            </h3>
            <p className="text-[10px] text-slate-400 mt-1 flex items-center gap-1 font-mono">
              <span className="font-semibold text-brand-blue">Primary KPI</span> (Registered Apex)
            </p>
          </div>
        </div>

        {/* KPI 2: Unique FQDNs */}
        <div className="glass-card p-4 rounded-xl border border-border/60 flex flex-col justify-between">
          <div className="flex justify-between items-start">
            <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">
              Unique FQDNs
            </span>
            <div className="p-2 bg-secondary rounded-lg text-slate-400">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <h3 className="text-2xl font-bold font-mono text-foreground tracking-tight">
              {loading && !data ? "..." : (metrics?.unique_fqdns ?? 0).toLocaleString()}
            </h3>
            <p className="text-[10px] text-slate-400 mt-1 font-mono">Distinct query hostnames</p>
          </div>
        </div>

        {/* KPI 3: Total DNS Queries */}
        <div className="glass-card p-4 rounded-xl border border-border/60 flex flex-col justify-between">
          <div className="flex justify-between items-start">
            <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">
              DNS Queries
            </span>
            <div className="p-2 bg-blue-500/10 rounded-lg text-blue-400">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <h3 className="text-2xl font-bold font-mono text-foreground tracking-tight">
              {loading && !data ? "..." : (metrics?.total_queries ?? 0).toLocaleString()}
            </h3>
            <p className="text-[10px] text-slate-400 mt-1 font-mono">Total telemetry records</p>
          </div>
        </div>

        {/* KPI 4: Unique Clients */}
        <div className="glass-card p-4 rounded-xl border border-border/60 flex flex-col justify-between">
          <div className="flex justify-between items-start">
            <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-400">
              Active Clients
            </span>
            <div className="p-2 bg-emerald-500/10 rounded-lg text-emerald-400">
              <Users className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <h3 className="text-2xl font-bold font-mono text-foreground tracking-tight">
              {loading && !data ? "..." : (metrics?.unique_clients ?? 0).toLocaleString()}
            </h3>
            <p className="text-[10px] text-slate-400 mt-1 font-mono">Unique IP endpoints</p>
          </div>
        </div>

        {/* KPI 5: Malicious Domains */}
        <div className="glass-card p-4 rounded-xl border border-red-500/20 bg-red-500/5 flex flex-col justify-between">
          <div className="flex justify-between items-start">
            <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-red-400">
              Malicious
            </span>
            <div className="p-2 bg-red-500/15 rounded-lg text-red-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <h3 className="text-2xl font-bold font-mono text-red-400 tracking-tight">
              {loading && !data ? "..." : (metrics?.malicious_domains ?? 0).toLocaleString()}
            </h3>
            <p className="text-[10px] text-red-400/80 mt-1 font-mono">Distinct malicious domains</p>
          </div>
        </div>

        {/* KPI 6: Suspicious Domains */}
        <div className="glass-card p-4 rounded-xl border border-amber-500/20 bg-amber-500/5 flex flex-col justify-between">
          <div className="flex justify-between items-start">
            <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-amber-400">
              Suspicious
            </span>
            <div className="p-2 bg-amber-500/15 rounded-lg text-amber-400">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3">
            <h3 className="text-2xl font-bold font-mono text-amber-400 tracking-tight">
              {loading && !data ? "..." : (metrics?.suspicious_domains ?? 0).toLocaleString()}
            </h3>
            <p className="text-[10px] text-amber-400/80 mt-1 font-mono">Distinct suspicious domains</p>
          </div>
        </div>
      </div>

      {/* Activity Timeline Chart */}
      <div className="glass-card p-5 bg-secondary/20 border border-border/50 rounded-xl space-y-3">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
          <div>
            <h3 className="text-sm font-semibold font-mono text-foreground uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-brand-blue" />
              Activity Timeline (Deterministic UTC Buckets)
            </h3>
            <p className="text-xs text-slate-400 flex items-center gap-1 mt-0.5">
              <Info className="w-3.5 h-3.5 text-slate-500 shrink-0" />
              <span>
                Timeline buckets display activity within each interval. Bucket unique domain counts are interval-specific and{" "}
                <strong className="text-slate-300">non-additive</strong>.
              </span>
            </p>
          </div>

          <div className="flex items-center space-x-4 text-xs font-mono">
            <div className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block" />
              <span className="text-slate-300">DNS Queries</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-purple-400 inline-block" />
              <span className="text-slate-300">Unique Domains (per bucket)</span>
            </div>
          </div>
        </div>

        <div className="h-[260px] w-full pt-2">
          {timeline.length === 0 ? (
            <div className="flex items-center justify-center h-full text-slate-500 text-xs font-mono">
              No DNS telemetry recorded in this time window
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="twQueries" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="twDomains" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#A855F7" stopOpacity={0.5} />
                    <stop offset="95%" stopColor="#A855F7" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255, 255, 255, 0.08)" />
                <XAxis
                  dataKey="timestamp"
                  stroke="#64748B"
                  fontSize={11}
                  tickFormatter={(t) => (t && t.length > 10 ? t.substring(11, 19) : t)}
                />
                <YAxis stroke="#64748B" fontSize={11} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "rgba(15, 23, 42, 0.95)",
                    borderRadius: "8px",
                    border: "1px solid rgba(255, 255, 255, 0.15)",
                    boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.5)",
                    color: "#F8FAFC",
                    fontSize: "12px",
                    fontFamily: "monospace",
                  }}
                  labelFormatter={(label) => String(label ?? "").replace("T", " ").replace("Z", "")}
                  formatter={(value: any, name: any) => {
                    const label = name === "queries" ? "DNS Queries" : "Unique Registered Domains";
                    return [value.toLocaleString(), label];
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="queries"
                  stroke="#3B82F6"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#twQueries)"
                  name="queries"
                />
                <Area
                  type="monotone"
                  dataKey="unique_domains"
                  stroke="#A855F7"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#twDomains)"
                  name="unique_domains"
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Custom Range Selection Modal */}
      {showCustomModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="glass-card max-w-md w-full p-6 space-y-4 border border-border shadow-2xl bg-card rounded-2xl">
            <div className="flex justify-between items-center border-b border-border pb-3">
              <h3 className="text-base font-bold font-mono text-foreground flex items-center gap-2">
                <Calendar className="w-4 h-4 text-brand-blue" />
                Custom Time Window Range
              </h3>
              <button
                onClick={() => setShowCustomModal(false)}
                className="text-slate-400 hover:text-foreground text-sm font-mono cursor-pointer"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-400 font-mono">
              Specify UTC start and end bounds (maximum 30 days history). Timeline buckets will automatically scale.
            </p>

            <div className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-slate-300 mb-1 font-semibold">Start Datetime:</label>
                <input
                  type="datetime-local"
                  value={customStart}
                  onChange={(e) => setCustomStart(e.target.value)}
                  className="w-full px-3 py-2 bg-background border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-brand-blue"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-semibold">End Datetime:</label>
                <input
                  type="datetime-local"
                  value={customEnd}
                  onChange={(e) => setCustomEnd(e.target.value)}
                  className="w-full px-3 py-2 bg-background border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-brand-blue"
                />
              </div>
            </div>

            <div className="flex justify-end space-x-2 pt-2 border-t border-border">
              <button
                onClick={() => setShowCustomModal(false)}
                className="px-4 py-2 rounded-lg bg-secondary hover:bg-muted text-xs font-mono text-slate-300 cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleApplyCustom}
                className="px-4 py-2 rounded-lg bg-brand-blue hover:bg-brand-blue/90 text-white text-xs font-mono font-semibold cursor-pointer"
              >
                Apply Range
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default TimeWindowAnalytics;
