"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Radar, ShieldCheck, Database, RefreshCw, ExternalLink, Globe, AlertTriangle } from "lucide-react";
import { MetricWidget } from "@/components/dashboard/MetricWidget";
import { DashboardWidget } from "@/components/dashboard/DashboardWidget";
import { GlobalFilterBar } from "@/components/layout/GlobalFilterBar";
import { GlobalTimeRangePicker } from "@/components/layout/GlobalTimeRangePicker";
import { apiClient } from "@/lib/api-client";
import { DashboardBundleData } from "@/types/api";
import { formatNumber } from "@/lib/format";

export const ThreatIntelligencePage: React.FC = () => {
  const [data, setData] = useState<DashboardBundleData | null>(null);
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchThreatData = useCallback(async (isManual = false) => {
    if (isManual) setIsRefreshing(true);
    else setLoading(true);
    try {
      const res = await apiClient.getDashboard();
      setData(res.data);
    } catch (err) {
      console.error("Failed to load TI feeds data:", err);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchThreatData();
  }, [fetchThreatData]);

  const summary = data?.summary;
  const categories = data?.categories || [];
  const totalThreats = summary?.total_threats ?? 0;

  const feeds = [
    {
      name: "Global DNS Sinkhole Blocklist",
      provider: "Internal SOC Engine",
      type: "Domain / FQDN",
      status: "Active & Synced",
      recordsCount: totalThreats > 0 ? formatNumber(totalThreats) : "0",
      lastSync: "Real-time stream",
    },
    {
      name: "Malware Command & Control (C2) Feeds",
      provider: "ThreatFox / Abuse.ch",
      type: "C2 IP / Domain",
      status: "Active & Synced",
      recordsCount: formatNumber(categories.find((c) => c.category.toLowerCase().includes("c2"))?.count ?? 0),
      lastSync: "Synchronized",
    },
    {
      name: "Emerging DGA Signatures",
      provider: "AI Heuristic Model",
      type: "Pattern Rule",
      status: "Active & Synced",
      recordsCount: formatNumber(categories.find((c) => c.category.toLowerCase().includes("dga"))?.count ?? 0),
      lastSync: "Automated inference",
    },
    {
      name: "Phishing & Brand Impersonation Registry",
      provider: "URLhaus Stream",
      type: "Domain / URL",
      status: "Active & Synced",
      recordsCount: formatNumber(categories.find((c) => c.category.toLowerCase().includes("phish"))?.count ?? 0),
      lastSync: "Real-time feed",
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground font-sans">
            Threat Intelligence Feeds & IOC Providers
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Aggregated threat intelligence streams, malicious reputation databases, and IOC ingestion state.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => fetchThreatData(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-border bg-card text-xs font-medium text-foreground hover:bg-accent transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin text-primary" : "text-muted-foreground"}`} />
            <span>Refresh</span>
          </button>
          <GlobalTimeRangePicker />
        </div>
      </div>

      {/* Global Filters */}
      <GlobalFilterBar />

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <MetricWidget
          title="Active TI Feeds"
          value="4"
          trend="All feeds online"
        />
        <MetricWidget
          title="Active Correlated IOCs"
          value={totalThreats}
          isThreat={totalThreats > 0}
          trend={totalThreats > 0 ? "Real-time matching" : "Zero active IOCs"}
        />
        <MetricWidget
          title="TI Pipeline Health"
          value="OPTIMAL"
          trend="Zero ingest latency"
        />
      </div>

      {/* Threat Feeds List Card */}
      <DashboardWidget
        title="Ingested Threat Intelligence Feeds"
        description="Continuous external reputation streams and heuristic blocklists"
      >
        <div className="space-y-3">
          {feeds.map((feed, idx) => (
            <div
              key={idx}
              className="p-3.5 rounded-lg border border-border bg-secondary/20 hover:bg-secondary/50 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3"
            >
              <div className="flex items-start gap-3">
                <div className="p-2 rounded-md bg-secondary text-primary shrink-0 mt-0.5 sm:mt-0">
                  <Radar className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-semibold text-foreground">
                      {feed.name}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 font-medium">
                      {feed.status}
                    </span>
                  </div>
                  <p className="text-[11px] text-muted-foreground mt-0.5">
                    Provider: {feed.provider} • Target: {feed.type}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-4 text-xs text-muted-foreground self-end sm:self-auto shrink-0 font-mono">
                <div>
                  <span className="text-foreground font-medium">{feed.recordsCount}</span> records
                </div>
                <div className="text-[11px]">
                  {feed.lastSync}
                </div>
              </div>
            </div>
          ))}
        </div>
      </DashboardWidget>
    </div>
  );
};

export default ThreatIntelligencePage;
