"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { Search, Globe2, ArrowRight, Database, ShieldAlert, Sparkles } from "lucide-react";
import { MetricWidget } from "@/components/dashboard/MetricWidget";
import { DashboardWidget } from "@/components/dashboard/DashboardWidget";
import { GlobalFilterBar } from "@/components/layout/GlobalFilterBar";
import { GlobalTimeRangePicker } from "@/components/layout/GlobalTimeRangePicker";

export const DomainIntelligencePage: React.FC = () => {
  const [lookupQuery, setLookupQuery] = useState("");
  const router = useRouter();

  const handleLookup = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = lookupQuery.trim();
    if (!clean) return;
    router.push(`/investigate/domains/${encodeURIComponent(clean)}`);
  };

  const samplePopularSearches = [
    "malicious-dga.xyz",
    "dns-tunnel-exfil.net",
    "phishing-secure-portal.com",
    "cdn.cloudflare.net",
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground font-sans">
            Domain Intelligence & Reputation Hub
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Deep WHOIS profiling, dynamic DGA detection, threat reputation scoring, and active telemetry correlation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <GlobalTimeRangePicker />
        </div>
      </div>

      {/* Global Filters */}
      <GlobalFilterBar />

      {/* Quick Lookup Hero */}
      <div className="p-6 rounded-xl border border-border bg-card shadow-xs">
        <form onSubmit={handleLookup} className="space-y-3">
          <div className="flex items-center gap-2 mb-1">
            <Sparkles className="w-4 h-4 text-primary" />
            <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground">
              Deep Domain Investigation Search
            </span>
          </div>

          <div className="flex flex-col sm:flex-row items-center gap-3">
            <div className="relative flex-1 w-full">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                type="text"
                value={lookupQuery}
                onChange={(e) => setLookupQuery(e.target.value)}
                placeholder="Enter domain name or FQDN (e.g., malicious-dga.xyz)..."
                className="w-full pl-10 pr-4 py-2.5 text-xs rounded-lg border border-border bg-background text-foreground placeholder:text-muted-foreground outline-none focus:border-primary font-mono"
              />
            </div>
            <button
              type="submit"
              className="flex items-center gap-1.5 px-4 py-2.5 rounded-lg bg-primary text-primary-foreground text-xs font-medium hover:opacity-90 transition-opacity cursor-pointer self-stretch sm:self-auto justify-center"
            >
              <span>Investigate Domain</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="flex items-center gap-2 flex-wrap text-xs text-muted-foreground pt-1">
            <span>Quick lookup:</span>
            {samplePopularSearches.map((domain) => (
              <button
                key={domain}
                type="button"
                onClick={() => router.push(`/investigate/domains/${encodeURIComponent(domain)}`)}
                className="px-2 py-0.5 rounded bg-secondary hover:bg-accent text-[11px] font-mono text-foreground transition-colors cursor-pointer"
              >
                {domain}
              </button>
            ))}
          </div>
        </form>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <MetricWidget
          title="Indexed Domains"
          value="1,000,000+"
          trend="Tranco Top 1M + IOCs"
        />
        <MetricWidget
          title="Reputation Cache"
          value="ONLINE"
          trend="Sub-millisecond query time"
        />
        <MetricWidget
          title="External TI Connectors"
          value="CONNECTED"
          trend="Multi-source validation"
        />
      </div>
    </div>
  );
};

export default DomainIntelligencePage;
