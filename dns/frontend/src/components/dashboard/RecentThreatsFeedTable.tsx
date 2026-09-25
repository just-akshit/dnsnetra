"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowRight, ExternalLink } from "lucide-react";
import { cn } from "@/lib/utils";

export interface ThreatFeedItem {
  id: string;
  timestamp: string;
  threatName: string;
  severity: "critical" | "high" | "medium" | "low";
  domain: string;
  clientIp: string;
  action: "blocked" | "alerted" | "sinkholed" | "monitored";
  ruleId: string;
}

export interface RecentThreatsFeedTableProps {
  items?: ThreatFeedItem[];
  className?: string;
}

const DEFAULT_THREAT_FEED: ThreatFeedItem[] = [
  {
    id: "evt-901",
    timestamp: "12s ago",
    threatName: "Cobalt Strike HTTPS C2 Beaconing",
    severity: "critical",
    domain: "c2-relay.darknet-sync.cc",
    clientIp: "192.168.10.42",
    action: "blocked",
    ruleId: "RULE-C2-882",
  },
  {
    id: "evt-902",
    timestamp: "48s ago",
    threatName: "DNS Tunneling Base64 Exfiltration",
    severity: "critical",
    domain: "data-chunk-01.tunnel-dns.biz",
    clientIp: "172.16.88.9",
    action: "blocked",
    ruleId: "RULE-EXFIL-04",
  },
  {
    id: "evt-903",
    timestamp: "2m ago",
    threatName: "Emotet DGA Domain Pattern Match",
    severity: "high",
    domain: "dga-payload.dynamic-routing.info",
    clientIp: "10.0.4.118",
    action: "sinkholed",
    ruleId: "RULE-DGA-219",
  },
  {
    id: "evt-904",
    timestamp: "5m ago",
    threatName: "Executive Credential Phishing Landing",
    severity: "high",
    domain: "auth-verify.secure-banklogin.ru",
    clientIp: "192.168.10.42",
    action: "blocked",
    ruleId: "RULE-PHISH-90",
  },
  {
    id: "evt-905",
    timestamp: "11m ago",
    threatName: "Fast-Flux Bulletproof Hosting Lookup",
    severity: "medium",
    domain: "telemetry-drop.cdn77-cloud.xyz",
    clientIp: "192.168.20.15",
    action: "alerted",
    ruleId: "RULE-ANOM-12",
  },
  {
    id: "evt-906",
    timestamp: "18m ago",
    threatName: "Cryptojacking Pool Stratum Query",
    severity: "medium",
    domain: "xmr-pool.stratum-mining.eu",
    clientIp: "10.0.12.50",
    action: "blocked",
    ruleId: "RULE-COIN-03",
  },
];

export const RecentThreatsFeedTable: React.FC<RecentThreatsFeedTableProps> = ({
  items = DEFAULT_THREAT_FEED,
  className,
}) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");
  const router = useRouter();

  const filteredItems = items.filter((item) => {
    if (selectedSeverity === "all") return true;
    return item.severity === selectedSeverity;
  });

  const severityBadges: Record<string, { bg: string; text: string; dot: string }> = {
    critical: {
      bg: "bg-red-500/10 border-red-500/30 text-red-600 dark:text-red-400",
      text: "CRITICAL",
      dot: "bg-red-500",
    },
    high: {
      bg: "bg-amber-500/10 border-amber-500/30 text-amber-600 dark:text-amber-400",
      text: "HIGH",
      dot: "bg-amber-500",
    },
    medium: {
      bg: "bg-blue-500/10 border-blue-500/30 text-blue-600 dark:text-blue-400",
      text: "MEDIUM",
      dot: "bg-blue-500",
    },
    low: {
      bg: "bg-neutral-500/10 border-neutral-500/30 text-neutral-600 dark:text-neutral-400",
      text: "LOW",
      dot: "bg-neutral-400",
    },
  };

  const actionBadges: Record<string, { bg: string; text: string }> = {
    blocked: {
      bg: "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20",
      text: "BLOCKED",
    },
    sinkholed: {
      bg: "bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20",
      text: "SINKHOLED",
    },
    alerted: {
      bg: "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20",
      text: "ALERTED",
    },
    monitored: {
      bg: "bg-neutral-500/10 text-neutral-600 dark:text-neutral-400 border-neutral-500/20",
      text: "MONITORED",
    },
  };

  return (
    <div
      className={cn(
        "flex flex-col justify-between rounded-[12px] p-5",
        "bg-white dark:bg-[#121826]",
        "border border-[#EBEBEB] dark:border-[#1E283D]",
        "shadow-2xs select-none",
        className
      )}
    >
      <div>
        {/* Card Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-2">
          <div className="flex items-center gap-2 min-w-0">
            <h2 className="text-[16px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em]">
              Recent Threats Feed
            </h2>
            <span className="flex items-center gap-1 text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              Live
            </span>
          </div>

          {/* Header Right Actions */}
          <div className="flex items-center gap-2.5">
            {/* Functional Severity Filter Tabs */}
            <div className="flex items-center bg-[#F2F2F2] dark:bg-[#1C2438] p-0.5 rounded-[6px] border border-[#EBEBEB] dark:border-[#2D3A54] text-[11px]">
              {[
                { id: "all", label: "All" },
                { id: "critical", label: "Critical" },
                { id: "high", label: "High" },
                { id: "medium", label: "Medium" },
              ].map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setSelectedSeverity(tab.id)}
                  className={cn(
                    "px-2.5 py-1 rounded-[4px] font-medium transition-colors cursor-pointer",
                    selectedSeverity === tab.id
                      ? "bg-white dark:bg-[#121826] text-[#1A1A1A] dark:text-[#F3F4F6] shadow-2xs font-semibold"
                      : "text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                  )}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <Link
              href="/analytics/threats"
              className="flex items-center gap-1 text-[12px] font-medium text-[#2F6FED] hover:text-[#255ED4] px-2.5 py-1 rounded-[6px] hover:bg-[#2F6FED]/10 transition-colors"
            >
              <span>View full log</span>
              <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
        </div>

        <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mb-4">
          Recent threats, IOC matches, and response actions
        </p>

        {/* Structured Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[12px]">
            <thead>
              <tr className="border-b border-[#EBEBEB] dark:border-[#1E283D] text-[#6B6B6B] dark:text-[#9CA3AF] font-medium">
                <th className="pb-2.5 pl-1">Timestamp</th>
                <th className="pb-2.5 px-2">Severity</th>
                <th className="pb-2.5 px-2">Threat Signature</th>
                <th className="pb-2.5 px-2">Target Domain / IOC</th>
                <th className="pb-2.5 px-2">Client IP</th>
                <th className="pb-2.5 px-2 text-center">Action</th>
                <th className="pb-2.5 pr-1 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70 font-sans">
              {filteredItems.map((item) => {
                const sev = severityBadges[item.severity] || severityBadges.medium;
                const act = actionBadges[item.action] || actionBadges.alerted;

                return (
                  <tr
                    key={item.id}
                    className="group hover:bg-neutral-50 dark:hover:bg-[#1C2438]/50 transition-colors"
                  >
                    {/* Timestamp */}
                    <td className="py-2.5 pl-1 font-mono text-[11px] text-[#9C9C9C] dark:text-[#6B7280] whitespace-nowrap">
                      {item.timestamp}
                    </td>

                    {/* Severity Badge */}
                    <td className="py-2.5 px-2">
                      <span
                        className={cn(
                          "inline-flex items-center gap-1 font-mono text-[10px] font-semibold px-2 py-0.5 rounded-full border",
                          sev.bg
                        )}
                      >
                        <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", sev.dot)} />
                        {sev.text}
                      </span>
                    </td>

                    {/* Threat Name */}
                    <td className="py-2.5 px-2 font-medium text-[#1A1A1A] dark:text-[#F3F4F6] max-w-[260px] truncate">
                      {item.threatName}
                    </td>

                    {/* Domain IOC */}
                    <td className="py-2.5 px-2 font-mono text-[12px] text-[#2F6FED] dark:text-[#60A5FA]">
                      <span
                        onClick={() => router.push(`/investigate/domains/${encodeURIComponent(item.domain)}`)}
                        className="hover:underline cursor-pointer truncate block max-w-[220px]"
                        title={item.domain}
                      >
                        {item.domain}
                      </span>
                    </td>

                    {/* Client IP */}
                    <td className="py-2.5 px-2 font-mono text-[12px] text-[#1A1A1A] dark:text-[#D1D5DB]">
                      <span
                        onClick={() => router.push(`/investigate/clients/${encodeURIComponent(item.clientIp)}`)}
                        className="hover:underline cursor-pointer"
                      >
                        {item.clientIp}
                      </span>
                    </td>

                    {/* Action Enforcement */}
                    <td className="py-2.5 px-2 text-center">
                      <span
                        className={cn(
                          "inline-block font-mono text-[10px] font-semibold px-2 py-0.5 rounded border",
                          act.bg
                        )}
                      >
                        {act.text}
                      </span>
                    </td>

                    {/* Investigation Action Link */}
                    <td className="py-2.5 pr-1 text-right">
                      <button
                        onClick={() => router.push(`/investigate/domains/${encodeURIComponent(item.domain)}`)}
                        className="p-1 rounded text-[#6B6B6B] hover:text-[#2F6FED] hover:bg-[#2F6FED]/10 transition-colors cursor-pointer"
                        title="Investigate incident"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Card Footer Summary */}
      <div className="mt-3.5 pt-3 border-t border-[#EBEBEB] dark:border-[#1E283D] flex items-center justify-between text-[11px] text-[#9C9C9C] dark:text-[#6B7280]">
        <div className="flex items-center gap-3">
          <span>Ingress: <strong>1,480 qps</strong></span>
          <span>•</span>
          <span>Mitigation: <strong className="text-emerald-600 dark:text-emerald-400">94.1% auto-blocked</strong></span>
        </div>
        <div className="font-mono text-[11px] text-muted-foreground">
          Sensors: 3/3 active
        </div>
      </div>
    </div>
  );
};

export default RecentThreatsFeedTable;
