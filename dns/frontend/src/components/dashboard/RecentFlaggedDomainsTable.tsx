"use client";

import React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Star, ExternalLink, ArrowRight } from "lucide-react";
import { VerdictBadge } from "@/components/security/VerdictBadge";
import { cn } from "@/lib/utils";

export interface FlaggedDomainItem {
  domain: string;
  verdict: "malicious" | "suspicious" | "clean" | "unknown";
  score: number;
  source: string;
  flaggedAt: string;
  isStarred?: boolean;
}

export interface RecentFlaggedDomainsTableProps {
  items?: FlaggedDomainItem[];
  className?: string;
}

const DEFAULT_FLAGGED_DOMAINS: FlaggedDomainItem[] = [
  {
    domain: "c2-relay.darknet-sync.cc",
    verdict: "malicious",
    score: 96,
    source: "URLhaus C2 Feed",
    flaggedAt: "2m ago",
    isStarred: true,
  },
  {
    domain: "auth-verify.secure-banklogin.ru",
    verdict: "malicious",
    score: 92,
    source: "AlienVault OTX",
    flaggedAt: "8m ago",
    isStarred: true,
  },
  {
    domain: "telemetry-drop.cdn77-cloud.xyz",
    verdict: "suspicious",
    score: 74,
    source: "Heuristic Anomaly",
    flaggedAt: "14m ago",
    isStarred: false,
  },
  {
    domain: "dga-payload.dynamic-routing.info",
    verdict: "malicious",
    score: 89,
    source: "VirusTotal (24/70)",
    flaggedAt: "27m ago",
    isStarred: true,
  },
  {
    domain: "api.fast-content-delivery.online",
    verdict: "suspicious",
    score: 68,
    source: "Newly Registered",
    flaggedAt: "42m ago",
    isStarred: false,
  },
];

export const RecentFlaggedDomainsTable: React.FC<RecentFlaggedDomainsTableProps> = ({
  items = DEFAULT_FLAGGED_DOMAINS,
  className,
}) => {
  const router = useRouter();

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
        <div className="flex items-center justify-between gap-3 mb-1">
          <h2 className="text-[15px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em]">
            Recent Flagged Domains
          </h2>

          <Link
            href="/investigate/domains?label=malicious"
            className="flex items-center gap-1 text-[12px] font-medium text-[#2F6FED] hover:text-[#255ED4] transition-colors"
          >
            <span>View all flagged</span>
            <ArrowRight className="w-3 h-3" />
          </Link>
        </div>

        <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mb-4">
          Flagged domains requiring analyst attention
        </p>

        {/* Structured Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[12px]">
            <thead>
              <tr className="border-b border-[#EBEBEB] dark:border-[#1E283D] text-[#6B6B6B] dark:text-[#9CA3AF] font-medium">
                <th className="pb-2 pl-1">Domain</th>
                <th className="pb-2 px-2">Verdict</th>
                <th className="pb-2 px-2 text-center">Score</th>
                <th className="pb-2 px-2 hidden sm:table-cell">Source</th>
                <th className="pb-2 px-2 text-right">Time</th>
                <th className="pb-2 pr-1 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70">
              {items.map((item) => (
                <tr
                  key={item.domain}
                  className="group hover:bg-neutral-50 dark:hover:bg-[#1C2438]/50 transition-colors"
                >
                  {/* Domain Name */}
                  <td className="py-2.5 pl-1 font-mono text-[12px] text-[#1A1A1A] dark:text-[#F3F4F6]">
                    <div className="flex items-center gap-1.5 max-w-[220px] truncate">
                      {item.isStarred && (
                        <Star className="w-3 h-3 text-amber-500 fill-current shrink-0" />
                      )}
                      <span
                        onClick={() => router.push(`/investigate/domains/${encodeURIComponent(item.domain)}`)}
                        className="truncate hover:text-[#2F6FED] hover:underline cursor-pointer"
                        title={item.domain}
                      >
                        {item.domain}
                      </span>
                    </div>
                  </td>

                  {/* Verdict */}
                  <td className="py-2.5 px-2">
                    <VerdictBadge verdict={item.verdict} />
                  </td>

                  {/* Risk Score */}
                  <td className="py-2.5 px-2 text-center">
                    <span
                      className={cn(
                        "inline-block font-mono text-[11px] font-semibold px-1.5 py-0.5 rounded",
                        item.score >= 90
                          ? "bg-red-500/10 text-red-500 dark:text-red-400"
                          : item.score >= 70
                          ? "bg-amber-500/10 text-amber-600 dark:text-amber-400"
                          : "bg-neutral-200 dark:bg-neutral-700 text-neutral-600 dark:text-neutral-300"
                      )}
                    >
                      {item.score}
                    </span>
                  </td>

                  {/* TI Source */}
                  <td className="py-2.5 px-2 text-[#6B6B6B] dark:text-[#9CA3AF] text-[11px] hidden sm:table-cell truncate max-w-[130px]">
                    {item.source}
                  </td>

                  {/* Time */}
                  <td className="py-2.5 px-2 text-right font-mono text-[11px] text-[#9C9C9C] dark:text-[#6B7280]">
                    {item.flaggedAt}
                  </td>

                  {/* Action Link */}
                  <td className="py-2.5 pr-1 text-right">
                    <button
                      onClick={() => router.push(`/investigate/domains/${encodeURIComponent(item.domain)}`)}
                      className="p-1 rounded text-[#6B6B6B] hover:text-[#2F6FED] hover:bg-[#2F6FED]/10 transition-colors cursor-pointer"
                      title="Investigate Domain"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Card Footer Summary */}
      <div className="mt-3 pt-2.5 border-t border-[#EBEBEB] dark:border-[#1E283D] flex items-center justify-between text-[11px] text-[#9C9C9C] dark:text-[#6B7280]">
        <span>5 active watchlists</span>
        <span className="font-mono text-amber-600 dark:text-amber-400 font-medium">3 high-risk starred</span>
      </div>
    </div>
  );
};

export default RecentFlaggedDomainsTable;
