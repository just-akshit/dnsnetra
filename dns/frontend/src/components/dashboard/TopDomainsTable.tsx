"use client";

import React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowRight, ExternalLink } from "lucide-react";
import { VerdictBadge } from "@/components/security/VerdictBadge";
import { cn } from "@/lib/utils";

export interface TopDomainEntry {
  rank: number;
  domain: string;
  queryCount: string;
  clientCount: number;
  verdict: "malicious" | "suspicious" | "clean" | "unknown";
  riskScore: number;
  category: string;
}

export interface TopDomainsTableProps {
  items?: TopDomainEntry[];
  className?: string;
}

const DEFAULT_TOP_DOMAINS: TopDomainEntry[] = [
  {
    rank: 1,
    domain: "api.github.com",
    queryCount: "2,410,800",
    clientCount: 524,
    verdict: "clean",
    riskScore: 2,
    category: "Developer APIs",
  },
  {
    rank: 2,
    domain: "gateway.discord.gg",
    queryCount: "1,842,100",
    clientCount: 412,
    verdict: "clean",
    riskScore: 5,
    category: "Communication",
  },
  {
    rank: 3,
    domain: "telemetry.cloud-metrics.ru",
    queryCount: "940,320",
    clientCount: 88,
    verdict: "suspicious",
    riskScore: 72,
    category: "Uncategorized",
  },
  {
    rank: 4,
    domain: "auth-portal.sso-verify.cc",
    queryCount: "412,900",
    clientCount: 34,
    verdict: "malicious",
    riskScore: 94,
    category: "Phishing / Credential",
  },
  {
    rank: 5,
    domain: "dns.google",
    queryCount: "389,000",
    clientCount: 680,
    verdict: "clean",
    riskScore: 1,
    category: "Infrastructure",
  },
];

export const TopDomainsTable: React.FC<TopDomainsTableProps> = ({
  items = DEFAULT_TOP_DOMAINS,
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
            Top Domains
          </h2>

          <Link
            href="/investigate/domains"
            className="flex items-center gap-1 text-[12px] font-medium text-[#2F6FED] hover:text-[#255ED4] transition-colors"
          >
            <span>View directory</span>
            <ArrowRight className="w-3 h-3" />
          </Link>
        </div>

        <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mb-4">
          Highest-volume domains by query count
        </p>

        {/* Structured Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[12px]">
            <thead>
              <tr className="border-b border-[#EBEBEB] dark:border-[#1E283D] text-[#6B6B6B] dark:text-[#9CA3AF] font-medium">
                <th className="pb-2 pl-1">Domain</th>
                <th className="pb-2 px-2 text-right">Queries</th>
                <th className="pb-2 px-2 text-center hidden sm:table-cell">Clients</th>
                <th className="pb-2 px-2">Verdict</th>
                <th className="pb-2 pr-1 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70">
              {items.map((item) => (
                <tr
                  key={item.domain}
                  className="group hover:bg-neutral-50 dark:hover:bg-[#1C2438]/50 transition-colors"
                >
                  {/* Domain with rank */}
                  <td className="py-2.5 pl-1 font-mono text-[12px] text-[#1A1A1A] dark:text-[#F3F4F6]">
                    <div className="flex items-center gap-2 max-w-[200px] truncate">
                      <span className="text-[11px] font-medium text-[#9C9C9C] dark:text-[#6B7280] w-3.5">
                        #{item.rank}
                      </span>
                      <span
                        onClick={() => router.push(`/investigate/domains/${encodeURIComponent(item.domain)}`)}
                        className="truncate hover:text-[#2F6FED] hover:underline cursor-pointer"
                        title={item.domain}
                      >
                        {item.domain}
                      </span>
                    </div>
                  </td>

                  {/* Query Volume */}
                  <td className="py-2.5 px-2 text-right font-mono font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">
                    {item.queryCount}
                  </td>

                  {/* Client Count */}
                  <td className="py-2.5 px-2 text-center text-[#6B6B6B] dark:text-[#9CA3AF] font-mono text-[11px] hidden sm:table-cell">
                    {item.clientCount}
                  </td>

                  {/* Verdict */}
                  <td className="py-2.5 px-2">
                    <VerdictBadge verdict={item.verdict} />
                  </td>

                  {/* Action Link */}
                  <td className="py-2.5 pr-1 text-right">
                    <button
                      onClick={() => router.push(`/investigate/domains/${encodeURIComponent(item.domain)}`)}
                      className="p-1 rounded text-[#6B6B6B] hover:text-[#2F6FED] hover:bg-[#2F6FED]/10 transition-colors cursor-pointer"
                      title="Inspect Domain"
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
        <span>1.42M domains tracked</span>
        <span className="font-mono text-muted-foreground">Aggregated across all resolvers</span>
      </div>
    </div>
  );
};

export default TopDomainsTable;
