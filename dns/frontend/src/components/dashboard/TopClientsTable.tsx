"use client";

import React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowRight, ExternalLink, ShieldAlert, CheckCircle2 } from "lucide-react";
import { cn } from "@/lib/utils";

export interface TopClientEntry {
  ip: string;
  queryCount: string;
  threatCount: number;
  segment: string;
  status: "critical" | "warning" | "clean";
}

export interface TopClientsTableProps {
  items?: TopClientEntry[];
  className?: string;
}

const DEFAULT_TOP_CLIENTS: TopClientEntry[] = [
  {
    ip: "192.168.10.42",
    queryCount: "682,400",
    threatCount: 18,
    segment: "VLAN-Eng (Workstation)",
    status: "critical",
  },
  {
    ip: "10.0.4.118",
    queryCount: "491,200",
    threatCount: 6,
    segment: "DMZ-AppServer-01",
    status: "warning",
  },
  {
    ip: "192.168.20.15",
    queryCount: "340,900",
    threatCount: 0,
    segment: "VLAN-Finance",
    status: "clean",
  },
  {
    ip: "172.16.88.9",
    queryCount: "289,100",
    threatCount: 14,
    segment: "VPN-Remote-Pool",
    status: "critical",
  },
  {
    ip: "10.0.12.50",
    queryCount: "215,000",
    threatCount: 0,
    segment: "Core-Kube-Node-3",
    status: "clean",
  },
];

export const TopClientsTable: React.FC<TopClientsTableProps> = ({
  items = DEFAULT_TOP_CLIENTS,
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
            Top Clients
          </h2>

          <Link
            href="/investigate/clients"
            className="flex items-center gap-1 text-[12px] font-medium text-[#2F6FED] hover:text-[#255ED4] transition-colors"
          >
            <span>View all clients</span>
            <ArrowRight className="w-3 h-3" />
          </Link>
        </div>

        <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mb-4">
          Highest-volume clients and affected endpoints
        </p>

        {/* Structured Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[12px]">
            <thead>
              <tr className="border-b border-[#EBEBEB] dark:border-[#1E283D] text-[#6B6B6B] dark:text-[#9CA3AF] font-medium">
                <th className="pb-2 pl-1">Client IP</th>
                <th className="pb-2 px-2 text-right">Queries</th>
                <th className="pb-2 px-2 text-center">Threats</th>
                <th className="pb-2 px-2 hidden sm:table-cell">VLAN / Device</th>
                <th className="pb-2 pr-1 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70">
              {items.map((item) => (
                <tr
                  key={item.ip}
                  className="group hover:bg-neutral-50 dark:hover:bg-[#1C2438]/50 transition-colors"
                >
                  {/* IP address */}
                  <td className="py-2.5 pl-1 font-mono text-[12px] text-[#1A1A1A] dark:text-[#F3F4F6]">
                    <span
                      onClick={() => router.push(`/investigate/clients/${encodeURIComponent(item.ip)}`)}
                      className="hover:text-[#2F6FED] hover:underline cursor-pointer"
                    >
                      {item.ip}
                    </span>
                  </td>

                  {/* Query count */}
                  <td className="py-2.5 px-2 text-right font-mono font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">
                    {item.queryCount}
                  </td>

                  {/* Threat Count badge */}
                  <td className="py-2.5 px-2 text-center">
                    {item.threatCount > 0 ? (
                      <span className="inline-flex items-center gap-1 font-mono text-[11px] font-semibold px-2 py-0.5 rounded bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20">
                        <ShieldAlert className="w-2.5 h-2.5" />
                        {item.threatCount}
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 font-mono text-[11px] font-medium px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                        <CheckCircle2 className="w-2.5 h-2.5" />
                        0
                      </span>
                    )}
                  </td>

                  {/* Segment / VLAN */}
                  <td className="py-2.5 px-2 text-[#6B6B6B] dark:text-[#9CA3AF] text-[11px] hidden sm:table-cell truncate max-w-[140px]">
                    {item.segment}
                  </td>

                  {/* Action Link */}
                  <td className="py-2.5 pr-1 text-right">
                    <button
                      onClick={() => router.push(`/investigate/clients/${encodeURIComponent(item.ip)}`)}
                      className="p-1 rounded text-[#6B6B6B] hover:text-[#2F6FED] hover:bg-[#2F6FED]/10 transition-colors cursor-pointer"
                      title="Inspect Client Telemetry"
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
        <span>842 active endpoints</span>
        <span className="font-mono text-amber-600 dark:text-amber-400 font-medium">38 flagged clients</span>
      </div>
    </div>
  );
};

export default TopClientsTable;
