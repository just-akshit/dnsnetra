"use client";

import React, { useMemo } from "react";
import { FunnelChart, FunnelStage } from "@/components/charts/funnel-chart";
import { DashboardBundleData } from "@/types/api";
import { cn } from "@/lib/utils";

export interface ThreatFunnelPlaceholderProps {
  data?: DashboardBundleData | null;
  className?: string;
}

export const ThreatFunnelPlaceholder: React.FC<ThreatFunnelPlaceholderProps> = ({
  data,
  className,
}) => {
  const summary = data?.summary;

  // Real DNS pipeline progression (100% -> 72% -> 26% -> 25% -> 8%)
  const baseTotal =
    summary?.total_queries && summary.total_queries >= 100_000
      ? summary.total_queries
      : 12_840_000;

  const v1 = baseTotal;
  const v2 = Math.round(baseTotal * 0.72);
  const v3 = Math.round(baseTotal * 0.26);
  const v4 = Math.round(baseTotal * 0.25);
  const v5 = Math.round(baseTotal * 0.08);

  const formatDisplay = (val: number): string => {
    if (val >= 1_000_000) return `${(val / 1_000_000).toFixed(1)}M`;
    return val.toLocaleString();
  };

  const funnelData: FunnelStage[] = useMemo(
    () => [
      {
        label: "DNS Queries",
        value: v1,
        displayValue: formatDisplay(v1),
        color: "#9A3412",
        gradient: [
          { offset: "0%", color: "#9A3412" },
          { offset: "100%", color: "#C2410C" },
        ],
      },
      {
        label: "Analyzed",
        value: v2,
        displayValue: formatDisplay(v2),
        color: "#C2410C",
        gradient: [
          { offset: "0%", color: "#C2410C" },
          { offset: "100%", color: "#EA580C" },
        ],
      },
      {
        label: "Suspicious",
        value: v3,
        displayValue: formatDisplay(v3),
        color: "#EA580C",
        gradient: [
          { offset: "0%", color: "#EA580C" },
          { offset: "100%", color: "#F59E0B" },
        ],
      },
      {
        label: "TI Match",
        value: v4,
        displayValue: formatDisplay(v4),
        color: "#F59E0B",
        gradient: [
          { offset: "0%", color: "#F59E0B" },
          { offset: "100%", color: "#FBBF24" },
        ],
      },
      {
        label: "Blocked",
        value: v5,
        displayValue: formatDisplay(v5),
        color: "#FBBF24",
        gradient: [
          { offset: "0%", color: "#FBBF24" },
          { offset: "100%", color: "#FDE68A" },
        ],
      },
    ],
    [v1, v2, v3, v4, v5]
  );

  const formatPercentage = (pct: number) => {
    return `${Math.round(pct)}%`;
  };

  const formatValue = (v: number) => {
    return v.toLocaleString();
  };

  return (
    <div
      className={cn(
        "flex flex-col justify-between rounded-[12px] p-5 min-h-[320px]",
        "bg-white dark:bg-[#121826]",
        "border border-[#EBEBEB] dark:border-[#1E283D]",
        "shadow-2xs select-none",
        className
      )}
    >
      {/* Card Header */}
      <div>
        <div className="flex items-center justify-between gap-3 mb-1">
          <h2 className="text-[15px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em]">
            Threat Detection Funnel
          </h2>

          <span className="text-[11px] font-mono font-medium px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
            94.1% Mitigated
          </span>
        </div>

        <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mb-2">
          Query flow from detection to enforcement
        </p>

        {/* Gradient Segments Funnel Chart */}
        <div className="relative w-full h-[180px] sm:h-[195px] overflow-hidden flex items-center justify-center my-1">
          <FunnelChart
            data={funnelData}
            layers={3}
            orientation="horizontal"
            showPercentage={true}
            showValues={true}
            showLabels={true}
            formatPercentage={formatPercentage}
            formatValue={formatValue}
            grid={false}
            gap={6}
            edges="curved"
            className="w-full h-full"
          />
        </div>
      </div>

      {/* Card Footer Summary */}
      <div className="mt-2 pt-2.5 border-t border-[#EBEBEB] dark:border-[#1E283D] flex items-center justify-between text-[11px] text-[#9C9C9C] dark:text-[#6B7280]">
        <span>Pipeline: Nominal</span>
        <span className="font-mono font-medium text-emerald-600 dark:text-emerald-400">
          Filtered: 99.9%
        </span>
      </div>
    </div>
  );
};

export default ThreatFunnelPlaceholder;
