"use client";

import React, { useState, useMemo } from "react";
import { cn } from "@/lib/utils";
import { PieChart } from "./pie-chart";
import { PieSlice } from "./pie-slice";
import { PieCenter } from "./pie-center";
import type { PieData } from "./pie-context";
import {
  Legend,
  LegendItem,
  LegendMarker,
  LegendLabel,
  LegendValue,
} from "./legend";
import type { LegendItemData } from "./legend/legend-context";

// ---------------------------------------------------------------------------
// Semantic Status Color Palette matching DNS Threat Detection tokens
// ---------------------------------------------------------------------------
export const VERDICT_COLORS = {
  clean: "#10B981", // Emerald 500
  malicious: "#EF4444", // Red 500
  reviewNeeded: "#F59E0B", // Amber 500
  unknown: "#64748B", // Slate 500
} as const;

export interface VerdictDistributionChartProps {
  /** Count of benign/clean DNS queries */
  clean: number;
  /** Count of malicious/threat DNS queries */
  malicious: number;
  /** Count of DNS queries requiring analyst review */
  reviewNeeded: number;
  /** Count of unclassified/unknown DNS queries */
  unknown: number;
  /** Loading indicator for initial skeleton presentation */
  loading?: boolean;
  /** Optional container class name */
  className?: string;
}

/**
 * Stable loading skeleton for the donut chart and legend
 */
const VerdictChartSkeleton: React.FC<{ className?: string }> = ({ className }) => (
  <div
    className={cn(
      "flex-1 flex flex-col sm:flex-row items-center justify-center gap-8 py-2 animate-pulse select-none",
      className
    )}
  >
    {/* Donut ring skeleton */}
    <div className="relative w-[260px] h-[260px] flex items-center justify-center shrink-0">
      <div className="w-[240px] h-[240px] rounded-full border-[32px] border-neutral-200 dark:border-neutral-800" />
      <div className="absolute flex flex-col items-center justify-center text-center">
        <div className="h-6 w-16 bg-neutral-200 dark:bg-neutral-800 rounded mb-1.5" />
        <div className="h-3.5 w-12 bg-neutral-200 dark:bg-neutral-800 rounded" />
      </div>
    </div>

    {/* Legend rows skeleton */}
    <div className="flex flex-col gap-2.5 w-full sm:w-64">
      {[1, 2, 3, 4].map((i) => (
        <div key={i} className="flex items-center justify-between py-1.5 px-2.5">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-neutral-200 dark:bg-neutral-800 shrink-0" />
            <div className="h-3.5 w-20 bg-neutral-200 dark:bg-neutral-800 rounded" />
          </div>
          <div className="h-3.5 w-16 bg-neutral-200 dark:bg-neutral-800 rounded" />
        </div>
      ))}
    </div>
  </div>
);

/**
 * Reusable Verdict Distribution Donut Chart using the official Bklit UI Chart components.
 * Coordinates hover interactions between the donut slices, center counter, and legend.
 */
export const VerdictDistributionChart: React.FC<VerdictDistributionChartProps> = React.memo(
  function VerdictDistributionChart({
    clean,
    malicious,
    reviewNeeded,
    unknown,
    loading = false,
    className = "",
  }) {
    const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

    const total = useMemo(
      () => clean + malicious + reviewNeeded + unknown,
      [clean, malicious, reviewNeeded, unknown]
    );

    // Bklit PieData array matching the 4 semantic verdict categories
    const pieData = useMemo<PieData[]>(
      () => [
        { label: "Clean", value: clean, color: VERDICT_COLORS.clean },
        { label: "Malicious", value: malicious, color: VERDICT_COLORS.malicious },
        { label: "Review Needed", value: reviewNeeded, color: VERDICT_COLORS.reviewNeeded },
        { label: "Unknown", value: unknown, color: VERDICT_COLORS.unknown },
      ],
      [clean, malicious, reviewNeeded, unknown]
    );

    // Composable Legend items with max value for percentage calculation
    const legendItems = useMemo<LegendItemData[]>(
      () => [
        {
          label: "Clean",
          value: clean,
          color: VERDICT_COLORS.clean,
          maxValue: total > 0 ? total : 1,
        },
        {
          label: "Malicious",
          value: malicious,
          color: VERDICT_COLORS.malicious,
          maxValue: total > 0 ? total : 1,
        },
        {
          label: "Review Needed",
          value: reviewNeeded,
          color: VERDICT_COLORS.reviewNeeded,
          maxValue: total > 0 ? total : 1,
        },
        {
          label: "Unknown",
          value: unknown,
          color: VERDICT_COLORS.unknown,
          maxValue: total > 0 ? total : 1,
        },
      ],
      [clean, malicious, reviewNeeded, unknown, total]
    );

    // Initial loading state before any data has arrived
    if (loading && total === 0) {
      return <VerdictChartSkeleton className={className} />;
    }

    // Zero data empty state: Avoid rendering a glitched or misleading 0-donut
    if (total === 0) {
      return (
        <div
          className={cn(
            "flex-1 flex flex-col items-center justify-center py-10 text-center select-none",
            className
          )}
        >
          <p className="text-[13px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">
            No query verdict data
          </p>
          <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mt-0.5 max-w-[240px]">
            No DNS queries were observed for this time range.
          </p>
        </div>
      );
    }

    return (
      <div
        className={cn(
          "flex-1 flex flex-col sm:flex-row items-center justify-center gap-8 py-2 select-none",
          className
        )}
      >
        {/* Left: Bklit Donut Chart with dynamic center display */}
        <div className="shrink-0 flex items-center justify-center">
          <PieChart
            data={pieData}
            size={260}
            innerRadius={80}
            padAngle={0.02}
            cornerRadius={3}
            hoverOffset={8}
            hoveredIndex={hoveredIndex}
            onHoverChange={setHoveredIndex}
          >
            {pieData.map((slice, index) => (
              <PieSlice
                key={slice.label}
                index={index}
                hoverEffect="translate"
                hoverOffset={8}
                showGlow={false}
              />
            ))}
            <PieCenter
              defaultLabel="Total Queries"
              valueClassName="text-2xl sm:text-3xl font-bold font-mono tracking-tight text-[#1A1A1A] dark:text-[#F3F4F6] tabular-nums leading-none"
              labelClassName="text-xs font-medium text-[#6B6B6B] dark:text-[#9CA3AF] mt-1.5 truncate max-w-full leading-tight"
            />
          </PieChart>
        </div>

        {/* Right: Coordinated Composable Legend with counts and percentages */}
        <div className="w-full sm:w-64">
          <Legend
            items={legendItems}
            hoveredIndex={hoveredIndex}
            onHoverChange={setHoveredIndex}
            className="gap-2"
          >
            <LegendItem className="flex items-center justify-between text-xs py-1.5 px-2.5 rounded-[6px] hover:bg-neutral-100 dark:hover:bg-[#161F33] transition-colors cursor-pointer">
              <div className="flex items-center gap-2 min-w-0">
                <LegendMarker className="w-2.5 h-2.5 shrink-0" />
                <LegendLabel className="font-medium text-[#1A1A1A] dark:text-[#F3F4F6] truncate text-xs" />
              </div>
              <LegendValue
                showPercentage
                className="font-mono text-[#6B6B6B] dark:text-[#9CA3AF] tabular-nums text-xs"
                percentageClassName="text-[11px] opacity-75 tabular-nums ml-1"
                formatValue={(v) => v.toLocaleString()}
                formatPercentage={(p) => `(${total > 0 ? p.toFixed(1) : "0.0"}%)`}
              />
            </LegendItem>
          </Legend>
        </div>
      </div>
    );
  }
);

VerdictDistributionChart.displayName = "VerdictDistributionChart";

export default VerdictDistributionChart;
