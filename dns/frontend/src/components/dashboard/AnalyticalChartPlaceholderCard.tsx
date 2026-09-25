"use client";

import React, { useState } from "react";
import { cn } from "@/lib/utils";

export interface AnalyticalChartPlaceholderCardProps {
  title: string;
  subtitle: string;
  intervals?: string[];
  className?: string;
}

export const AnalyticalChartPlaceholderCard: React.FC<AnalyticalChartPlaceholderCardProps> = ({
  title,
  subtitle,
  intervals = ["5m", "15m", "1h", "6h", "24h"],
  className,
}) => {
  const [selectedInterval, setSelectedInterval] = useState("1h");

  return (
    <div
      className={cn(
        "flex flex-col justify-between rounded-[12px] p-5 min-h-[320px] sm:min-h-[340px]",
        "bg-white dark:bg-[#121826]",
        "border border-[#EBEBEB] dark:border-[#1E283D]",
        "shadow-2xs select-none",
        className
      )}
    >
      {/* Card Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div className="min-w-0">
          <h2 className="text-[16px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em]">
            {title}
          </h2>
          <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mt-0.5">
            {subtitle}
          </p>
        </div>

        {/* Functional Interval Selector Tabs */}
        <div className="flex items-center gap-2.5 self-end sm:self-auto">
          <div className="flex items-center bg-[#F2F2F2] dark:bg-[#1C2438] p-0.5 rounded-[6px] border border-[#EBEBEB] dark:border-[#2D3A54] text-[11px]">
            {intervals.map((int) => (
              <button
                key={int}
                type="button"
                onClick={() => setSelectedInterval(int)}
                className={cn(
                  "px-2.5 py-1 rounded-[4px] font-medium transition-colors cursor-pointer",
                  selectedInterval === int
                    ? "bg-white dark:bg-[#121826] text-[#1A1A1A] dark:text-[#F3F4F6] shadow-2xs font-semibold"
                    : "text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                )}
              >
                {int}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Clean Structured Chart Canvas Area */}
      <div className="relative w-full flex-1 min-h-[220px] sm:min-h-[240px] rounded-[8px] bg-neutral-50/50 dark:bg-[#0E1320]/60 border border-[#EBEBEB] dark:border-[#1E283D] flex flex-col justify-between p-4 overflow-hidden">
        {/* Subtle Background Grid Lines */}
        <div className="absolute inset-0 p-4 flex flex-col justify-between pointer-events-none opacity-40">
          <div className="border-b border-neutral-200 dark:border-neutral-800 w-full" />
          <div className="border-b border-neutral-200 dark:border-neutral-800 w-full" />
          <div className="border-b border-neutral-200 dark:border-neutral-800 w-full" />
          <div className="border-b border-neutral-200 dark:border-neutral-800 w-full" />
        </div>

        {/* Minimal empty canvas baseline */}
        <div className="relative flex-1 w-full flex items-center justify-center pointer-events-none">
          <span className="text-[12px] text-[#9C9C9C] dark:text-[#6B7280] font-medium">
            No data available for selected range
          </span>
        </div>

        {/* X-Axis Timeline Footer */}
        <div className="relative z-10 pt-2 flex items-center justify-between text-[11px] font-mono text-[#9C9C9C] dark:text-[#6B7280]">
          <span>00:00</span>
          <span>06:00</span>
          <span>12:00</span>
          <span>18:00</span>
          <span className="text-[#2F6FED] font-semibold">Live</span>
        </div>
      </div>
    </div>
  );
};

export default AnalyticalChartPlaceholderCard;
