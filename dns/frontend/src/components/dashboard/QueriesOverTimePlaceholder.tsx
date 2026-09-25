"use client";

import React, { useState } from "react";
import { cn } from "@/lib/utils";

export interface QueriesOverTimePlaceholderProps {
  totalQueries?: number | string;
  threatQueries?: number | string;
  className?: string;
}

export const QueriesOverTimePlaceholder: React.FC<QueriesOverTimePlaceholderProps> = ({
  totalQueries = "12.8M",
  threatQueries = "24,891",
  className,
}) => {
  const [selectedInterval, setSelectedInterval] = useState("1h");

  const intervals = ["5m", "15m", "1h", "6h", "24h"];

  return (
    <div
      className={cn(
        "flex flex-col rounded-[12px] p-5",
        "bg-white dark:bg-[#121826]",
        "border border-[#EBEBEB] dark:border-[#1E283D]",
        "shadow-2xs select-none",
        className
      )}
    >
      {/* Card Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h2 className="text-[16px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em]">
              Queries Over Time
            </h2>
            <span className="flex items-center gap-1 text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              Live
            </span>
          </div>
          <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mt-0.5">
            DNS query and threat activity over time
          </p>
        </div>

        {/* Header Right Actions */}
        <div className="flex items-center gap-3 self-end sm:self-auto">
          {/* Legend Badges */}
          <div className="hidden md:flex items-center gap-3 text-[12px]">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-[#2F6FED]" />
              <span className="text-[#1A1A1A] dark:text-[#F3F4F6] font-medium text-[12px]">
                Total Queries <span className="font-mono text-muted-foreground text-[11px]">({totalQueries})</span>
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-red-500" />
              <span className="text-[#1A1A1A] dark:text-[#F3F4F6] font-medium text-[12px]">
                Threat Queries <span className="font-mono text-muted-foreground text-[11px]">({threatQueries})</span>
              </span>
            </div>
          </div>

          {/* Functional Interval Selector Tabs */}
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

      {/* Clean Structured Chart Visualization Area */}
      <div className="relative w-full h-[240px] sm:h-[260px] rounded-[8px] bg-neutral-50/50 dark:bg-[#0E1320]/60 border border-[#EBEBEB] dark:border-[#1E283D] flex flex-col justify-between p-4 overflow-hidden">
        {/* Background Grid Lines */}
        <div className="absolute inset-0 p-4 flex flex-col justify-between pointer-events-none opacity-40">
          <div className="border-b border-neutral-200 dark:border-neutral-800 w-full" />
          <div className="border-b border-neutral-200 dark:border-neutral-800 w-full" />
          <div className="border-b border-neutral-200 dark:border-neutral-800 w-full" />
          <div className="border-b border-neutral-200 dark:border-neutral-800 w-full" />
        </div>

        {/* Chart Telemetry Waveform */}
        <div className="relative flex-1 w-full flex items-center justify-center">
          <svg
            className="w-full h-full text-[#2F6FED]/20 dark:text-[#2F6FED]/15"
            preserveAspectRatio="none"
            viewBox="0 0 800 200"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <defs>
              <linearGradient id="queriesGradClean" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#2F6FED" stopOpacity="0.22" />
                <stop offset="100%" stopColor="#2F6FED" stopOpacity="0.0" />
              </linearGradient>
            </defs>
            <path
              d="M0 150 Q 100 70, 200 120 T 400 50 T 600 100 T 800 35 L 800 200 L 0 200 Z"
              fill="url(#queriesGradClean)"
            />
            <path
              d="M0 150 Q 100 70, 200 120 T 400 50 T 600 100 T 800 35"
              stroke="#2F6FED"
              strokeWidth="2"
              strokeLinecap="round"
            />
            <path
              d="M0 185 Q 150 180, 300 165 T 500 135 T 700 170 T 800 155"
              stroke="#EF4444"
              strokeWidth="1.5"
              strokeLinecap="round"
            />
          </svg>
        </div>

        {/* X-Axis Timeline Footer */}
        <div className="relative z-10 pt-2 flex items-center justify-between text-[11px] font-mono text-[#9C9C9C] dark:text-[#6B7280]">
          <span>00:00</span>
          <span>04:00</span>
          <span>08:00</span>
          <span>12:00</span>
          <span>16:00</span>
          <span>20:00</span>
          <span className="text-[#2F6FED] font-semibold">Live</span>
        </div>
      </div>
    </div>
  );
};

export default QueriesOverTimePlaceholder;
