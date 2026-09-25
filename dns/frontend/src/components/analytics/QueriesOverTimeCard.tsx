"use client";

import React from "react";
import { MoreHorizontal } from "lucide-react";
import { DNSQueriesOverTimeChart } from "@/components/charts/DNSQueriesOverTimeChart";
import { cn } from "@/lib/utils";

export interface TimeSeriesPoint {
  time: string;
  queries: number;
  threat_queries?: number;
  time_bucket?: string;
  timestamp?: string;
  total_queries?: number;
}

export interface QueriesOverTimeCardProps {
  data?: TimeSeriesPoint[];
  totalValue?: number;
  isEmpty?: boolean;
  className?: string;
}

export const QueriesOverTimeCard: React.FC<QueriesOverTimeCardProps> = ({
  data = [],
  totalValue = 0,
  isEmpty = false,
  className = "",
}) => {
  // Map data to timeseries objects compatible with DNSQueriesOverTimeChart
  const formattedTimeseries = (data || []).map((pt) => ({
    time_bucket: pt.time_bucket || pt.time || pt.timestamp,
    timestamp: pt.timestamp || pt.time,
    total_queries: pt.total_queries ?? pt.queries ?? 0,
    threat_queries: pt.threat_queries ?? 0,
  }));

  return (
    <div
      className={cn(
        "bg-[#FFFFFF] dark:bg-[#121826] border border-[#EBEBEB] dark:border-[#1E283D] rounded-[12px] p-6 shadow-2xs relative flex flex-col justify-between min-h-[460px]",
        className
      )}
    >
      {/* 1. Header: Title & Menu */}
      <div className="flex items-center justify-between mb-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-[16px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em]">
              Queries over time
            </h3>
            <span className="flex items-center gap-1 text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              Live
            </span>
          </div>
          <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mt-0.5">
            DNS query and threat activity across time
          </p>
        </div>

        <button
          className="text-[#9C9C9C] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6] transition-colors p-1.5 rounded cursor-pointer"
          title="Chart options"
        >
          <MoreHorizontal className="w-4 h-4" />
        </button>
      </div>

      {/* 2. Bklit Trio-with-Brush Line Chart */}
      <div className="w-full flex-1 mt-2">
        <DNSQueriesOverTimeChart
          timeseries={formattedTimeseries}
          isLoading={false}
          height={340}
        />
      </div>
    </div>
  );
};

export default QueriesOverTimeCard;
