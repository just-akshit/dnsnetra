"use client";

import React from "react";
import { MoreHorizontal } from "lucide-react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  YAxis,
} from "recharts";
import { EmptyStatePill } from "./EmptyStatePill";
import { cn } from "@/lib/utils";

export interface SparklinePoint {
  value: number;
}

export interface StatTriptychProps {
  totalQueries?: number;
  queriesSparkline?: SparklinePoint[];
  avgProcessingTime?: number; // in microseconds
  processingSparkline?: SparklinePoint[];
  cacheHitRate?: number; // in percentage, e.g. 94.2 or 0
  cacheSparkline?: SparklinePoint[];
  isEmpty?: boolean;
  className?: string;
}

export const StatTriptych: React.FC<StatTriptychProps> = ({
  totalQueries = 0,
  queriesSparkline = [],
  avgProcessingTime = 0,
  processingSparkline = [],
  cacheHitRate = 0,
  cacheSparkline = [],
  isEmpty = false,
  className = "",
}) => {
  const hasQueryData = !isEmpty && queriesSparkline.length > 0 && totalQueries > 0;
  const hasProcessingData = !isEmpty && processingSparkline.length > 0 && avgProcessingTime > 0;
  const hasCacheData = !isEmpty && cacheSparkline.length > 0 && cacheHitRate > 0;

  // Flat zero placeholder data when empty
  const flatLineData = [
    { value: 0 },
    { value: 0 },
    { value: 0 },
    { value: 0 },
    { value: 0 },
    { value: 0 },
    { value: 0 },
    { value: 0 },
  ];

  return (
    <div
      className={cn(
        "bg-[#FFFFFF] dark:bg-[#121826] border border-[#EBEBEB] dark:border-[#1E283D] rounded-[6px] grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-[#EBEBEB] dark:divide-[#1E283D] shadow-xs overflow-hidden",
        className
      )}
    >
      {/* Cell 1: Total Queries */}
      <div className="p-6 flex flex-col justify-between min-h-[190px]">
        <div>
          <div className="flex items-center justify-between">
            <span className="text-[14px] font-medium text-[#6B6B6B] dark:text-[#9CA3AF]">
              Total Queries
            </span>
            <button
              className="text-[#9C9C9C] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6] transition-colors p-1 rounded cursor-pointer"
              title="Card options"
            >
              <MoreHorizontal className="w-4 h-4" />
            </button>
          </div>

          <div className="mt-2 flex items-baseline">
            <span className="text-[36px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tabular-nums tracking-tight">
              {isEmpty ? "0" : totalQueries.toLocaleString()}
            </span>
          </div>
        </div>

        {/* Sparkline area */}
        <div className="relative h-[56px] w-full mt-4 flex items-center justify-center">
          {hasQueryData ? (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={queriesSparkline} margin={{ top: 4, bottom: 4, left: 0, right: 0 }}>
                <YAxis domain={['dataMin - 1', 'dataMax + 1']} hide />
                <Line
                  type="monotone"
                  dataKey="value"
                  stroke="#2F7DE1"
                  strokeWidth={2}
                  dot={false}
                  isAnimationActive={false}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={flatLineData} margin={{ top: 28, bottom: 28, left: 0, right: 0 }}>
                  <YAxis domain={[-1, 1]} hide />
                  <Line
                    type="linear"
                    dataKey="value"
                    stroke="#EBEBEB"
                    strokeWidth={1.5}
                    dot={false}
                    isAnimationActive={false}
                  />
                </LineChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <EmptyStatePill label="No data" />
              </div>
            </>
          )}
        </div>
      </div>

      {/* Cell 2: Avg Processing Time */}
      <div className="p-6 flex flex-col justify-between min-h-[190px]">
        <div>
          <div className="flex items-center justify-between">
            <span className="text-[14px] font-medium text-[#6B6B6B] dark:text-[#9CA3AF]">
              Avg Processing Time
            </span>
            <button
              className="text-[#9C9C9C] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6] transition-colors p-1 rounded cursor-pointer"
              title="Card options"
            >
              <MoreHorizontal className="w-4 h-4" />
            </button>
          </div>

          <div className="mt-2 flex items-baseline gap-1">
            <span className="text-[36px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tabular-nums tracking-tight">
              {isEmpty ? "0" : avgProcessingTime.toLocaleString()}
            </span>
            <span className="text-[28px] font-normal text-[#6B6B6B] dark:text-[#9CA3AF]">
              μs
            </span>
          </div>
        </div>

        {/* Sparkline area */}
        <div className="relative h-[56px] w-full mt-4 flex items-center justify-center">
          {hasProcessingData ? (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={processingSparkline} margin={{ top: 4, bottom: 4, left: 0, right: 0 }}>
                <YAxis domain={['dataMin - 1', 'dataMax + 1']} hide />
                <Line
                  type="monotone"
                  dataKey="value"
                  stroke="#2F7DE1"
                  strokeWidth={2}
                  dot={false}
                  isAnimationActive={false}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={flatLineData} margin={{ top: 28, bottom: 28, left: 0, right: 0 }}>
                  <YAxis domain={[-1, 1]} hide />
                  <Line
                    type="linear"
                    dataKey="value"
                    stroke="#EBEBEB"
                    strokeWidth={1.5}
                    dot={false}
                    isAnimationActive={false}
                  />
                </LineChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <EmptyStatePill label="No data" />
              </div>
            </>
          )}
        </div>
      </div>

      {/* Cell 3: Cache Hit Rate */}
      <div className="p-6 flex flex-col justify-between min-h-[190px]">
        <div>
          <div className="flex items-center justify-between">
            <span className="text-[14px] font-medium text-[#6B6B6B] dark:text-[#9CA3AF]">
              Cache Hit Rate
            </span>
            <button
              className="text-[#9C9C9C] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6] transition-colors p-1 rounded cursor-pointer"
              title="Card options"
            >
              <MoreHorizontal className="w-4 h-4" />
            </button>
          </div>

          <div className="mt-2 flex items-baseline gap-0.5">
            <span className="text-[36px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tabular-nums tracking-tight">
              {isEmpty ? "0.00" : cacheHitRate.toFixed(2)}
            </span>
            <span className="text-[28px] font-normal text-[#6B6B6B] dark:text-[#9CA3AF]">
              %
            </span>
          </div>
        </div>

        {/* Sparkline area */}
        <div className="relative h-[56px] w-full mt-4 flex items-center justify-center">
          {hasCacheData ? (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={cacheSparkline} margin={{ top: 4, bottom: 4, left: 0, right: 0 }}>
                <YAxis domain={['dataMin - 1', 'dataMax + 1']} hide />
                <Line
                  type="monotone"
                  dataKey="value"
                  stroke="#2F7DE1"
                  strokeWidth={2}
                  dot={false}
                  isAnimationActive={false}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={flatLineData} margin={{ top: 28, bottom: 28, left: 0, right: 0 }}>
                  <YAxis domain={[-1, 1]} hide />
                  <Line
                    type="linear"
                    dataKey="value"
                    stroke="#EBEBEB"
                    strokeWidth={1.5}
                    dot={false}
                    isAnimationActive={false}
                  />
                </LineChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <EmptyStatePill label="No data" />
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default StatTriptych;
