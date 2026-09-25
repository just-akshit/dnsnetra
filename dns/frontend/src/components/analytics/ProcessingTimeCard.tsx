"use client";

import React from "react";
import { MoreHorizontal } from "lucide-react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import { EmptyStatePill } from "./EmptyStatePill";
import { cn } from "@/lib/utils";

export interface ProcessingPoint {
  time: string;
  p50: number;
  p99: number;
}

export interface ProcessingTimeCardProps {
  data?: ProcessingPoint[];
  p50Value?: number;
  p99Value?: number;
  isEmpty?: boolean;
  className?: string;
}

const DEFAULT_EMPTY_DATA: ProcessingPoint[] = [
  { time: "20:00", p50: 0, p99: 0 },
  { time: "25", p50: 0, p99: 0 },
  { time: "04:00", p50: 0, p99: 0 },
  { time: "08:00", p50: 0, p99: 0 },
  { time: "12:00", p50: 0, p99: 0 },
  { time: "16:00", p50: 0, p99: 0 },
];

export const ProcessingTimeCard: React.FC<ProcessingTimeCardProps> = ({
  data = [],
  p50Value = 0,
  p99Value = 0,
  isEmpty = false,
  className = "",
}) => {
  const chartData = !isEmpty && data.length > 0 ? data : DEFAULT_EMPTY_DATA;
  const isActuallyEmpty = isEmpty || data.length === 0 || (p50Value === 0 && p99Value === 0);

  return (
    <div
      className={cn(
        "bg-[#FFFFFF] dark:bg-[#121826] border border-[#EBEBEB] dark:border-[#1E283D] rounded-[6px] p-6 shadow-xs relative flex flex-col justify-between",
        className
      )}
    >
      {/* 1. Header: Title & Menu */}
      <div className="flex items-center justify-between">
        <h3 className="text-[14px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">
          Processing time P50 vs P99
        </h3>
        <button
          className="text-[#9C9C9C] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6] transition-colors p-1 rounded cursor-pointer"
          title="Chart options"
        >
          <MoreHorizontal className="w-4 h-4" />
        </button>
      </div>

      {/* 2. Legend row with 2 series */}
      <div className="flex items-center gap-5 mt-2 text-[13px]">
        {/* P50 Series */}
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-[#2F7DE1] inline-block shrink-0" />
          <span className="font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">
            P50
          </span>
          <span className="font-normal text-[#6B6B6B] dark:text-[#9CA3AF] tabular-nums">
            {isActuallyEmpty ? "0 μs" : `${p50Value.toLocaleString()} μs`}
          </span>
        </div>

        {/* P99 Series */}
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-[#F0A73B] inline-block shrink-0" />
          <span className="font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">
            P99
          </span>
          <span className="font-normal text-[#6B6B6B] dark:text-[#9CA3AF] tabular-nums">
            {isActuallyEmpty ? "0 μs" : `${p99Value.toLocaleString()} μs`}
          </span>
        </div>
      </div>

      {/* 3. Full-width Dual Line Chart (~460px tall) */}
      <div className="relative w-full h-[460px] mt-6">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart
            data={chartData}
            margin={{ top: 16, right: 16, left: -16, bottom: 8 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#EFEFEF"
              className="dark:stroke-[#1E293B]"
              vertical={false}
            />
            <XAxis
              dataKey="time"
              stroke="#9C9C9C"
              className="text-[12px]"
              tickLine={false}
              axisLine={false}
              dy={10}
            />
            <YAxis
              stroke="#9C9C9C"
              className="text-[12px]"
              tickLine={false}
              axisLine={false}
              domain={isActuallyEmpty ? [0, 1] : ['auto', 'auto']}
              ticks={isActuallyEmpty ? [0, 0.2, 0.4, 0.6, 0.8, 1] : undefined}
              tickFormatter={(val) => (isActuallyEmpty ? `${val}` : `${val} μs`)}
            />
            {!isActuallyEmpty && (
              <Tooltip
                contentStyle={{
                  backgroundColor: "#FFFFFF",
                  borderColor: "#EBEBEB",
                  borderRadius: "6px",
                  fontSize: "12px",
                  color: "#1A1A1A",
                  boxShadow: "0 2px 4px rgba(0,0,0,0.06)",
                }}
                formatter={(val: any) => [`${val} μs`]}
              />
            )}
            <Line
              type="monotone"
              dataKey="p50"
              stroke="#2F7DE1"
              strokeWidth={2}
              dot={false}
              isAnimationActive={!isActuallyEmpty}
              name="P50"
            />
            <Line
              type="monotone"
              dataKey="p99"
              stroke="#F0A73B"
              strokeWidth={2}
              dot={false}
              isAnimationActive={!isActuallyEmpty}
              name="P99"
            />
          </LineChart>
        </ResponsiveContainer>

        {/* Empty state pill overlay over flat line */}
        {isActuallyEmpty && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <EmptyStatePill label="No data" />
          </div>
        )}
      </div>
    </div>
  );
};

export default ProcessingTimeCard;
