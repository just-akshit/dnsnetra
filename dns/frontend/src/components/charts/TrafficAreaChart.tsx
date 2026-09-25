"use client";

import React from "react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import { cn } from "@/lib/utils";

export interface TrafficAreaPoint {
  time: string;
  total: number;
  clean?: number;
  threats?: number;
  suspicious?: number;
  [key: string]: any;
}

export interface TrafficAreaChartProps {
  data: TrafficAreaPoint[];
  height?: number;
  showGrid?: boolean;
  showTooltip?: boolean;
  gradientId?: string;
  color?: string;
  className?: string;
}

export const TrafficAreaChart: React.FC<TrafficAreaChartProps> = ({
  data = [],
  height = 280,
  showGrid = true,
  showTooltip = true,
  gradientId = "trafficAreaGrad",
  color = "#2F7DE1",
  className = "",
}) => {
  return (
    <div className={cn("w-full relative", className)} style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={data}
          margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
        >
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={color} stopOpacity={0.25} />
              <stop offset="95%" stopColor={color} stopOpacity={0.0} />
            </linearGradient>
            <linearGradient id="threatAreaGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#EF4444" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
            </linearGradient>
          </defs>

          {showGrid && (
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#EFEFEF"
              className="dark:stroke-[#1E283D]"
              vertical={false}
            />
          )}

          <XAxis
            dataKey="time"
            stroke="#9C9C9C"
            className="text-[11px]"
            tickLine={false}
            axisLine={false}
            dy={8}
          />
          <YAxis
            stroke="#9C9C9C"
            className="text-[11px]"
            tickLine={false}
            axisLine={false}
          />

          {showTooltip && (
            <Tooltip
              contentStyle={{
                backgroundColor: "#FFFFFF",
                borderColor: "#EBEBEB",
                borderRadius: "6px",
                fontSize: "12px",
                color: "#1A1A1A",
                boxShadow: "0 4px 12px rgba(0,0,0,0.08)",
              }}
            />
          )}

          <Area
            type="monotone"
            dataKey="total"
            stroke={color}
            strokeWidth={2}
            fillOpacity={1}
            fill={`url(#${gradientId})`}
          />

          {data.some((d) => (d.threats ?? 0) > 0) && (
            <Area
              type="monotone"
              dataKey="threats"
              stroke="#EF4444"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#threatAreaGrad)"
            />
          )}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};

export default TrafficAreaChart;
