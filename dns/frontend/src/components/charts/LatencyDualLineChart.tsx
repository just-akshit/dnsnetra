"use client";

import React from "react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from "recharts";
import { cn } from "@/lib/utils";

export interface LatencyPoint {
  time: string;
  p50: number;
  p90?: number;
  p99: number;
  [key: string]: any;
}

export interface LatencyDualLineChartProps {
  data: LatencyPoint[];
  height?: number;
  unit?: string;
  showP90?: boolean;
  className?: string;
}

export const LatencyDualLineChart: React.FC<LatencyDualLineChartProps> = ({
  data = [],
  height = 320,
  unit = "μs",
  showP90 = false,
  className = "",
}) => {
  return (
    <div className={cn("w-full relative", className)} style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart
          data={data}
          margin={{ top: 10, right: 10, left: -10, bottom: 0 }}
        >
          <CartesianGrid
            strokeDasharray="3 3"
            stroke="#EFEFEF"
            className="dark:stroke-[#1E283D]"
            vertical={false}
          />
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
            tickFormatter={(val) => `${val} ${unit}`}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "#FFFFFF",
              borderColor: "#EBEBEB",
              borderRadius: "6px",
              fontSize: "12px",
              color: "#1A1A1A",
              boxShadow: "0 4px 12px rgba(0,0,0,0.08)",
            }}
            formatter={(val: any, name: any) => [`${val} ${unit}`, name]}
          />
          <Legend
            iconType="circle"
            wrapperStyle={{ fontSize: "12px", paddingTop: "8px" }}
          />
          <Line
            type="monotone"
            dataKey="p50"
            name="P50"
            stroke="#2F7DE1"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4 }}
          />
          {showP90 && (
            <Line
              type="monotone"
              dataKey="p90"
              name="P90"
              stroke="#8B5CF6"
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4 }}
            />
          )}
          <Line
            type="monotone"
            dataKey="p99"
            name="P99"
            stroke="#F0A73B"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

export default LatencyDualLineChart;
