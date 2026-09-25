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
} from "recharts";
import { cn } from "@/lib/utils";

export interface QueryTimelinePoint {
  time: string;
  queries: number;
  [key: string]: any;
}

export interface QueriesLineChartProps {
  data: QueryTimelinePoint[];
  height?: number;
  color?: string;
  strokeWidth?: number;
  showGrid?: boolean;
  className?: string;
}

export const QueriesLineChart: React.FC<QueriesLineChartProps> = ({
  data = [],
  height = 320,
  color = "#2F7DE1",
  strokeWidth = 2,
  showGrid = true,
  className = "",
}) => {
  return (
    <div className={cn("w-full relative", className)} style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart
          data={data}
          margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
        >
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
          <Tooltip
            contentStyle={{
              backgroundColor: "#FFFFFF",
              borderColor: "#EBEBEB",
              borderRadius: "6px",
              fontSize: "12px",
              color: "#1A1A1A",
              boxShadow: "0 4px 12px rgba(0,0,0,0.08)",
            }}
            formatter={(val: any) => [`${val} queries`, "DNS Traffic"]}
          />
          <Line
            type="monotone"
            dataKey="queries"
            stroke={color}
            strokeWidth={strokeWidth}
            dot={false}
            activeDot={{ r: 4, stroke: color, strokeWidth: 2, fill: "#FFFFFF" }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

export default QueriesLineChart;
