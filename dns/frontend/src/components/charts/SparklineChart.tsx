"use client";

import React from "react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  YAxis,
} from "recharts";
import { cn } from "@/lib/utils";

export interface SparklineChartProps {
  data: number[] | { value: number }[];
  color?: string;
  height?: number;
  strokeWidth?: number;
  className?: string;
}

export const SparklineChart: React.FC<SparklineChartProps> = ({
  data = [],
  color = "#2F7DE1",
  height = 40,
  strokeWidth = 1.5,
  className = "",
}) => {
  const chartData = data.map((d) => (typeof d === "number" ? { value: d } : d));

  return (
    <div className={cn("w-full relative", className)} style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={chartData} margin={{ top: 2, bottom: 2, left: 0, right: 0 }}>
          <YAxis domain={['dataMin - 1', 'dataMax + 1']} hide />
          <Line
            type="monotone"
            dataKey="value"
            stroke={color}
            strokeWidth={strokeWidth}
            dot={false}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

export default SparklineChart;
