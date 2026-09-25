"use client";

import React from "react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from "recharts";
import { cn } from "@/lib/utils";

export interface SeverityItem {
  severity: "critical" | "high" | "medium" | "low" | string;
  count: number;
}

export interface SeverityDistributionChartProps {
  data: SeverityItem[];
  height?: number;
  barSize?: number;
  className?: string;
}

const SEVERITY_CONFIG: Record<string, { label: string; color: string }> = {
  critical: { label: "Critical", color: "#EF4444" },
  high: { label: "High", color: "#F97316" },
  medium: { label: "Medium", color: "#F59E0B" },
  low: { label: "Low", color: "#3B82F6" },
};

export const SeverityDistributionChart: React.FC<SeverityDistributionChartProps> = ({
  data = [],
  height = 180,
  barSize = 24,
  className = "",
}) => {
  const chartData = data.map((d) => ({
    ...d,
    label: SEVERITY_CONFIG[d.severity.toLowerCase()]?.label || d.severity,
    color: SEVERITY_CONFIG[d.severity.toLowerCase()]?.color || "#64748B",
  }));

  return (
    <div className={cn("w-full relative", className)} style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <XAxis
            dataKey="label"
            stroke="#9C9C9C"
            className="text-[11px]"
            tickLine={false}
            axisLine={false}
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
            formatter={(val: any) => [`${val} alerts`, "Incidents"]}
          />
          <Bar dataKey="count" radius={[4, 4, 0, 0]} barSize={barSize}>
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default SeverityDistributionChart;
