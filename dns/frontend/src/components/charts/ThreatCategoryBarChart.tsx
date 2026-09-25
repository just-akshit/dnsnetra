"use client";

import React from "react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
} from "recharts";
import { ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

export interface ThreatCategoryItem {
  category: string;
  count: number;
  color?: string;
  severity?: "critical" | "high" | "medium" | "low";
}

export interface ThreatCategoryBarChartProps {
  data: ThreatCategoryItem[];
  layout?: "horizontal" | "vertical";
  height?: number;
  barSize?: number;
  yAxisWidth?: number;
  tooltipLabel?: string;
  onBarClick?: (item: ThreatCategoryItem) => void;
  className?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#EF4444",
  high: "#F97316",
  medium: "#F59E0B",
  low: "#3B82F6",
};

export const ThreatCategoryBarChart: React.FC<ThreatCategoryBarChartProps> = ({
  data = [],
  layout = "vertical",
  height = 280,
  barSize = 16,
  yAxisWidth = 140,
  tooltipLabel = "queries",
  onBarClick,
  className = "",
}) => {
  if (data.length === 0) {
    return (
      <div
        className={cn(
          "w-full flex flex-col items-center justify-center py-10 text-center select-none",
          className,
        )}
        style={{ height }}
      >
        <ShieldCheck className="h-8 w-8 text-emerald-500 mb-2" />
        <p className="text-[13px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">
          No threat domains detected
        </p>
        <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mt-0.5 max-w-[260px]">
          All observed queries in this time window resolved to benign destinations.
        </p>
      </div>
    );
  }

  return (
    <div className={cn("w-full relative", className)} style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        {layout === "vertical" ? (
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 10, right: 20, left: 10, bottom: 0 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#EFEFEF"
              className="dark:stroke-[#1E283D]"
              horizontal={false}
            />
            <XAxis
              type="number"
              stroke="#9C9C9C"
              className="text-[11px] font-mono"
              tickLine={false}
              axisLine={false}
              allowDecimals={false}
            />
            <YAxis
              type="category"
              dataKey="category"
              stroke="#9C9C9C"
              tickLine={false}
              axisLine={false}
              width={yAxisWidth}
              tick={(props: any) => {
                const { x, y, payload } = props;
                const val = String(payload?.value || "");
                const displayVal =
                  val.length > 22 ? val.slice(0, 20) + "…" : val;
                return (
                  <text
                    x={x}
                    y={y}
                    dy={4}
                    textAnchor="end"
                    fill="#9C9C9C"
                    className="text-[11px] font-mono"
                  >
                    <title>{val}</title>
                    {displayVal}
                  </text>
                );
              }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "var(--card, #FFFFFF)",
                borderColor: "var(--border, #EBEBEB)",
                borderRadius: "6px",
                fontSize: "12px",
                color: "var(--foreground, #1A1A1A)",
                boxShadow: "0 4px 12px rgba(0,0,0,0.08)",
              }}
              formatter={(val: any) => [`${val} ${tooltipLabel}`, "Volume"]}
            />
            <Bar
              dataKey="count"
              radius={[0, 4, 4, 0]}
              barSize={barSize}
              onClick={
                onBarClick ? (entry: any) => onBarClick(entry) : undefined
              }
              className={onBarClick ? "cursor-pointer" : undefined}
            >
              {data.map((entry, index) => {
                const color =
                  entry.color ||
                  (entry.severity
                    ? SEVERITY_COLORS[entry.severity]
                    : undefined) ||
                  (index === 0
                    ? "#EF4444"
                    : index === 1
                      ? "#F59E0B"
                      : "#2F7DE1");
                return <Cell key={`cell-${index}`} fill={color} />;
              })}
            </Bar>
          </BarChart>
        ) : (
          <BarChart
            data={data}
            margin={{ top: 10, right: 10, left: -20, bottom: 20 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#EFEFEF"
              className="dark:stroke-[#1E283D]"
              vertical={false}
            />
            <XAxis
              dataKey="category"
              stroke="#9C9C9C"
              className="text-[11px]"
              tickLine={false}
              axisLine={false}
              angle={-20}
              textAnchor="end"
            />
            <YAxis
              stroke="#9C9C9C"
              className="text-[11px]"
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "var(--card, #FFFFFF)",
                borderColor: "var(--border, #EBEBEB)",
                borderRadius: "6px",
                fontSize: "12px",
                color: "var(--foreground, #1A1A1A)",
                boxShadow: "0 4px 12px rgba(0,0,0,0.08)",
              }}
              formatter={(val: any) => [`${val} ${tooltipLabel}`, "Count"]}
            />
            <Bar
              dataKey="count"
              radius={[4, 4, 0, 0]}
              barSize={barSize}
              onClick={
                onBarClick ? (entry: any) => onBarClick(entry) : undefined
              }
              className={onBarClick ? "cursor-pointer" : undefined}
            >
              {data.map((entry, index) => {
                const color =
                  entry.color ||
                  (entry.severity
                    ? SEVERITY_COLORS[entry.severity]
                    : undefined) ||
                  (index === 0
                    ? "#EF4444"
                    : index === 1
                      ? "#F59E0B"
                      : "#2F7DE1");
                return <Cell key={`cell-${index}`} fill={color} />;
              })}
            </Bar>
          </BarChart>
        )}
      </ResponsiveContainer>
    </div>
  );
};

export default ThreatCategoryBarChart;
