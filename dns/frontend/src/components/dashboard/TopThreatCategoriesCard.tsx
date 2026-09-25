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
import { BarChart3 } from "lucide-react";
import { cn } from "@/lib/utils";

export interface ThreatCategoryItem {
  category: string;
  count: number;
  color: string;
  pct: string;
}

export interface TopThreatCategoriesCardProps {
  data?: ThreatCategoryItem[];
  className?: string;
}

const DEFAULT_CATEGORIES: ThreatCategoryItem[] = [
  { category: "Malware", count: 4820, color: "#EF4444", pct: "29.3%" },
  { category: "Phishing", count: 3610, color: "#F97316", pct: "21.9%" },
  { category: "C2", count: 2940, color: "#DC2626", pct: "17.9%" },
  { category: "DGA", count: 2150, color: "#8B5CF6", pct: "13.1%" },
  { category: "Suspicious", count: 1740, color: "#F59E0B", pct: "10.6%" },
  { category: "Policy", count: 1211, color: "#3B82F6", pct: "7.2%" },
];

export const TopThreatCategoriesCard: React.FC<TopThreatCategoriesCardProps> = ({
  data = DEFAULT_CATEGORIES,
  className,
}) => {
  return (
    <div
      className={cn(
        "flex flex-col justify-between rounded-[12px] p-5 h-[380px]",
        "bg-white dark:bg-[#121826]",
        "border border-[#EBEBEB] dark:border-[#1E283D]",
        "shadow-2xs select-none",
        className
      )}
    >
      <div>
        {/* Card Header */}
        <div className="flex items-center justify-between gap-3 mb-1">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-md bg-[#2F6FED]/10 text-[#2F6FED] flex items-center justify-center">
              <BarChart3 className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-[15px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em]">
              Top Threat Categories
            </h2>
          </div>

          <span className="text-[11px] font-mono font-medium px-2 py-0.5 rounded bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20">
            6 Categories
          </span>
        </div>

        <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mb-2">
          Threat activity by category
        </p>
      </div>

      {/* Bar Chart Area */}
      <div className="flex-1 w-full min-h-[235px] max-h-[250px] relative">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={data}
            margin={{ top: 10, right: 10, left: -18, bottom: 0 }}
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
              className="text-[11px] font-sans"
              tickLine={false}
              axisLine={{ stroke: "#E5E7EB" }}
            />
            <YAxis
              stroke="#9C9C9C"
              className="text-[11px] font-mono"
              tickLine={false}
              axisLine={false}
              tickFormatter={(v) => (v >= 1000 ? `${(v / 1000).toFixed(1)}k` : v)}
            />
            <Tooltip
              cursor={{ fill: "rgba(47, 111, 237, 0.06)" }}
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const d = payload[0].payload as ThreatCategoryItem;
                  return (
                    <div className="bg-white dark:bg-[#1C2438] border border-[#EBEBEB] dark:border-[#2D3A54] rounded-[6px] p-2 shadow-md text-xs">
                      <div className="flex items-center gap-1.5">
                        <span
                          className="w-2 h-2 rounded-full"
                          style={{ backgroundColor: d.color }}
                        />
                        <span className="font-semibold text-[#1A1A1A] dark:text-[#F3F4F6]">
                          {d.category}
                        </span>
                      </div>
                      <div className="text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF] font-mono mt-0.5">
                        {d.count.toLocaleString()} threats ({d.pct})
                      </div>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={28}>
              {data.map((entry, index) => (
                <Cell key={`bar-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Card Footer Summary */}
      <div className="mt-2 pt-2.5 border-t border-[#EBEBEB] dark:border-[#1E283D] flex items-center justify-between text-[11px] text-[#9C9C9C] dark:text-[#6B7280]">
        <span>Total categorized: 16,471</span>
        <span className="font-mono text-red-500 dark:text-red-400 font-medium">
          Top: Malware (29.3%)
        </span>
      </div>
    </div>
  );
};

export default TopThreatCategoriesCard;
