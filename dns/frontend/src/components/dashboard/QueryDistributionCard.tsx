"use client";

import React from "react";
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from "recharts";
import { PieChart as PieIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export interface QueryDistributionItem {
  name: string;
  value: number;
  color: string;
  pct: string;
}

export interface QueryDistributionCardProps {
  data?: QueryDistributionItem[];
  className?: string;
}

const DEFAULT_DISTRIBUTION: QueryDistributionItem[] = [
  { name: "Benign", value: 11820000, color: "#10B981", pct: "92.1%" },
  { name: "Suspicious", value: 680000, color: "#F59E0B", pct: "5.3%" },
  { name: "Malicious", value: 210000, color: "#EF4444", pct: "1.6%" },
  { name: "Blocked", value: 130000, color: "#8B5CF6", pct: "1.0%" },
];

export const QueryDistributionCard: React.FC<QueryDistributionCardProps> = ({
  data = DEFAULT_DISTRIBUTION,
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
              <PieIcon className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-[15px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em]">
              Query Distribution
            </h2>
          </div>

          <span className="text-[11px] font-mono font-medium px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
            92.1% Clean
          </span>
        </div>

        <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mb-1">
          Queries by classification
        </p>
      </div>

      {/* Donut Chart Area */}
      <div className="flex-1 w-full min-h-[200px] max-h-[215px] relative flex items-center justify-center">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={54}
              outerRadius={80}
              paddingAngle={3}
              dataKey="value"
              stroke="transparent"
            >
              {data.map((entry, index) => (
                <Cell key={`slice-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const d = payload[0].payload as QueryDistributionItem;
                  return (
                    <div className="bg-white dark:bg-[#1C2438] border border-[#EBEBEB] dark:border-[#2D3A54] rounded-[6px] p-2 shadow-md text-xs">
                      <div className="flex items-center gap-1.5">
                        <span
                          className="w-2 h-2 rounded-full"
                          style={{ backgroundColor: d.color }}
                        />
                        <span className="font-semibold text-[#1A1A1A] dark:text-[#F3F4F6]">
                          {d.name}
                        </span>
                      </div>
                      <div className="text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF] font-mono mt-0.5">
                        {d.value.toLocaleString()} queries ({d.pct})
                      </div>
                    </div>
                  );
                }
                return null;
              }}
            />
          </PieChart>
        </ResponsiveContainer>

        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-[15px] font-bold text-[#1A1A1A] dark:text-[#F3F4F6] font-mono leading-none">
            12.8M
          </span>
          <span className="text-[9px] uppercase tracking-wider text-[#9C9C9C] dark:text-[#6B7280] font-medium mt-0.5">
            Total
          </span>
        </div>
      </div>

      {/* Compact Legend Pills */}
      <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF] pt-1">
        {data.map((d) => (
          <div key={d.name} className="flex items-center gap-1.5">
            <span
              className="w-2 h-2 rounded-full shrink-0"
              style={{ backgroundColor: d.color }}
            />
            <span className="font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">{d.name}</span>
            <span className="font-mono text-[10px] text-[#9C9C9C] dark:text-[#6B7280]">
              ({d.pct})
            </span>
          </div>
        ))}
      </div>

      {/* Card Footer Summary */}
      <div className="mt-2 pt-2.5 border-t border-[#EBEBEB] dark:border-[#1E283D] flex items-center justify-between text-[11px] text-[#9C9C9C] dark:text-[#6B7280]">
        <span>Classified: 12.8M</span>
        <span className="font-mono text-emerald-600 dark:text-emerald-400 font-medium">
          Pass Rate: 92.1%
        </span>
      </div>
    </div>
  );
};

export default QueryDistributionCard;
