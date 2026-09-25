"use client";

import React from "react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis as RechartsXAxis,
  YAxis as RechartsYAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Cell,
  PieChart as RechartsPieChart,
  Pie,
} from "recharts";
import { Clock, Activity } from "lucide-react";
import { DashboardChartConfig } from "@/types/chart-config";
import { DashboardBundleData } from "@/types/api";
import { ChartMenu } from "@/components/dashboard/ChartMenu";
import {
  CandlestickChart,
  Candlestick,
  ChartTooltip as CandlestickTooltip,
  CandlestickTooltipContent,
  XAxis as CandleXAxis,
} from "@/components/charts/CandlestickChart";
import {
  DNSDetectionBarChart,
  DailyDNSQueryData,
  buildDailyDNSQueryTimeline,
  getDaysCountFromRange,
} from "@/components/charts/DNSDetectionBarChart";
import { DNSQueriesOverTimeChart } from "@/components/charts/DNSQueriesOverTimeChart";
import { buildThreatOHLC } from "@/components/dashboard/CandlestickThreatCard";
import { cn } from "@/lib/utils";

export interface DynamicChartCardProps {
  config: DashboardChartConfig;
  data: DashboardBundleData | null;
  loading?: boolean;
  globalTimeRange?: string;
  onConfigure: () => void;
  onDuplicate: () => void;
  onRemove: () => void;
  onTimeRangeChange: (mode: "global" | "custom", customRange?: string) => void;
  className?: string;
}

export const DynamicChartCard: React.FC<DynamicChartCardProps> = ({
  config,
  data,
  loading = false,
  globalTimeRange = "24h",
  onConfigure,
  onDuplicate,
  onRemove,
  onTimeRangeChange,
  className,
}) => {
  const isCustomTime = config.timeRange.mode === "custom";
  const activeTimeLabel = isCustomTime ? config.timeRange.customRange : globalTimeRange;

  // Grid column span
  const colSpanClass = config.gridSpan === "full" ? "col-span-1 lg:col-span-2" : "col-span-1";

  // Render chart content dynamically based on chartType
  const renderChartBody = () => {
    if (loading) {
      return (
        <div className="flex-1 w-full flex items-center justify-center min-h-[220px]">
          <div className="flex items-center gap-2 text-xs text-[#9C9C9C] dark:text-[#6B7280]">
            <Activity className="w-4 h-4 animate-spin text-[#2F6FED]" />
            <span>Loading telemetry...</span>
          </div>
        </div>
      );
    }

    switch (config.chartType) {
      case "depth-bar":
      case "bar": {
        const rawTimeseries = data?.timeseries || [];
        const days = getDaysCountFromRange(
          config.timeRange?.mode === "custom"
            ? config.timeRange.customRange
            : globalTimeRange
        );
        const depthData: DailyDNSQueryData[] = buildDailyDNSQueryTimeline(rawTimeseries, days);

        return (
          <div className="w-full">
            <DNSDetectionBarChart
              title=""
              description=""
              data={depthData}
              daysCount={days}
              isLoading={loading}
              showSummaryBadges={false}
              aspectRatio="2.4 / 1"
              className="border-0 bg-transparent p-0 shadow-none dark:bg-transparent"
            />
          </div>
        );
      }

      case "timeseries": {
        return (
          <div className="w-full">
            <DNSQueriesOverTimeChart
              timeseries={data?.timeseries}
              isLoading={loading}
              height={360}
            />
          </div>
        );
      }

      case "donut": {
        const totalQ = data?.summary?.total_queries || 0;
        const totalThreats = data?.summary?.total_threats || 0;
        const cleanQ = Math.max(0, totalQ - totalThreats);

        const donutData = totalQ > 0 ? [
          {
            name: "Clean / Benign",
            value: cleanQ,
            color: "#10B981",
            pct: `${((cleanQ / totalQ) * 100).toFixed(1)}%`
          },
          {
            name: "Malicious / Threats",
            value: totalThreats,
            color: "#EF4444",
            pct: `${((totalThreats / totalQ) * 100).toFixed(1)}%`
          },
        ] : [
          { name: "No Activity", value: 1, color: "#6B7280", pct: "0%" }
        ];

        const displayTotal = totalQ >= 1_000_000
          ? `${(totalQ / 1_000_000).toFixed(1)}M`
          : totalQ >= 1_000
          ? `${(totalQ / 1_000).toFixed(1)}k`
          : totalQ.toString();

        return (
          <div className="flex-1 w-full flex flex-col justify-center">
            <div className="w-full min-h-[190px] relative flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <RechartsPieChart>
                  <Pie
                    data={donutData}
                    cx="50%"
                    cy="50%"
                    innerRadius={52}
                    outerRadius={76}
                    paddingAngle={3}
                    dataKey="value"
                    stroke="transparent"
                  >
                    {donutData.map((entry, idx) => (
                      <Cell key={`donut-${idx}`} fill={entry.color} />
                    ))}
                  </Pie>
                </RechartsPieChart>
              </ResponsiveContainer>

              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-[15px] font-bold text-[#1A1A1A] dark:text-[#F3F4F6] font-mono leading-none">
                  {displayTotal}
                </span>
                <span className="text-[9px] uppercase tracking-wider text-[#9C9C9C] dark:text-[#6B7280] font-medium mt-0.5">
                  Queries
                </span>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF] pt-1">
              {donutData.map((d) => (
                <div key={d.name} className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: d.color }} />
                  <span className="font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">{d.name}</span>
                  <span className="font-mono text-[10px] text-[#9C9C9C] dark:text-[#6B7280]">({d.pct})</span>
                </div>
              ))}
            </div>
          </div>
        );
      }

      case "candlestick": {
        const ohlcData = buildThreatOHLC(data?.timeseries);
        return (
          <div className="flex-1 w-full relative flex items-center justify-center min-h-[240px]">
            <CandlestickChart
              candleWidth={8}
              data={ohlcData}
              margin={{ top: 8, right: 8, bottom: 36, left: 8 }}
              style={{ height: 260 }}
            >
              <Candlestick
                negativeFill="var(--color-red-500)"
                positiveFill="var(--color-emerald-500)"
              />
              <CandlestickTooltip content={CandlestickTooltipContent} />
              <CandleXAxis />
            </CandlestickChart>
          </div>
        );
      }

      case "stat": {
        const totalQ = data?.summary?.total_queries || 0;
        const numVal = totalQ >= 1_000_000
          ? `${(totalQ / 1_000_000).toFixed(1)}M`
          : totalQ >= 1_000
          ? `${(totalQ / 1_000).toFixed(1)}k`
          : totalQ.toString();
        return (
          <div className="flex-1 w-full flex flex-col justify-center items-center py-6">
            <span className="text-[42px] font-bold text-[#1A1A1A] dark:text-[#F3F4F6] font-mono tracking-tight">
              {numVal}
            </span>
            <span className="text-[13px] text-[#6B6B6B] dark:text-[#9CA3AF] mt-1">
              {config.metric} • Aggregation: {config.aggregation || "count"}
            </span>
          </div>
        );
      }

      case "toplist": {
        const topList = (data?.top_domains || []).slice(0, 5);
        return (
          <div className="flex-1 w-full overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <thead>
                <tr className="border-b border-[#EBEBEB] dark:border-[#1E283D] text-[#6B6B6B] dark:text-[#9CA3AF]">
                  <th className="pb-2">Target</th>
                  <th className="pb-2 text-right">Volume</th>
                  <th className="pb-2 text-center">Verdict</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#EBEBEB]/70 dark:divide-[#1E283D]/70 font-mono">
                {topList.map((item, idx) => (
                  <tr key={item.domain || idx} className="hover:bg-neutral-50 dark:hover:bg-[#1C2438]/50">
                    <td className="py-2 text-[#1A1A1A] dark:text-[#F3F4F6] truncate max-w-[200px]">
                      {item.domain}
                    </td>
                    <td className="py-2 text-right text-[#1A1A1A] dark:text-[#F3F4F6]">
                      {item.query_count.toLocaleString()}
                    </td>
                    <td className="py-2 text-center text-[11px] font-sans">
                      <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                        {item.label}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      }

      default: {
        return (
          <div className="relative w-full flex-1 min-h-[220px] rounded-[8px] bg-neutral-50/50 dark:bg-[#0E1320]/60 border border-[#EBEBEB] dark:border-[#1E283D] flex flex-col justify-between p-4 overflow-hidden">
            <div className="absolute inset-0 p-4 flex flex-col justify-between pointer-events-none opacity-40">
              <div className="border-b border-neutral-200 dark:border-neutral-800 w-full" />
              <div className="border-b border-neutral-200 dark:border-neutral-800 w-full" />
              <div className="border-b border-neutral-200 dark:border-neutral-800 w-full" />
            </div>
            <div className="relative flex-1 w-full flex items-center justify-center pointer-events-none">
              <span className="text-[12px] text-[#9C9C9C] dark:text-[#6B7280]">
                No data available for selected range
              </span>
            </div>
          </div>
        );
      }
    }
  };

  const isLarge = config.gridSpan === "full" || config.chartType === "timeseries";

  return (
    <div
      className={cn(
        "flex flex-col justify-between rounded-[12px] p-5",
        isLarge ? "min-h-[480px]" : "min-h-[340px]",
        "bg-white dark:bg-[#121826]",
        "border border-[#EBEBEB] dark:border-[#1E283D]",
        "shadow-2xs select-none",
        colSpanClass,
        className
      )}
    >
      {/* Card Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h2 className="text-[16px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em] truncate">
              {config.title}
            </h2>
            {isCustomTime && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-[#2F6FED]/10 text-[#2F6FED] border border-[#2F6FED]/20">
                <Clock className="w-2.5 h-2.5" />
                {config.timeRange.customRange}
              </span>
            )}
          </div>
          {config.subtitle && (
            <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mt-0.5 truncate">
              {config.subtitle}
            </p>
          )}
        </div>

        {/* Action Header Menu */}
        <div className="flex items-center gap-1 self-end sm:self-auto">
          <ChartMenu
            timeRange={config.timeRange}
            onTimeRangeChange={onTimeRangeChange}
            onConfigure={onConfigure}
            onDuplicate={onDuplicate}
            onRemove={onRemove}
          />
        </div>
      </div>

      {/* Dynamic Visualization Canvas */}
      {renderChartBody()}

      {/* Card Footer Summary */}
      <div className="mt-3 pt-2.5 border-t border-[#EBEBEB] dark:border-[#1E283D] flex items-center justify-between text-[11px] text-[#9C9C9C] dark:text-[#6B7280]">
        <span>
          Dataset: <strong>{config.dataset}</strong>
        </span>
        <span className="font-mono">
          {isCustomTime ? `Custom: ${config.timeRange.customRange}` : "Global time range"}
        </span>
      </div>
    </div>
  );
};

export default DynamicChartCard;
