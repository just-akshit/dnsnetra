"use client";

import React, { useMemo } from "react";
import { curveCatmullRom } from "@visx/curve";
import {
  LineChart,
  Line,
  XAxis,
  Grid,
  Background,
  ChartTooltip,
  ChartBrush,
  ChartBrushLayout,
} from "@/components/charts";
import { cn } from "@/lib/utils";

export interface IntradayDNSPoint {
  [key: string]: unknown;
  date: Date;
  timeStr: string;
  clean: number;
  suspicious: number;
  malicious: number;
  total: number;
}

export interface DNSQueriesOverTimeChartProps {
  timeseries?: Array<{
    time_bucket?: string;
    total_queries?: number;
    threat_queries?: number;
    timestamp?: string;
    queries?: number;
  }>;
  isLoading?: boolean;
  className?: string;
  height?: number | string;
  preset?: string;
}

const MONTHS = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/**
 * Builds continuous time slots based on the active preset
 * (24h -> hourly, 7d/30d -> daily, 1y -> monthly)
 * and distributes real DNS query telemetry onto those coordinates.
 */
export function buildQueryTimeline(
  rawTimeseries: Array<any> = [],
  preset = "24h",
): IntradayDNSPoint[] {
  if (rawTimeseries && rawTimeseries.length > 0) {
    return rawTimeseries.map((item) => {
      const rawTime = item.time_bucket || item.timestamp || item.bucket_time;
      let d = new Date();
      if (rawTime) {
        const parsed = new Date(String(rawTime).replace(" ", "T"));
        if (!isNaN(parsed.getTime())) d = parsed;
      }

      let timeStr = "";
      if (
        preset === "24h" ||
        preset === "1d" ||
        preset === "15m" ||
        preset === "1h" ||
        preset === "6h"
      ) {
        const h = String(d.getHours()).padStart(2, "0");
        timeStr = `${h}:00`;
      } else if (preset === "7d" || preset === "30d") {
        const month = MONTHS[d.getMonth()];
        const day = String(d.getDate()).padStart(2, "0");
        timeStr = `${month} ${day}`;
      } else if (preset === "1y" || preset === "6mo") {
        timeStr = MONTHS[d.getMonth()];
      } else {
        const month = MONTHS[d.getMonth()];
        const day = String(d.getDate()).padStart(2, "0");
        timeStr = `${month} ${day}`;
      }

      const total = Number(item.total_queries ?? item.queries ?? 0);
      const malicious = Number(
        item.malicious_queries ?? item.threat_queries ?? 0,
      );
      const clean = Math.max(0, total - malicious);

      return {
        date: d,
        timeStr,
        clean,
        suspicious: 0,
        malicious,
        total,
      };
    });
  }

  // Fallback if empty raw timeseries: generate 24 hourly zero-filled slots
  const baseDate = new Date();
  baseDate.setHours(0, 0, 0, 0);
  const slots: IntradayDNSPoint[] = [];
  for (let h = 0; h < 24; h++) {
    const slotDate = new Date(baseDate);
    slotDate.setHours(h, 0, 0, 0);
    const padH = String(h).padStart(2, "0");
    slots.push({
      date: slotDate,
      timeStr: `${padH}:00`,
      clean: 0,
      suspicious: 0,
      malicious: 0,
      total: 0,
    });
  }
  return slots;
}

export const buildIntradayQueryTimeline = buildQueryTimeline;

export const DNSQueriesOverTimeChart: React.FC<DNSQueriesOverTimeChartProps> = ({
  timeseries = [],
  isLoading = false,
  className,
  height = 360,
  preset = "24h",
}) => {
  const chartData = useMemo(() => {
    return buildQueryTimeline(timeseries, preset);
  }, [timeseries, preset]);

  const summary = useMemo(() => {
    let clean = 0;
    let malicious = 0;
    let total = 0;

    for (const pt of chartData) {
      clean += pt.clean;
      malicious += pt.malicious;
      total += pt.total;
    }

    return { clean, malicious, total };
  }, [chartData]);

  // XAxis formatter adapting to preset
  const formatTimeTick = (val: unknown) => {
    const d = val instanceof Date ? val : typeof val === "string" ? new Date(val) : null;
    if (!d || isNaN(d.getTime())) return String(val);

    if (preset === "7d" || preset === "30d") {
      const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
      return `${months[d.getMonth()]} ${d.getDate()}`;
    }
    if (preset === "1y" || preset === "6mo") {
      const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
      return months[d.getMonth()];
    }
    const h = String(d.getHours()).padStart(2, "0");
    const m = String(d.getMinutes()).padStart(2, "0");
    return `${h}:${m}`;
  };

  return (
    <div className={cn("w-full flex flex-col select-none", className)}>
      {/* Top Legend Row - Total, Clean, Malicious ONLY */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 mb-2 border-b border-[#EBEBEB] dark:border-[#1E283D]">
        <div className="flex flex-wrap items-center gap-5 text-[12px]">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#2F6FED] shadow-2xs shrink-0" />
            <span className="font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">
              Total Queries
            </span>
            <span className="font-mono text-[#6B6B6B] dark:text-[#9CA3AF] text-[11px]">
              ({summary.total.toLocaleString()})
            </span>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#10B981] shadow-2xs shrink-0" />
            <span className="font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">
              Benign Queries
            </span>
            <span className="font-mono text-[#6B6B6B] dark:text-[#9CA3AF] text-[11px]">
              ({summary.clean.toLocaleString()})
            </span>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#EF4444] shadow-2xs shrink-0" />
            <span className="font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">
              Malicious Queries
            </span>
            <span className="font-mono text-[#6B6B6B] dark:text-[#9CA3AF] text-[11px]">
              ({summary.malicious.toLocaleString()})
            </span>
          </div>
        </div>

        <div className="flex items-center gap-1.5 text-[11px] font-mono text-[#6B6B6B] dark:text-[#9CA3AF]">
          <span>Observed Window Volume:</span>
          <span className="font-semibold text-[#1A1A1A] dark:text-[#F3F4F6]">
            {summary.total.toLocaleString()}
          </span>
        </div>
      </div>

      {/* Main Chart with Brush / Overview Layout */}
      <div className="w-full" style={{ height }}>
        <ChartBrushLayout
          data={chartData}
          xDataKey="date"
          enabled={true}
          height={68}
          brushStrip={(layout) => (
            <LineChart
              animationDuration={0}
              className="size-full"
              data={chartData}
              margin={{ top: 4, right: 24, bottom: 4, left: 24 }}
              status={isLoading ? "loading" : "ready"}
              style={{ aspectRatio: "unset", height: "100%" }}
            >
              <Line
                animate={false}
                dataKey="total"
                fadeEdges={true}
                showHighlight={false}
                stroke="#2F6FED"
                strokeWidth={1.5}
                curve={curveCatmullRom}
              />
              <Line
                animate={false}
                dataKey="clean"
                fadeEdges={true}
                showHighlight={false}
                stroke="#10B981"
                strokeWidth={1.5}
                curve={curveCatmullRom}
              />
              <Line
                animate={false}
                dataKey="malicious"
                fadeEdges={true}
                showHighlight={false}
                stroke="#EF4444"
                strokeWidth={1.5}
                curve={curveCatmullRom}
              />
              <ChartBrush
                initialSelection={layout.brushSelection ?? undefined}
                onSelectionChange={layout.onBrushSelectionChange}
                selectionPattern={{ color: "#2F6FED", preset: "diagonal", opacity: 0.15 }}
              />
            </LineChart>
          )}
        >
          {(layout) => (
            <LineChart
              className="size-full"
              data={chartData}
              status={isLoading ? "loading" : "ready"}
              style={{ aspectRatio: "unset", height: "100%" }}
              margin={{ top: 12, right: 24, bottom: 24, left: 24 }}
              tweenYDomainOnXDomainChange={true}
              xDomain={layout.xDomain}
              xDomainSlotCount={layout.xDomainSlotCount}
              yDomainTween={true}
            >
              {/* Subtle background texture */}
              <Background pattern="dots" opacity={0.12} />

              {/* Minimal horizontal grid */}
              <Grid horizontal stroke="var(--chart-grid, #E2E8F0)" />

              {/* Required Three Series: Total, Clean, Malicious */}
              <Line
                dataKey="total"
                fadeEdges={true}
                stroke="#2F6FED"
                strokeWidth={2.5}
                curve={curveCatmullRom}
              />
              <Line
                dataKey="clean"
                fadeEdges={true}
                stroke="#10B981"
                strokeWidth={2.5}
                curve={curveCatmullRom}
              />
              <Line
                dataKey="malicious"
                fadeEdges={true}
                stroke="#EF4444"
                strokeWidth={2.5}
                curve={curveCatmullRom}
              />

              {/* Time-of-Day X-Axis */}
              <XAxis numTicks={7} />

              {/* Interactive Tooltip showing Total, Clean, and Malicious */}
              <ChartTooltip
                rows={(point: Record<string, unknown>) => {
                  const clean = Number(point.clean ?? 0);
                  const malicious = Number(point.malicious ?? 0);
                  const total = Number(point.total ?? clean + malicious);

                  return [
                    {
                      label: "Total Queries",
                      value: total.toLocaleString(),
                      color: "#2F6FED",
                    },
                    {
                      label: "Benign Queries",
                      value: clean.toLocaleString(),
                      color: "#10B981",
                    },
                    {
                      label: "Malicious Queries",
                      value: malicious.toLocaleString(),
                      color: "#EF4444",
                    },
                  ];
                }}
              />
            </LineChart>
          )}
        </ChartBrushLayout>
      </div>
    </div>
  );
};

export default DNSQueriesOverTimeChart;
