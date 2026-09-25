"use client";

import React, { useMemo } from "react";
import {
  BarChart,
  Bar,
  BarDepthBack,
  BarDepthFront,
  BarDepthProvider,
  BarXAxis,
  Grid,
  ChartTooltip,
} from "@/components/charts/bar-chart-exports";
import { Activity, ShieldCheck, Database, Calendar } from "lucide-react";
import { cn } from "@/lib/utils";

export interface DailyDNSQueryData {
  /** Calendar date in ISO format (YYYY-MM-DD) */
  date: string;
  /** Total DNS queries detected on this calendar day */
  total: number;
  /** Clean queries breakdown */
  clean: number;
  benign?: number;
  /** Suspicious / Review Needed queries breakdown */
  suspicious: number;
  review_needed?: number;
  /** Malicious queries breakdown */
  malicious: number;
  /** Unknown queries breakdown */
  unknown?: number;
  [key: string]: string | number | undefined;
}

export interface DNSDetectionBarChartProps {
  /** Array of daily telemetry items, or raw bucketed telemetry to aggregate */
  data?: DailyDNSQueryData[];
  /** Loading state flag */
  isLoading?: boolean;
  /** Custom aspect ratio string (e.g. "2.4 / 1", "2 / 1", "16 / 9") */
  aspectRatio?: string;
  /** Chart title (default: "DNS Query Volume") */
  title?: string;
  /** Chart description (default: "Daily DNS queries over time") */
  description?: string;
  /** Optional custom class name */
  className?: string;
  /** Bar fill/theme color (default: #2F6FED) */
  barColor?: string;
  /** Stagger delay in seconds (default auto-computed by Bklit) */
  staggerDelay?: number;
  /** Whether to show header KPI badges */
  showSummaryBadges?: boolean;
  /** Number of days in the continuous timeline (default: 14) */
  daysCount?: number;
}

// Format "YYYY-MM-DD" -> "August 30, 2026"
export function formatFullDate(dateStr: string): string {
  if (!dateStr) return "—";
  const parts = dateStr.split("-");
  if (parts.length === 3) {
    const year = Number(parts[0]);
    const month = Number(parts[1]);
    const day = Number(parts[2]);
    if (!isNaN(year) && !isNaN(month) && !isNaN(day)) {
      const date = new Date(year, month - 1, day);
      return date.toLocaleDateString("en-US", {
        month: "long",
        day: "numeric",
        year: "numeric",
      });
    }
  }
  return dateStr;
}

// Format "YYYY-MM-DD" -> "Mon" or "Aug 30"
export function formatXAxisDate(dateStr: string): string {
  if (!dateStr) return "";
  const parts = dateStr.split("-");
  if (parts.length === 3) {
    const year = Number(parts[0]);
    const month = Number(parts[1]);
    const day = Number(parts[2]);
    if (!isNaN(year) && !isNaN(month) && !isNaN(day)) {
      const date = new Date(year, month - 1, day);
      return date.toLocaleDateString("en-US", {
        weekday: "short",
      });
    }
  }
  return dateStr;
}

/**
 * Resolves number of days for a given range preset string.
 */
export function getDaysCountFromRange(rangeStr?: string): number {
  if (!rangeStr) return 14;
  const lower = rangeStr.toLowerCase();
  if (lower.includes("7d") || lower.includes("7 day") || lower.includes("week")) return 7;
  if (lower.includes("30d") || lower.includes("30 day") || lower.includes("month")) return 30;
  if (lower.includes("90d") || lower.includes("quarter")) return 90;
  if (lower.includes("365") || lower.includes("year") || lower.includes("1y")) return 365;
  if (lower.includes("24h") || lower.includes("12h") || lower.includes("6h") || lower.includes("1h") || lower.includes("30m")) return 7;
  return 14;
}

/**
 * Aggregates raw DNS telemetry records/buckets into a continuous daily timeline.
 * Preserves zero-query days with total: 0, clean: 0, suspicious: 0, malicious: 0, unknown: 0.
 */
export function buildDailyDNSQueryTimeline(
  rawTelemetry: Array<{
    time_bucket?: string;
    timestamp?: string;
    date?: string;
    total_queries?: number;
    threat_queries?: number;
    total?: number;
    clean?: number;
    benign?: number;
    suspicious?: number;
    review_needed?: number;
    malicious?: number;
    unknown?: number;
    [key: string]: any;
  }>,
  daysCount = 14
): DailyDNSQueryData[] {
  if (!rawTelemetry || rawTelemetry.length === 0) {
    // Generate empty calendar days ending today
    const now = new Date();
    const timeline: DailyDNSQueryData[] = [];
    for (let i = daysCount - 1; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      const yyyy = d.getFullYear();
      const mm = String(d.getMonth() + 1).padStart(2, "0");
      const dd = String(d.getDate()).padStart(2, "0");
      timeline.push({
        date: `${yyyy}-${mm}-${dd}`,
        total: 0,
        clean: 0,
        suspicious: 0,
        malicious: 0,
        unknown: 0,
      });
    }
    return timeline;
  }

  // 1. Aggregate real telemetry records by calendar day (YYYY-MM-DD)
  const dailyMap = new Map<
    string,
    { total: number; clean: number; suspicious: number; malicious: number; unknown: number }
  >();
  let latestDateKey: string | null = null;

  for (const pt of rawTelemetry) {
    const rawTime = pt.date || pt.time_bucket || pt.timestamp;
    if (!rawTime) continue;

    // Extract YYYY-MM-DD
    const dateKey = String(rawTime).slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateKey)) continue;

    if (!latestDateKey || dateKey > latestDateKey) {
      latestDateKey = dateKey;
    }

    const total = Number(
      pt.total ?? pt.total_queries ?? pt.queries ?? 0
    );
    const malicious = Number(
      pt.malicious ?? pt.threat_queries ?? 0
    );
    const suspicious = Number(
      pt.suspicious ?? pt.review_needed ?? pt.suspicious_queries ?? 0
    );
    const unknown = Number(
      pt.unknown ?? pt.unknown_queries ?? 0
    );
    const clean =
      pt.clean !== undefined
        ? Number(pt.clean)
        : pt.benign !== undefined
          ? Number(pt.benign)
          : Math.max(0, total - malicious - suspicious - unknown);

    const existing = dailyMap.get(dateKey) || {
      total: 0,
      clean: 0,
      suspicious: 0,
      malicious: 0,
      unknown: 0,
    };
    existing.total += total;
    existing.malicious += malicious;
    existing.suspicious += suspicious;
    existing.clean += clean;
    existing.unknown += unknown;
    dailyMap.set(dateKey, existing);
  }

  // 2. Anchor end date to latest event date or today
  let endDate: Date;
  if (latestDateKey) {
    const [y, m, d] = latestDateKey.split("-").map(Number);
    endDate = new Date(y, m - 1, d);
  } else {
    endDate = new Date();
  }

  // 3. Build continuous daily array (one item per day)
  const timeline: DailyDNSQueryData[] = [];
  for (let i = daysCount - 1; i >= 0; i--) {
    const d = new Date(endDate);
    d.setDate(d.getDate() - i);
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    const dateKey = `${yyyy}-${mm}-${dd}`;

    const item = dailyMap.get(dateKey);
    if (item) {
      timeline.push({
        date: dateKey,
        total: item.total,
        clean: item.clean,
        suspicious: item.suspicious,
        malicious: item.malicious,
        unknown: item.unknown,
      });
    } else {
      timeline.push({
        date: dateKey,
        total: 0,
        clean: 0,
        suspicious: 0,
        malicious: 0,
        unknown: 0,
      });
    }
  }

  return timeline;
}

export const DNSDetectionBarChart: React.FC<DNSDetectionBarChartProps> = ({
  data = [],
  isLoading = false,
  aspectRatio = "2.4 / 1",
  title = "DNS Query Volume",
  description = "Daily DNS queries over time",
  className,
  barColor = "#2F6FED",
  staggerDelay,
  showSummaryBadges = true,
  daysCount = 14,
}) => {
  // Ensure we have a continuous daily timeline
  const chartData = useMemo(() => {
    if (!data || data.length === 0) {
      return buildDailyDNSQueryTimeline([], daysCount);
    }
    // If input already has items matching length, ensure proper number formatting
    if (data.length >= daysCount - 1 && data.length <= daysCount + 1) {
      return data.map((d) => ({
        date: d.date,
        total: Number(d.total || 0),
        clean: Number(d.clean || d.benign || 0),
        suspicious: Number(d.suspicious || d.review_needed || 0),
        malicious: Number(d.malicious || 0),
        unknown: Number(d.unknown || 0),
      }));
    }
    // Otherwise construct the continuous daily timeline from provided telemetry
    return buildDailyDNSQueryTimeline(data, daysCount);
  }, [data, daysCount]);

  // Summary counts for badges
  const summary = useMemo(() => {
    return chartData.reduce(
      (acc, curr) => ({
        totalQueries: acc.totalQueries + curr.total,
        totalClean: acc.totalClean + curr.clean,
        totalSuspicious: acc.totalSuspicious + curr.suspicious,
        totalMalicious: acc.totalMalicious + curr.malicious,
        totalUnknown: acc.totalUnknown + (curr.unknown || 0),
        activeDays: acc.activeDays + (curr.total > 0 ? 1 : 0),
      }),
      { totalQueries: 0, totalClean: 0, totalSuspicious: 0, totalMalicious: 0, totalUnknown: 0, activeDays: 0 }
    );
  }, [chartData]);

  const isEmpty = !isLoading && summary.totalQueries === 0;

  return (
    <div
      className={cn(
        "relative w-full rounded-[10px] border border-neutral-200/80 bg-white/70 p-5 shadow-xs backdrop-blur-md dark:border-neutral-800/80 dark:bg-[#0B0F17]/80",
        className
      )}
    >
      {/* Header with Title and KPI Badges */}
      {Boolean(title || description || showSummaryBadges) && (
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            {title && (
              <h3 className="font-semibold text-neutral-900 text-sm tracking-tight dark:text-neutral-100">
                {title}
              </h3>
            )}
            {description && (
              <p className="text-neutral-500 text-xs dark:text-neutral-400">
                {description}
              </p>
            )}
          </div>

          {showSummaryBadges && (
            <div className="flex flex-wrap items-center gap-2.5 text-xs">
              <div className="inline-flex items-center gap-1.5 rounded-md border border-neutral-200 bg-neutral-100/60 px-2.5 py-1 font-medium text-neutral-800 dark:border-neutral-800 dark:bg-neutral-900/60 dark:text-neutral-200">
                <Database className="h-3.5 w-3.5 text-[#2F6FED]" />
                <span>Total Volume:</span>
                <span className="font-mono font-semibold">
                  {summary.totalQueries.toLocaleString()}
                </span>
              </div>

              <div className="inline-flex items-center gap-1.5 rounded-md border border-neutral-200 bg-neutral-100/60 px-2.5 py-1 font-medium text-neutral-600 dark:border-neutral-800 dark:bg-neutral-900/60 dark:text-neutral-400">
                <Calendar className="h-3.5 w-3.5 text-neutral-500" />
                <span>{chartData.length} Days</span>
                {summary.activeDays > 0 && (
                  <span className="opacity-75">
                    ({summary.activeDays} active)
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Chart Visualization Area */}
      <div className="relative w-full">
        {isLoading ? (
          <div className="flex min-h-[260px] w-full flex-col items-center justify-center gap-2 rounded-lg border border-neutral-100 bg-neutral-50/50 dark:border-neutral-900 dark:bg-neutral-950/30">
            <Activity className="h-5 w-5 animate-spin text-[#2F6FED]" />
            <span className="text-neutral-500 text-xs dark:text-neutral-400">
              Loading daily DNS telemetry...
            </span>
          </div>
        ) : isEmpty ? (
          <div className="flex min-h-[260px] w-full flex-col items-center justify-center gap-1 rounded-lg border border-dashed border-neutral-200 bg-neutral-50/30 dark:border-neutral-800 dark:bg-neutral-900/20">
            <ShieldCheck className="h-6 w-6 text-neutral-400" />
            <span className="font-medium text-neutral-700 text-xs dark:text-neutral-300">
              No DNS telemetry recorded in this time range
            </span>
            <span className="text-neutral-400 text-xs">
              Daily query bars will populate continuously as DNS events are logged
            </span>
          </div>
        ) : (
          <BarDepthProvider
            segmentsAccessor={(datum) => [
              { value: Number(datum.clean || datum.benign || 0), color: "#10B981" },
              { value: Number(datum.suspicious || datum.review_needed || 0), color: "#F59E0B" },
              { value: Number(datum.malicious || 0), color: "#EF4444" },
              { value: Number(datum.unknown || 0), color: "#64748B" },
            ]}
          >
            <BarChart
              aspectRatio={aspectRatio}
              barGap={0.2}
              className="w-full"
              data={chartData}
              margin={{ top: 24, right: 24, bottom: 44, left: 45 }}
              stacked
              status="ready"
              xDataKey="date"
            >
              <Grid horizontal vertical={false} />

              {/* 3D multi-segment depth side facets (green -> yellow -> red -> slate) and top lid */}
              <BarDepthBack color="#10B981" dataKey="clean" />

              {/* Stacked 3D visual segments: Clean (bottom), Review Needed (middle), Malicious (upper), Unknown (top) */}
              <Bar
                dataKey="clean"
                fill="#10B981"
                perspective
                staggerDelay={staggerDelay}
              />
              <Bar
                dataKey="suspicious"
                fill="#F59E0B"
                perspective
                staggerDelay={staggerDelay}
              />
              <Bar
                dataKey="malicious"
                fill="#EF4444"
                perspective
                staggerDelay={staggerDelay}
              />
              <Bar
                dataKey="unknown"
                fill="#64748B"
                perspective
                staggerDelay={staggerDelay}
              />

              {/* Front glass sheen */}
              <BarDepthFront dataKey="clean" />

              {/* Formatted X-Axis displaying readable representative calendar dates */}
              <BarXAxis
                formatLabel={formatXAxisDate}
                maxLabels={chartData.length <= 14 ? chartData.length : 12}
              />

              {/* Tooltip displaying full calendar date and detailed query breakdown */}
              <ChartTooltip
                rows={(point) => {
                  const clean = Number(point.clean || point.benign || 0);
                  const suspicious = Number(point.suspicious || point.review_needed || 0);
                  const malicious = Number(point.malicious || 0);
                  const unknown = Number(point.unknown || 0);
                  const total = Number(
                    point.total || clean + suspicious + malicious + unknown
                  );
                  return [
                    {
                      label: "Total Queries",
                      value: total,
                      color: "#2F6FED",
                    },
                    {
                      label: "Clean / Benign",
                      value: clean,
                      color: "#10B981", // Emerald Green
                    },
                    {
                      label: "Review Needed",
                      value: suspicious,
                      color: "#F59E0B", // Amber Yellow
                    },
                    {
                      label: "Malicious Queries",
                      value: malicious,
                      color: "#EF4444", // Red
                    },
                    ...(unknown > 0
                      ? [
                          {
                            label: "Unknown Queries",
                            value: unknown,
                            color: "#64748B", // Slate
                          },
                        ]
                      : []),
                  ];
                }}
              />
            </BarChart>
          </BarDepthProvider>
        )}
      </div>
    </div>
  );
};

export default DNSDetectionBarChart;
