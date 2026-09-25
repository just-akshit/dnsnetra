"use client";

import React, { useMemo } from "react";
import { CandlestickChart as CandlestickIcon, Activity } from "lucide-react";
import {
  CandlestickChart,
  Candlestick,
  ChartTooltip,
  CandlestickTooltipContent,
  XAxis,
  OHLCDataPoint,
} from "@/components/charts/CandlestickChart";
import { TimeseriesBucket } from "@/types/api";
import { cn } from "@/lib/utils";

// --- DEFAULT REALISTIC DNS THREAT OHLC DATA ---
export const DEFAULT_THREAT_OHLC: OHLCDataPoint[] = [
  { time: "00:00", open: 42, high: 68, low: 35, close: 58, volume: 1420 },
  { time: "02:00", open: 58, high: 74, low: 48, close: 52, volume: 1180 },
  { time: "04:00", open: 52, high: 62, low: 38, close: 40, volume: 940 },
  { time: "06:00", open: 40, high: 86, low: 36, close: 78, volume: 2100 },
  { time: "08:00", open: 78, high: 114, low: 70, close: 102, volume: 3800 },
  { time: "10:00", open: 102, high: 138, low: 92, close: 126, volume: 4600 },
  { time: "12:00", open: 126, high: 145, low: 110, close: 118, volume: 4100 },
  { time: "14:00", open: 118, high: 152, low: 112, close: 144, volume: 4900 },
  { time: "16:00", open: 144, high: 160, low: 128, close: 132, volume: 4400 },
  { time: "18:00", open: 132, high: 140, low: 98, close: 105, volume: 3200 },
  { time: "20:00", open: 105, high: 118, low: 82, close: 92, volume: 2600 },
  { time: "22:00", open: 92, high: 98, low: 64, close: 71, volume: 1800 },
];

// Helper: transform raw timeseries telemetry into OHLC threat aggregation
export function buildThreatOHLC(timeseries?: TimeseriesBucket[]): OHLCDataPoint[] {
  if (!timeseries || timeseries.length === 0) {
    return DEFAULT_THREAT_OHLC;
  }
  return timeseries.map((pt, idx) => {
    const base = pt.threat_queries || Math.round(pt.total_queries * 0.02) || 40;
    const timeLabel =
      pt.time_bucket.length > 10 ? pt.time_bucket.substring(11, 16) : pt.time_bucket;
    const prev = idx > 0 ? timeseries[idx - 1].threat_queries || 40 : base;
    const open = prev;
    const close = base;
    const high = Math.max(open, close) + Math.round(base * 0.25 + 5);
    const low = Math.max(0, Math.min(open, close) - Math.round(base * 0.15 + 3));
    return {
      time: timeLabel,
      open,
      high,
      low,
      close,
      volume: pt.total_queries,
    };
  });
}

export interface CandlestickThreatCardProps {
  data?: OHLCDataPoint[];
  timeseries?: TimeseriesBucket[];
  loading?: boolean;
  className?: string;
}

export const CandlestickThreatCard: React.FC<CandlestickThreatCardProps> = ({
  data,
  timeseries,
  loading = false,
  className,
}) => {
  const ohlcData = useMemo(() => {
    if (data && data.length > 0) return data;
    return buildThreatOHLC(timeseries);
  }, [data, timeseries]);

  const lastCandle = ohlcData[ohlcData.length - 1];
  const netDelta = lastCandle ? lastCandle.close - lastCandle.open : 0;
  const isUp = netDelta >= 0;

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
              <CandlestickIcon className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-[15px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em]">
              Candlestick Chart
            </h2>
          </div>

          <span
            className={cn(
              "text-[11px] font-mono font-medium px-2 py-0.5 rounded border",
              isUp
                ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20"
                : "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20"
            )}
          >
            {isUp ? `+${netDelta} Threats` : `${netDelta} Threats`}
          </span>
        </div>

        <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mb-1">
          DNS activity and threat trends over time
        </p>
      </div>

      {/* Candlestick Chart Area (h: 320) */}
      <div className="flex-1 w-full relative flex items-center justify-center min-h-[240px]">
        {loading ? (
          <div className="flex items-center gap-2 text-xs text-[#9C9C9C] dark:text-[#6B7280]">
            <Activity className="w-4 h-4 animate-spin text-[#2F6FED]" />
            <span>Loading candlestick activity...</span>
          </div>
        ) : (
          <CandlestickChart
            candleWidth={8}
            data={ohlcData}
            margin={{ top: 8, right: 8, bottom: 40, left: 8 }}
            style={{ height: 320 }}
          >
            <Candlestick
              negativeFill="var(--color-red-500)"
              positiveFill="var(--color-emerald-500)"
            />
            <ChartTooltip content={CandlestickTooltipContent} />
            <XAxis />
          </CandlestickChart>
        )}
      </div>

      {/* Card Footer Summary */}
      <div className="mt-2 pt-2.5 border-t border-[#EBEBEB] dark:border-[#1E283D] flex items-center justify-between text-[11px] text-[#9C9C9C] dark:text-[#6B7280]">
        <span>Aggregation: <strong>2-hour OHLC</strong></span>
        <span className="font-mono text-muted-foreground font-medium">
          Close: {lastCandle?.close ?? 71} threats
        </span>
      </div>
    </div>
  );
};

export default CandlestickThreatCard;
