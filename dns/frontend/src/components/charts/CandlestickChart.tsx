"use client";

import React, { createContext, useContext, useState, useMemo, useRef } from "react";
import { cn } from "@/lib/utils";

// --- TYPES ---
export interface OHLCDataPoint {
  time: string;
  open: number;
  high: number;
  low: number;
  close: number;
  volume?: number;
  [key: string]: any;
}

interface CandlestickChartContextValue {
  data: OHLCDataPoint[];
  candleWidth: number;
  margin: { top: number; right: number; bottom: number; left: number };
  width: number;
  height: number;
  hoveredIndex: number | null;
  setHoveredIndex: (idx: number | null) => void;
  hoverPos: { x: number; y: number } | null;
  setHoverPos: (pos: { x: number; y: number } | null) => void;
  xScale: (index: number) => number;
  yScale: (val: number) => number;
  minVal: number;
  maxVal: number;
  yTicks: number[];
}

const CandlestickChartContext = createContext<CandlestickChartContextValue | null>(null);

export const useCandlestickChart = () => {
  const ctx = useContext(CandlestickChartContext);
  if (!ctx) {
    throw new Error("Candlestick compound components must be used within <CandlestickChart>");
  }
  return ctx;
};

// --- CANDLESTICK CHART ROOT COMPONENT ---
export interface CandlestickChartProps {
  data: OHLCDataPoint[];
  candleWidth?: number;
  margin?: { top?: number; right?: number; bottom?: number; left?: number };
  style?: React.CSSProperties;
  className?: string;
  children: React.ReactNode;
}

export const CandlestickChart: React.FC<CandlestickChartProps> = ({
  data = [],
  candleWidth = 8,
  margin: userMargin,
  style,
  className,
  children,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [hoverPos, setHoverPos] = useState<{ x: number; y: number } | null>(null);

  const margin = useMemo(
    () => ({
      top: userMargin?.top ?? 8,
      right: userMargin?.right ?? 8,
      bottom: userMargin?.bottom ?? 40,
      left: userMargin?.left ?? 8,
    }),
    [userMargin]
  );

  const width = 500;
  const height = (typeof style?.height === "number" ? style.height : 320);

  const { minVal, maxVal, yTicks } = useMemo(() => {
    if (!data.length) return { minVal: 0, maxVal: 100, yTicks: [0, 25, 50, 75, 100] };
    let min = Infinity;
    let max = -Infinity;
    data.forEach((d) => {
      if (d.low < min) min = d.low;
      if (d.high > max) max = d.high;
    });
    // Add small buffer
    const pad = Math.max(5, (max - min) * 0.1);
    const bottom = Math.max(0, Math.floor(min - pad));
    const top = Math.ceil(max + pad);
    const step = (top - bottom) / 4;
    const ticks = [bottom, Math.round(bottom + step), Math.round(bottom + step * 2), Math.round(bottom + step * 3), top];
    return { minVal: bottom, maxVal: top, yTicks: ticks };
  }, [data]);

  const innerWidth = width - margin.left - margin.right;
  const innerHeight = height - margin.top - margin.bottom;

  const xScale = useMemo(() => {
    return (index: number) => {
      if (data.length <= 1) return margin.left + innerWidth / 2;
      return margin.left + (index / (data.length - 1)) * innerWidth;
    };
  }, [data.length, margin.left, innerWidth]);

  const yScale = useMemo(() => {
    return (val: number) => {
      if (maxVal === minVal) return margin.top + innerHeight / 2;
      const ratio = (val - minVal) / (maxVal - minVal);
      return margin.top + innerHeight * (1 - ratio);
    };
  }, [minVal, maxVal, margin.top, innerHeight]);

  const contextValue = useMemo(
    () => ({
      data,
      candleWidth,
      margin,
      width,
      height,
      hoveredIndex,
      setHoveredIndex,
      hoverPos,
      setHoverPos,
      xScale,
      yScale,
      minVal,
      maxVal,
      yTicks,
    }),
    [
      data,
      candleWidth,
      margin,
      width,
      height,
      hoveredIndex,
      hoverPos,
      xScale,
      yScale,
      minVal,
      maxVal,
      yTicks,
    ]
  );

  return (
    <CandlestickChartContext.Provider value={contextValue}>
      <div
        ref={containerRef}
        className={cn("relative w-full select-none flex flex-col justify-center", className)}
        style={{ ...style, height }}
      >
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-full overflow-visible"
          preserveAspectRatio="none"
          onMouseLeave={() => {
            setHoveredIndex(null);
            setHoverPos(null);
          }}
        >
          {/* Horizontal Gridlines & Y-Axis Ticks */}
          <g className="grid-lines opacity-40">
            {yTicks.map((tickVal, i) => {
              const y = yScale(tickVal);
              return (
                <g key={`ytick-${i}`}>
                  <line
                    x1={margin.left}
                    y1={y}
                    x2={width - margin.right}
                    y2={y}
                    stroke="currentColor"
                    strokeWidth="1"
                    strokeDasharray="3 3"
                    className="text-[#EBEBEB] dark:text-[#1E283D]"
                  />
                  <text
                    x={width - margin.right}
                    y={y - 3}
                    textAnchor="end"
                    className="text-[9px] font-mono fill-[#9C9C9C] dark:fill-[#6B7280]"
                  >
                    {tickVal}
                  </text>
                </g>
              );
            })}
          </g>

          {children}
        </svg>
      </div>
    </CandlestickChartContext.Provider>
  );
};

// --- CANDLESTICK COMPONENT ---
export interface CandlestickProps {
  negativeFill?: string;
  positiveFill?: string;
  candleWidth?: number;
  className?: string;
}

export const Candlestick: React.FC<CandlestickProps> = ({
  negativeFill = "var(--color-red-500, #EF4444)",
  positiveFill = "var(--color-emerald-500, #10B981)",
  candleWidth: overrideWidth,
  className,
}) => {
  const { data, candleWidth: defaultWidth, xScale, yScale, setHoveredIndex, setHoverPos, hoveredIndex } =
    useCandlestickChart();

  const width = overrideWidth || defaultWidth;

  return (
    <g className={cn("candlesticks-layer", className)}>
      {data.map((d, i) => {
        const isUp = d.close >= d.open;
        const color = isUp ? positiveFill : negativeFill;
        const x = xScale(i);
        const yHigh = yScale(d.high);
        const yLow = yScale(d.low);
        const yOpen = yScale(d.open);
        const yClose = yScale(d.close);

        const bodyY = Math.min(yOpen, yClose);
        const bodyHeight = Math.max(2.5, Math.abs(yClose - yOpen));
        const isHovered = hoveredIndex === i;

        return (
          <g
            key={`candle-${d.time}-${i}`}
            className="cursor-pointer transition-opacity duration-150"
            onMouseEnter={(e) => {
              setHoveredIndex(i);
              const rect = e.currentTarget.getBoundingClientRect();
              setHoverPos({ x: rect.left + rect.width / 2, y: rect.top });
            }}
          >
            {/* Hover focus column */}
            {isHovered && (
              <rect
                x={x - width * 1.5}
                y={0}
                width={width * 3}
                height="100%"
                fill="currentColor"
                className="text-[#2F6FED]/5 dark:text-[#2F6FED]/10 pointer-events-none"
              />
            )}

            {/* High-Low Wick Line */}
            <line
              x1={x}
              y1={yHigh}
              x2={x}
              y2={yLow}
              stroke={color}
              strokeWidth={1.5}
              strokeLinecap="round"
            />

            {/* Open-Close Candle Body */}
            <rect
              x={x - width / 2}
              y={bodyY}
              width={width}
              height={bodyHeight}
              rx={1.5}
              fill={color}
              stroke={color}
              strokeWidth={0.5}
              className={cn(
                "transition-transform duration-150",
                isHovered && "filter drop-shadow-sm"
              )}
            />
          </g>
        );
      })}
    </g>
  );
};

// --- X-AXIS COMPONENT ---
export interface XAxisProps {
  className?: string;
  interval?: number;
}

export const XAxis: React.FC<XAxisProps> = ({ className, interval = 2 }) => {
  const { data, xScale, height, margin } = useCandlestickChart();
  const y = height - margin.bottom + 18;

  return (
    <g className={cn("xaxis-layer", className)}>
      {data.map((d, i) => {
        // Show every Nth label or first/last to avoid overlap
        if (i % interval !== 0 && i !== data.length - 1) return null;
        const x = xScale(i);
        return (
          <text
            key={`xaxis-${d.time}-${i}`}
            x={x}
            y={y}
            textAnchor="middle"
            className="text-[10px] font-mono fill-[#9C9C9C] dark:fill-[#6B7280]"
          >
            {d.time}
          </text>
        );
      })}
    </g>
  );
};

// --- CANDLESTICK TOOLTIP CONTENT ---
export interface CandlestickTooltipContentProps {
  active?: boolean;
  payload?: any;
  label?: string;
  className?: string;
}

export const CandlestickTooltipContent: React.FC<any> = () => {
  const { data, hoveredIndex } = useCandlestickChart();

  if (hoveredIndex === null || !data[hoveredIndex]) return null;

  const d = data[hoveredIndex];
  const isUp = d.close >= d.open;
  const delta = d.close - d.open;
  const deltaPct = d.open > 0 ? ((delta / d.open) * 100).toFixed(1) : "0";

  return (
    <div className="absolute top-2 right-2 pointer-events-none z-30 bg-white/95 dark:bg-[#121826]/95 border border-[#EBEBEB] dark:border-[#1E283D] rounded-[8px] p-2.5 shadow-md backdrop-blur-xs text-[11px] min-w-[150px]">
      <div className="flex items-center justify-between gap-2 border-b border-[#EBEBEB] dark:border-[#1E283D] pb-1 mb-1.5 font-sans">
        <span className="font-semibold text-[#1A1A1A] dark:text-[#F3F4F6]">
          Threat Bucket: <span className="font-mono font-normal">{d.time}</span>
        </span>
        <span
          className={cn(
            "font-mono text-[10px] font-semibold px-1 py-0.2 rounded",
            isUp
              ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
              : "bg-red-500/10 text-red-600 dark:text-red-400"
          )}
        >
          {delta >= 0 ? `+${delta}` : delta} ({deltaPct}%)
        </span>
      </div>

      <div className="grid grid-cols-2 gap-x-3 gap-y-1 font-mono text-[11px]">
        <div className="flex items-center justify-between text-[#6B6B6B] dark:text-[#9CA3AF]">
          <span>Open:</span>
          <span className="font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">{d.open}</span>
        </div>
        <div className="flex items-center justify-between text-[#6B6B6B] dark:text-[#9CA3AF]">
          <span>High:</span>
          <span className="font-medium text-red-500 dark:text-red-400 font-semibold">{d.high}</span>
        </div>
        <div className="flex items-center justify-between text-[#6B6B6B] dark:text-[#9CA3AF]">
          <span>Low:</span>
          <span className="font-medium text-emerald-600 dark:text-emerald-400">{d.low}</span>
        </div>
        <div className="flex items-center justify-between text-[#6B6B6B] dark:text-[#9CA3AF]">
          <span>Close:</span>
          <span className="font-medium text-[#1A1A1A] dark:text-[#F3F4F6] font-semibold">{d.close}</span>
        </div>
      </div>
    </div>
  );
};

// --- CHART TOOLTIP WRAPPER ---
export interface ChartTooltipProps {
  content?: React.ComponentType<any>;
}

export const ChartTooltip: React.FC<ChartTooltipProps> = ({ content: Content }) => {
  if (!Content) return null;
  return <Content />;
};

export default CandlestickChart;
