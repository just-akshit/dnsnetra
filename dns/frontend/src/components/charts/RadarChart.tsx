"use client";

import React, { createContext, useContext, useMemo } from "react";
import { cn } from "@/lib/utils";

// --- TYPES ---
export interface RadarMetric {
  key: string;
  label: string;
  max?: number;
}

export interface RadarDataItem {
  label: string;
  color?: string;
  [key: string]: any;
}

interface RadarChartContextValue {
  data: RadarDataItem[];
  metrics: RadarMetric[];
  size: number;
  radius: number;
  cx: number;
  cy: number;
  angleStep: number;
}

const RadarChartContext = createContext<RadarChartContextValue | null>(null);

export const useRadarChart = () => {
  const context = useContext(RadarChartContext);
  if (!context) {
    throw new Error("RadarChart compound subcomponents must be used within <RadarChart>");
  }
  return context;
};

// Helper: convert polar coords (radius, angle in degrees) to cartesian (x, y)
function polarToCartesian(centerX: number, centerY: number, radius: number, angleInDegrees: number) {
  // Start from top (0 deg is -90 in standard math)
  const angleInRadians = ((angleInDegrees - 90) * Math.PI) / 180.0;
  return {
    x: centerX + radius * Math.cos(angleInRadians),
    y: centerY + radius * Math.sin(angleInRadians),
  };
}

// Clamp helper
function clamp(val: number, min = 0, max = 100) {
  return Math.min(max, Math.max(min, val));
}

// --- MAIN RADARCHART COMPONENT ---
export interface RadarChartProps {
  data: RadarDataItem[];
  metrics: RadarMetric[];
  size?: number;
  className?: string;
  children: React.ReactNode;
}

export const RadarChart: React.FC<RadarChartProps> = ({
  data,
  metrics,
  size = 250,
  className,
  children,
}) => {
  const cx = size / 2;
  const cy = size / 2;
  // Reserve padding for axis text labels
  const radius = size * 0.35;
  const angleStep = metrics.length > 0 ? 360 / metrics.length : 60;

  const contextValue = useMemo(
    () => ({
      data,
      metrics,
      size,
      radius,
      cx,
      cy,
      angleStep,
    }),
    [data, metrics, size, radius, cx, cy, angleStep]
  );

  return (
    <RadarChartContext.Provider value={contextValue}>
      <div
        className={cn("relative flex items-center justify-center select-none", className)}
        style={{ width: "100%", height: "100%" }}
      >
        <svg
          viewBox={`0 0 ${size} ${size}`}
          className="w-full h-full max-w-[280px] max-h-[220px] overflow-visible"
        >
          {children}
        </svg>
      </div>
    </RadarChartContext.Provider>
  );
};

// --- RADAR GRID COMPONENT ---
export interface RadarGridProps {
  levels?: number;
  className?: string;
}

export const RadarGrid: React.FC<RadarGridProps> = ({
  levels = 4,
  className,
}) => {
  const { metrics, radius, cx, cy, angleStep } = useRadarChart();

  const concentricPolygons = useMemo(() => {
    const polys: string[] = [];
    for (let level = 1; level <= levels; level++) {
      const currentRadius = (radius / levels) * level;
      const points = metrics.map((_, i) => {
        const angle = i * angleStep;
        const pt = polarToCartesian(cx, cy, currentRadius, angle);
        return `${pt.x},${pt.y}`;
      });
      polys.push(points.join(" "));
    }
    return polys;
  }, [levels, radius, metrics, cx, cy, angleStep]);

  return (
    <g className={cn("radar-grid", className)}>
      {concentricPolygons.map((points, idx) => (
        <polygon
          key={`grid-level-${idx}`}
          points={points}
          fill="none"
          stroke="currentColor"
          strokeWidth="1"
          strokeDasharray={idx === levels - 1 ? undefined : "3 3"}
          className="text-[#E5E7EB] dark:text-[#1E283D]/90"
        />
      ))}
    </g>
  );
};

// --- RADAR AXIS SPOKES COMPONENT ---
export interface RadarAxisProps {
  className?: string;
}

export const RadarAxis: React.FC<RadarAxisProps> = ({ className }) => {
  const { metrics, radius, cx, cy, angleStep } = useRadarChart();

  return (
    <g className={cn("radar-axis", className)}>
      {metrics.map((_, i) => {
        const angle = i * angleStep;
        const pt = polarToCartesian(cx, cy, radius, angle);
        return (
          <line
            key={`axis-${i}`}
            x1={cx}
            y1={cy}
            x2={pt.x}
            y2={pt.y}
            stroke="currentColor"
            strokeWidth="1"
            className="text-[#E5E7EB] dark:text-[#1E283D]"
          />
        );
      })}
    </g>
  );
};

// --- RADAR LABELS COMPONENT ---
export interface RadarLabelsProps {
  className?: string;
  offset?: number;
}

export const RadarLabels: React.FC<RadarLabelsProps> = ({
  className,
  offset = 20,
}) => {
  const { metrics, radius, cx, cy, angleStep } = useRadarChart();

  return (
    <g className={cn("radar-labels", className)}>
      {metrics.map((m, i) => {
        const angle = i * angleStep;
        const labelPt = polarToCartesian(cx, cy, radius + offset, angle);

        // Compute text-anchor based on horizontal position
        let textAnchor: "middle" | "start" | "end" = "middle";
        if (Math.abs(labelPt.x - cx) > 10) {
          textAnchor = labelPt.x > cx ? "start" : "end";
        }

        // Adjust dy for vertical balance
        let dy = "0.35em";
        if (labelPt.y < cy - radius * 0.5) dy = "0em";
        else if (labelPt.y > cy + radius * 0.5) dy = "0.75em";

        return (
          <text
            key={`label-${m.key}`}
            x={labelPt.x}
            y={labelPt.y}
            textAnchor={textAnchor}
            dy={dy}
            className="text-[10px] font-medium fill-[#6B7280] dark:fill-[#9CA3AF] tracking-[-0.01em]"
          >
            {m.label}
          </text>
        );
      })}
    </g>
  );
};

// --- RADAR AREA COMPONENT ---
export interface RadarAreaProps {
  index: number;
  color?: string;
  fillOpacity?: number;
  strokeWidth?: number;
  showDots?: boolean;
  className?: string;
}

export const RadarArea: React.FC<RadarAreaProps> = ({
  index,
  color,
  fillOpacity = 0.25,
  strokeWidth = 2,
  showDots = true,
  className,
}) => {
  const { data, metrics, radius, cx, cy, angleStep } = useRadarChart();
  const item = data[index];

  const { pointsStr, vertices } = useMemo(() => {
    if (!item) return { pointsStr: "", vertices: [] };
    const pts: { x: number; y: number; value: number; key: string; label: string }[] = [];
    metrics.forEach((m, i) => {
      const rawVal = item[m.key] ?? 0;
      const maxVal = m.max || 100;
      const normalized = clamp((rawVal / maxVal) * 100, 0, 100);
      const currentRadius = (normalized / 100) * radius;
      const angle = i * angleStep;
      const pt = polarToCartesian(cx, cy, currentRadius, angle);
      pts.push({
        x: pt.x,
        y: pt.y,
        value: rawVal,
        key: m.key,
        label: m.label,
      });
    });

    const str = pts.map((p) => `${p.x},${p.y}`).join(" ");
    return { pointsStr: str, vertices: pts };
  }, [item, metrics, radius, cx, cy, angleStep]);

  if (!item) return null;

  const areaColor = color || item.color || "#2F6FED";

  return (
    <g className={cn("radar-area-group", className)}>
      {/* Filled Polygon Area */}
      <polygon
        points={pointsStr}
        fill={areaColor}
        fillOpacity={fillOpacity}
        stroke={areaColor}
        strokeWidth={strokeWidth}
        strokeLinejoin="round"
        className="transition-all duration-300 ease-out"
      />

      {/* Vertex Dots */}
      {showDots &&
        vertices.map((v, i) => (
          <g key={`dot-${v.key}-${i}`} className="group cursor-pointer">
            <circle
              cx={v.x}
              cy={v.y}
              r={3.5}
              fill="#FFFFFF"
              stroke={areaColor}
              strokeWidth={1.5}
              className="dark:fill-[#121826] transition-transform duration-150 hover:scale-125"
            />
            {/* Native SVG title tooltip */}
            <title>{`${v.label}: ${v.value}/100`}</title>
          </g>
        ))}
    </g>
  );
};

export default RadarChart;
