import React from "react";
import { cn } from "@/lib/utils";

export interface RiskScoreGaugeProps {
  score: number;
  size?: number;
  className?: string;
  showLabel?: boolean;
}

export const RiskScoreGauge: React.FC<RiskScoreGaugeProps> = ({
  score = 0,
  size = 140,
  className,
  showLabel = true,
}) => {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  
  // Color calculation based on risk score
  const getColor = (val: number) => {
    if (val >= 75) return { stroke: "#EF4444", text: "text-red-500", label: "CRITICAL RISK" };
    if (val >= 50) return { stroke: "#F97316", text: "text-orange-500", label: "HIGH RISK" };
    if (val >= 25) return { stroke: "#F59E0B", text: "text-amber-500", label: "MEDIUM RISK" };
    return { stroke: "#10B981", text: "text-emerald-500", label: "LOW RISK" };
  };

  const status = getColor(clamped);

  const strokeWidth = size * 0.08;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = Math.PI * radius * 1.5; // 270 degree arc
  const strokeDashoffset = circumference - (clamped / 100) * circumference;

  return (
    <div className={cn("relative flex flex-col items-center justify-center", className)}>
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        className="transform -rotate-[225deg]"
      >
        {/* Background Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          className="text-muted/40"
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={0}
          strokeLinecap="round"
        />

        {/* Dynamic Progress Fill */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={status.stroke}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          className="transition-all duration-700 ease-out"
        />
      </svg>

      {/* Central Content */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className={cn("font-mono font-bold tracking-tight text-foreground", size > 120 ? "text-3xl" : "text-xl")}>
          {clamped}
        </span>
        {showLabel && (
          <span className={cn("font-mono text-[9px] uppercase tracking-widest font-semibold mt-0.5", status.text)}>
            {status.label}
          </span>
        )}
      </div>
    </div>
  );
};

export default RiskScoreGauge;
