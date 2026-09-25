import React from "react";
import { cn } from "@/lib/utils";

export interface RiskGaugeChartProps {
  score: number; // 0 to 100
  size?: number;
  label?: string;
  className?: string;
}

export const RiskGaugeChart: React.FC<RiskGaugeChartProps> = ({
  score = 0,
  size = 180,
  label = "Perimeter Risk",
  className = "",
}) => {
  const normalizedScore = Math.max(0, Math.min(100, score));

  // Determine risk category & color
  let riskLevel = "Low";
  let riskColor = "#10B981"; // Emerald
  if (normalizedScore > 75) {
    riskLevel = "Critical";
    riskColor = "#EF4444"; // Red
  } else if (normalizedScore > 50) {
    riskLevel = "High";
    riskColor = "#F97316"; // Orange
  } else if (normalizedScore > 25) {
    riskLevel = "Medium";
    riskColor = "#F59E0B"; // Amber
  }

  // Semi-circle gauge arc calculation (180 degrees from -180 to 0)
  const radius = size / 2 - 14;
  const strokeWidth = 12;
  const circumference = Math.PI * radius;
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  return (
    <div
      className={cn("flex flex-col items-center justify-center select-none", className)}
      style={{ width: size }}
    >
      <div className="relative flex items-center justify-center" style={{ width: size, height: size / 2 + 20 }}>
        <svg
          width={size}
          height={size / 2 + 16}
          viewBox={`0 0 ${size} ${size / 2 + 16}`}
          className="overflow-visible"
        >
          {/* Background Track Arc */}
          <path
            d={`M 14,${size / 2} A ${radius},${radius} 0 0,1 ${size - 14},${size / 2}`}
            fill="none"
            stroke="#EBEBEB"
            className="dark:stroke-[#1E283D]"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />

          {/* Active Colored Score Arc */}
          <path
            d={`M 14,${size / 2} A ${radius},${radius} 0 0,1 ${size - 14},${size / 2}`}
            fill="none"
            stroke={riskColor}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-700 ease-out"
          />
        </svg>

        {/* Center Score Readout */}
        <div className="absolute bottom-0 flex flex-col items-center justify-center text-center">
          <span className="text-[28px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tabular-nums tracking-tight leading-none">
            {normalizedScore}
          </span>
          <span
            className="text-[11px] font-semibold uppercase tracking-wider mt-1 px-2 py-0.5 rounded-full"
            style={{ backgroundColor: `${riskColor}18`, color: riskColor }}
          >
            {riskLevel}
          </span>
        </div>
      </div>

      <span className="text-[12px] font-medium text-[#6B6B6B] dark:text-[#9CA3AF] mt-1">
        {label}
      </span>
    </div>
  );
};

export default RiskGaugeChart;
