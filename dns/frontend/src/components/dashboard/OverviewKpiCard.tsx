import React from "react";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";
import { cn } from "@/lib/utils";

export interface OverviewKpiCardProps {
  title: string;
  value: string | number;
  trend?: {
    value: string;
    isPositive?: boolean;
    isNeutral?: boolean;
    label?: string;
  };
  onClick?: () => void;
  ariaLabel?: string;
  className?: string;
}

export const OverviewKpiCard: React.FC<OverviewKpiCardProps> = ({
  title,
  value,
  trend,
  onClick,
  ariaLabel,
  className,
}) => {
  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (onClick && (e.key === "Enter" || e.key === " ")) {
      e.preventDefault();
      onClick();
    }
  };

  return (
    <div
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      onClick={onClick}
      onKeyDown={onClick ? handleKeyDown : undefined}
      aria-label={ariaLabel || `View ${title} analytics`}
      className={cn(
        "group relative flex flex-col justify-between rounded-xl p-3.5 min-h-[92px]",
        "bg-card border border-border/80 dark:border-white/[0.08]",
        "shadow-xs outline-hidden transition-all duration-150 ease-out",
        onClick &&
          "cursor-pointer hover:border-primary/40 hover:bg-muted/30 focus-visible:ring-2 focus-visible:ring-primary active:scale-[0.99]",
        className
      )}
    >
      {/* KPI Title */}
      <div className="text-[12px] font-medium text-muted-foreground tracking-tight group-hover:text-foreground transition-colors line-clamp-1">
        {title}
      </div>

      {/* Metric value and meaningful trend row */}
      <div className="flex items-baseline justify-between gap-2 mt-1 min-w-0">
        <div className="font-bold tracking-tight text-[22px] sm:text-[24px] leading-none text-foreground font-mono tabular-nums min-w-0">
          {value}
        </div>

        {/* Semantic Trend Indicator */}
        {trend && (
          <div
            className={cn(
              "flex items-center gap-0.5 text-[11px] font-mono font-medium shrink-0",
              trend.isNeutral
                ? "text-muted-foreground"
                : trend.isPositive
                ? "text-emerald-600 dark:text-emerald-400"
                : "text-rose-600 dark:text-rose-400"
            )}
            title={trend.label || `${trend.value} vs previous period`}
          >
            {trend.isNeutral ? (
              <Minus className="w-3 h-3" />
            ) : trend.isPositive ? (
              <TrendingUp className="w-3 h-3" />
            ) : (
              <TrendingDown className="w-3 h-3" />
            )}
            <span>{trend.value}</span>
          </div>
        )}
      </div>
    </div>
  );
};

export default OverviewKpiCard;
