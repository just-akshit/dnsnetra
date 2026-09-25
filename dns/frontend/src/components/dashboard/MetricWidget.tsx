"use client";

import React from "react";
import Link from "next/link";
import { ArrowUpRight } from "lucide-react";
import { cn } from "@/lib/utils";

export interface MetricWidgetProps {
  title: string;
  value: string | number;
  subValue?: string;
  trend?: string;
  href?: string;
  isThreat?: boolean;
  className?: string;
}

export const MetricWidget: React.FC<MetricWidgetProps> = ({
  title,
  value,
  subValue,
  trend,
  href,
  isThreat = false,
  className,
}) => {
  const isPositiveThreat = isThreat && typeof value === "number" ? value > 0 : isThreat;

  const content = (
    <div
      className={cn(
        "group relative flex flex-col justify-between p-3.5 bg-card border border-border/70 rounded-md shadow-2xs transition-all duration-150",
        href && "hover:border-border hover:bg-muted/10 cursor-pointer",
        className
      )}
    >
      {/* Top Header: Title */}
      <div className="flex items-center justify-between gap-1">
        <span className="text-[12px] font-medium text-muted-foreground truncate">
          {title}
        </span>
        {href && (
          <ArrowUpRight className="w-3.5 h-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
        )}
      </div>

      {/* Main Metric Value */}
      <div className="my-2 flex items-baseline gap-1.5">
        <span
          className={cn(
            "text-2xl font-semibold tracking-tight text-foreground",
            isPositiveThreat ? "text-red-500 dark:text-red-400" : "text-foreground"
          )}
        >
          {typeof value === "number" ? value.toLocaleString() : value}
        </span>
        {subValue && (
          <span className="text-[11px] text-muted-foreground font-normal">
            {subValue}
          </span>
        )}
      </div>

      {/* Footer: Trend or Subtle Indicator */}
      <div className="flex items-center justify-between text-[11px] text-muted-foreground pt-1 border-t border-border/40">
        <span>{trend || (isPositiveThreat ? "Active incident" : "Active telemetry")}</span>
        {href && (
          <span className="text-primary text-[11px] opacity-0 group-hover:opacity-100 transition-opacity">
            View all →
          </span>
        )}
      </div>
    </div>
  );

  if (href) {
    return <Link href={href} className="block no-underline">{content}</Link>;
  }

  return content;
};

export default MetricWidget;
