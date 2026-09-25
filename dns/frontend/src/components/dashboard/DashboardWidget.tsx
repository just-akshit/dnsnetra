"use client";

import React from "react";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

export interface DashboardWidgetProps {
  title: React.ReactNode;
  description?: React.ReactNode;
  headerAction?: React.ReactNode;
  loading?: boolean;
  error?: string | null;
  empty?: boolean;
  emptyMessage?: string;
  className?: string;
  children?: React.ReactNode;
}

export const DashboardWidget: React.FC<DashboardWidgetProps> = ({
  title,
  description,
  headerAction,
  loading = false,
  error = null,
  empty = false,
  emptyMessage = "No data available for this window.",
  className,
  children,
}) => {
  return (
    <div
      className={cn(
        "relative flex flex-col bg-card border border-border/70 rounded-md shadow-2xs overflow-hidden",
        className
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-border/50 gap-2">
        <div>
          <h3 className="text-[13px] font-semibold text-foreground tracking-tight truncate">
            {title}
          </h3>
          {description && (
            <p className="text-[11px] text-muted-foreground">{description}</p>
          )}
        </div>
        {headerAction && <div className="shrink-0">{headerAction}</div>}
      </div>

      {/* Content */}
      <div className="p-4 flex-1 flex flex-col justify-center">
        {loading ? (
          <div className="space-y-2 py-4">
            <Skeleton className="h-4 w-1/3 rounded" />
            <Skeleton className="h-20 w-full rounded" />
          </div>
        ) : error ? (
          <div className="py-6 text-center space-y-1">
            <p className="text-xs text-destructive font-medium">{error}</p>
          </div>
        ) : empty ? (
          <div className="py-8 text-center text-xs text-muted-foreground">
            {emptyMessage}
          </div>
        ) : (
          children
        )}
      </div>
    </div>
  );
};

export default DashboardWidget;
