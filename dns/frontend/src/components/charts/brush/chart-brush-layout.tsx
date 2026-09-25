"use client";

import React, { memo, useCallback, useEffect, useMemo, useState } from "react";
import { cn } from "@/lib/utils";
import type { BrushSelection } from "./chart-brush";

export interface ChartBrushLayoutState {
  xDomain?: [Date, Date];
  xDomainSlotCount?: number;
  brushSelection: BrushSelection | null;
  onBrushSelectionChange: (selection: BrushSelection | null) => void;
}

export interface ChartBrushLayoutProps {
  data: Record<string, any>[];
  xDataKey?: string;
  xExtentMax?: Date;
  enabled?: boolean;
  height?: number;
  fitMainContent?: boolean;
  className?: string;
  children: (layout: ChartBrushLayoutState) => React.ReactNode;
  brushStrip?: (layout: ChartBrushLayoutState) => React.ReactNode;
}

export function resolveBrushTrackXExtent<T extends Record<string, any>>(
  data: T[],
  getX: (d: T) => Date,
  xExtentMax?: Date
): [Date, Date] | null {
  if (!data || data.length === 0) return null;
  const dates = data
    .map(getX)
    .filter((d) => d instanceof Date && !isNaN(d.getTime()));
  if (dates.length === 0) return null;
  const min = new Date(Math.min(...dates.map((d) => d.getTime())));
  const max = xExtentMax ?? new Date(Math.max(...dates.map((d) => d.getTime())));
  return [min, max];
}

export const ChartBrushLayout = memo(function ChartBrushLayout({
  data,
  xDataKey = "date",
  xExtentMax,
  enabled = true,
  height = 72,
  fitMainContent = false,
  className,
  children,
  brushStrip,
}: ChartBrushLayoutProps) {
  const getX = useMemo(
    () => (item: Record<string, any>) => {
      const val = item[xDataKey];
      return val instanceof Date ? val : new Date(val);
    },
    [xDataKey]
  );

  const fullExtent = useMemo(
    () => resolveBrushTrackXExtent(data, getX, xExtentMax),
    [data, getX, xExtentMax]
  );

  const [selection, setSelection] = useState<BrushSelection | null>(null);

  useEffect(() => {
    if (fullExtent) {
      setSelection({ start: fullExtent[0], end: fullExtent[1] });
    } else {
      setSelection(null);
    }
  }, [fullExtent]);

  const handleSelectionChange = useCallback(
    (newSel: BrushSelection | null) => {
      if (!newSel) {
        if (fullExtent) {
          setSelection({ start: fullExtent[0], end: fullExtent[1] });
        }
        return;
      }
      setSelection(newSel);
    },
    [fullExtent]
  );

  const layoutState: ChartBrushLayoutState = useMemo(
    () => ({
      xDomain: enabled && selection ? [selection.start, selection.end] : undefined,
      xDomainSlotCount: enabled ? data.length : undefined,
      brushSelection: selection,
      onBrushSelectionChange: handleSelectionChange,
    }),
    [selection, data.length, enabled, handleSelectionChange]
  );

  return (
    <div
      className={cn(
        "flex size-full min-h-0 min-w-0 flex-col",
        fitMainContent ? "justify-start gap-1" : "gap-3",
        className
      )}
    >
      {/* Main Chart Canvas */}
      <div className={cn("min-h-0 min-w-0", fitMainContent ? "shrink-0" : "flex-1")}>
        {children(layoutState)}
      </div>

      {/* Brush / Overview Strip */}
      {enabled && brushStrip && (
        <div className="min-h-0 shrink-0 select-none" style={{ height }}>
          {brushStrip(layoutState)}
        </div>
      )}
    </div>
  );
});

ChartBrushLayout.displayName = "ChartBrushLayout";
