"use client";

import React, {
  memo,
  useCallback,
  useEffect,
  useId,
  useMemo,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { Brush } from "@visx/brush";
import { chartCssVars, useChartStable } from "../chart-context";
import { renderPatternPreset, PatternPresetId } from "../pattern-preset";
import { cn } from "@/lib/utils";

export type Margin = {
  top: number;
  right: number;
  bottom: number;
  left: number;
};

export interface BrushSelection {
  start: Date;
  end: Date;
}

export interface SelectionPatternConfig {
  preset: PatternPresetId;
  color?: string;
  scale?: number;
  strokeWidth?: number;
  radius?: number;
  complement?: boolean;
  fill?: string;
  tileBackground?: string;
  opacity?: number;
}

export interface ChartBrushProps {
  onSelectionChange?: (selection: BrushSelection | null) => void;
  brushDirection?: "horizontal" | "vertical" | "both";
  selectedBoxStyle?: React.SVGProps<SVGRectElement>;
  initialSelection?: BrushSelection | null;
  selection?: BrushSelection | null;
  useWindowMoveEvents?: boolean;
  blurPx?: number;
  fadeOuterEdges?: boolean;
  selectionPattern?: SelectionPatternConfig;
}

function normalizeDate(val: unknown): Date {
  if (val instanceof Date) return val;
  if (typeof val === "number" || typeof val === "string") return new Date(val);
  return new Date();
}

function resolveFadeStyles(side: "left" | "right", opts: { blurPx: number; fadeOuterEdges: boolean }) {
  let maskImage: string | undefined;
  const fadePct = "15%";
  if (opts.fadeOuterEdges) {
    maskImage =
      side === "left"
        ? `linear-gradient(to right, transparent 0%, black ${fadePct}, black 100%)`
        : `linear-gradient(to left, transparent 0%, black ${fadePct}, black 100%)`;
  }
  return {
    pointerEvents: "none" as const,
    backdropFilter: opts.blurPx > 0 ? `blur(${opts.blurPx}px)` : undefined,
    WebkitBackdropFilter: opts.blurPx > 0 ? `blur(${opts.blurPx}px)` : undefined,
    maskImage,
    WebkitMaskImage: maskImage,
  };
}

function BrushBlurOverlayPortal({
  containerRef,
  margin,
  innerWidth,
  innerHeight,
  selectionX0,
  selectionX1,
  blurPx = 1.5,
  fadeOuterEdges = true,
}: {
  containerRef: React.RefObject<HTMLDivElement | null>;
  margin: Margin;
  innerWidth: number;
  innerHeight: number;
  selectionX0: number;
  selectionX1: number;
  blurPx?: number;
  fadeOuterEdges?: boolean;
}) {
  const [mounted, setMounted] = useState(false);
  const options = {
    blurPx: Math.min(5, Math.max(0, blurPx)),
    fadeOuterEdges,
  };

  useEffect(() => {
    setMounted(true);
  }, []);

  const container = containerRef?.current;
  if (!mounted || !container) return null;

  const leftBound = Math.max(0, Math.min(selectionX0, selectionX1, innerWidth));
  const rightBound = Math.max(leftBound, Math.min(Math.max(selectionX0, selectionX1), innerWidth));
  const leftWidth = Math.max(0, leftBound);
  const rightWidth = Math.max(0, innerWidth - rightBound);

  if (leftWidth <= 0 && rightWidth <= 0) return null;

  const top = margin.top;
  const left = margin.left;

  return createPortal(
    <div aria-hidden="true" className="pointer-events-none absolute inset-0 z-[1]">
      {leftWidth > 0 && (
        <div
          className="absolute"
          style={{
            ...resolveFadeStyles("left", options),
            top,
            left,
            width: leftWidth,
            height: innerHeight,
          }}
        />
      )}
      {rightWidth > 0 && (
        <div
          className="absolute"
          style={{
            ...resolveFadeStyles("right", options),
            top,
            left: left + rightBound,
            width: rightWidth,
            height: innerHeight,
          }}
        />
      )}
    </div>,
    container
  );
}

function BrushPatternPortal({
  containerRef,
  margin,
  innerWidth,
  innerHeight,
  selectionX0,
  selectionX1,
  pattern,
}: {
  containerRef: React.RefObject<HTMLDivElement | null>;
  margin: Margin;
  innerWidth: number;
  innerHeight: number;
  selectionX0: number;
  selectionX1: number;
  pattern?: SelectionPatternConfig;
}) {
  const [mounted, setMounted] = useState(false);
  const patternId = useId().replace(/:/g, "");

  useEffect(() => {
    setMounted(true);
  }, []);

  const container = containerRef?.current;
  if (!mounted || !container || !pattern || pattern.preset === "none") return null;

  const leftBound = Math.max(0, Math.min(selectionX0, selectionX1, innerWidth));
  const selWidth = Math.max(leftBound, Math.min(Math.max(selectionX0, selectionX1), innerWidth)) - leftBound;

  if (selWidth <= 0) return null;

  const top = margin.top;
  const left = margin.left;

  const patternDef = renderPatternPreset(pattern.preset, patternId, {
    color: pattern.color,
    scale: pattern.scale,
    strokeWidth: pattern.strokeWidth,
    radius: pattern.radius,
    complement: pattern.complement,
    fill: pattern.fill,
    tileBackground: pattern.tileBackground,
  });

  if (!patternDef) return null;

  return createPortal(
    <svg aria-hidden="true" className="pointer-events-none absolute inset-0 z-[1]" width="100%" height="100%">
      <defs>{patternDef}</defs>
      <rect
        x={left + leftBound}
        y={top}
        width={selWidth}
        height={innerHeight}
        fill={`url(#${patternId})`}
        fillOpacity={pattern.opacity ?? 1}
      />
    </svg>,
    container
  );
}

function BrushHandlePillPortal({
  containerRef,
  margin,
  innerWidth,
  innerHeight,
  selectionX0,
  selectionX1,
}: {
  containerRef: React.RefObject<HTMLDivElement | null>;
  margin: Margin;
  innerWidth: number;
  innerHeight: number;
  selectionX0: number;
  selectionX1: number;
}) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const container = containerRef?.current;
  if (!mounted || !container) return null;

  const leftBound = Math.max(0, Math.min(selectionX0, selectionX1, innerWidth));
  const rightBound = Math.max(leftBound, Math.min(Math.max(selectionX0, selectionX1), innerWidth));

  const top = margin.top + (innerHeight - 24) / 2;
  const left = margin.left;
  const handlePositions = leftBound === rightBound ? [leftBound] : [leftBound, rightBound];

  return createPortal(
    <div aria-hidden="true" className="pointer-events-none absolute inset-0 z-[2]">
      {handlePositions.map((pos, idx) => (
        <div
          key={idx}
          className="absolute shrink-0 rounded-full shadow-xs transition-colors"
          style={{
            top,
            left: left + pos - 2,
            width: 4,
            height: 24,
            backgroundColor: "var(--chart-brush-border, #CBD5E1)",
          }}
        />
      ))}
    </div>,
    container
  );
}

function CustomBrushHandle({
  x,
  y,
  width,
  height,
  className,
}: {
  x: number;
  y: number;
  width: number;
  height: number;
  className?: string;
}) {
  const isHorizontal = className?.includes("left") || className?.includes("right");
  return (
    <rect
      x={x}
      y={y}
      width={width}
      height={height}
      className={className}
      fill="transparent"
      style={{ cursor: isHorizontal ? "ew-resize" : "ns-resize" }}
    />
  );
}

const ChartBrushInner = memo(function ChartBrushInner({
  brushDirection = "horizontal",
  selectedBoxStyle,
  initialSelection,
  useWindowMoveEvents = true,
  xScale,
  yScale,
  innerWidth,
  innerHeight,
  margin,
  onBrushPreview,
  onBrushCommit,
  blurPx,
  fadeOuterEdges,
  selectionPattern,
}: {
  brushDirection?: "horizontal" | "vertical" | "both";
  selectedBoxStyle?: React.SVGProps<SVGRectElement>;
  initialSelection?: BrushSelection | null;
  useWindowMoveEvents?: boolean;
  xScale: any;
  yScale: any;
  innerWidth: number;
  innerHeight: number;
  margin: Margin;
  onBrushPreview?: (bounds: any) => void;
  onBrushCommit?: (bounds: any) => void;
  blurPx?: number;
  fadeOuterEdges?: boolean;
  selectionPattern?: SelectionPatternConfig;
}) {
  const { containerRef } = useChartStable();

  const initialPosition = useMemo(() => {
    if (!initialSelection || innerWidth <= 0 || innerHeight <= 0 || !xScale) return undefined;
    const startX = Math.max(0, xScale(initialSelection.start) ?? 0);
    const endX = Math.min(innerWidth, xScale(initialSelection.end) ?? innerWidth);
    if (endX <= startX) return undefined;
    return {
      start: { x: startX, y: 0 },
      end: { x: endX, y: innerHeight },
    };
  }, [initialSelection, xScale, innerWidth, innerHeight]);

  const [pixelBounds, setPixelBounds] = useState(() => ({
    x0: initialPosition?.start.x ?? 0,
    x1: initialPosition?.end.x ?? innerWidth,
  }));

  useEffect(() => {
    setPixelBounds({
      x0: initialPosition?.start.x ?? 0,
      x1: initialPosition?.end.x ?? innerWidth,
    });
  }, [initialPosition, innerWidth]);

  const handleBrushChange = useCallback(
    (bounds: any) => {
      if (!bounds || bounds.x0 === undefined || bounds.x1 === undefined || !xScale) return;
      const d0 = normalizeDate(bounds.x0);
      const d1 = normalizeDate(bounds.x1);
      const minX = Math.max(0, xScale(d0 < d1 ? d0 : d1) ?? 0);
      const maxX = Math.min(innerWidth, xScale(d1 > d0 ? d1 : d0) ?? innerWidth);
      if (maxX > minX) {
        const pb = { x0: minX, x1: maxX };
        setPixelBounds(pb);
        onBrushPreview?.(bounds);
      }
    },
    [innerWidth, xScale, onBrushPreview]
  );

  const handleBrushEnd = useCallback(
    (bounds: any) => {
      handleBrushChange(bounds);
      onBrushCommit?.(bounds);
    },
    [handleBrushChange, onBrushCommit]
  );

  const defaultBoxStyle = useMemo(
    () => ({
      fill: "transparent",
      fillOpacity: 0,
      stroke: "var(--chart-brush-border, #CBD5E1)",
      strokeWidth: 1,
    }),
    []
  );

  return (
    <g className="chart-brush">
      <BrushBlurOverlayPortal
        containerRef={containerRef}
        margin={margin}
        innerWidth={innerWidth}
        innerHeight={innerHeight}
        selectionX0={pixelBounds.x0}
        selectionX1={pixelBounds.x1}
        blurPx={blurPx}
        fadeOuterEdges={fadeOuterEdges}
      />
      <BrushPatternPortal
        containerRef={containerRef}
        margin={margin}
        innerWidth={innerWidth}
        innerHeight={innerHeight}
        selectionX0={pixelBounds.x0}
        selectionX1={pixelBounds.x1}
        pattern={selectionPattern}
      />
      <BrushHandlePillPortal
        containerRef={containerRef}
        margin={margin}
        innerWidth={innerWidth}
        innerHeight={innerHeight}
        selectionX0={pixelBounds.x0}
        selectionX1={pixelBounds.x1}
      />
      <Brush
        key={`brush-${innerWidth}-${innerHeight}`}
        brushDirection={brushDirection}
        handleSize={8}
        width={innerWidth}
        height={innerHeight}
        initialBrushPosition={initialPosition}
        margin={useWindowMoveEvents ? margin : { top: 0, left: 0, right: 0, bottom: 0 }}
        onChange={handleBrushChange}
        onBrushEnd={handleBrushEnd}
        renderBrushHandle={CustomBrushHandle}
        selectedBoxStyle={selectedBoxStyle ?? defaultBoxStyle}
        useWindowMoveEvents={useWindowMoveEvents}
        xScale={xScale}
        yScale={yScale}
      />
    </g>
  );
});

export function ChartBrush({
  onSelectionChange,
  brushDirection = "horizontal",
  selectedBoxStyle,
  initialSelection,
  useWindowMoveEvents = true,
  blurPx,
  fadeOuterEdges,
  selectionPattern,
}: ChartBrushProps) {
  const { xScale, yScale, innerWidth, innerHeight, margin, isLoaded } = useChartStable();

  const toSelection = useCallback((bounds: any): BrushSelection | null => {
    if (!bounds || bounds.x0 === undefined || bounds.x1 === undefined) return null;
    const d0 = normalizeDate(bounds.x0);
    const d1 = normalizeDate(bounds.x1);
    if (d0.getTime() === d1.getTime()) return null;
    return {
      start: d0 < d1 ? d0 : d1,
      end: d1 > d0 ? d1 : d0,
    };
  }, []);

  const handleChange = useCallback(
    (bounds: any) => {
      onSelectionChange?.(toSelection(bounds));
    },
    [onSelectionChange, toSelection]
  );

  if (!isLoaded || innerWidth <= 0 || innerHeight <= 0) {
    return null;
  }

  return (
    <ChartBrushInner
      brushDirection={brushDirection}
      selectedBoxStyle={selectedBoxStyle}
      initialSelection={initialSelection}
      useWindowMoveEvents={useWindowMoveEvents}
      xScale={xScale}
      yScale={yScale}
      innerWidth={innerWidth}
      innerHeight={innerHeight}
      margin={margin}
      onBrushPreview={handleChange}
      onBrushCommit={handleChange}
      blurPx={blurPx}
      fadeOuterEdges={fadeOuterEdges}
      selectionPattern={selectionPattern}
    />
  );
}

ChartBrush.displayName = "ChartBrush";
