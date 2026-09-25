"use client";

import React, { createContext, useContext, useState, useEffect, useCallback, useMemo } from "react";

export type TimeRangePreset =
  | "1m"
  | "5m"
  | "15m"
  | "30m"
  | "1h"
  | "6h"
  | "12h"
  | "24h"
  | "7d"
  | "30d"
  | "6mo"
  | "1y"
  | "custom";

export interface TimeRangeValue {
  preset: TimeRangePreset;
  label: string;
  startDate: Date;
  endDate: Date;
  isCustom: boolean;
}

export interface TimeRangeContextType {
  timeRange: TimeRangeValue;
  range: TimeRangePreset;
  setTimeRangePreset: (preset: TimeRangePreset) => void;
  setCustomTimeRange: (start: Date, end: Date) => void;
  isLive: boolean;
  setIsLive: (live: boolean) => void;
  isRefreshing: boolean;
  lastUpdated: Date | null;
  refreshCount: number;
  triggerRefresh: () => Promise<void>;
  registerRefreshHandler: (handler: () => Promise<void>) => () => void;
}

const PRESET_LABELS: Record<TimeRangePreset, string> = {
  "1m": "Last 1 minute",
  "5m": "Last 5 minutes",
  "15m": "Last 15 minutes",
  "30m": "Last 30 minutes",
  "1h": "Last 1 hour",
  "6h": "6 hours",
  "12h": "Last 12 hours",
  "24h": "Last 24 hours",
  "7d": "Last 7 days",
  "30d": "Last 30 days",
  "6mo": "Last 6 months",
  "1y": "Last 1 year",
  custom: "Custom Range",
};

const PRESET_MINUTES: Record<TimeRangePreset, number> = {
  "1m": 1,
  "5m": 5,
  "15m": 15,
  "30m": 30,
  "1h": 60,
  "6h": 360,
  "12h": 720,
  "24h": 1440,
  "7d": 10080,
  "30d": 43200,
  "6mo": 259200, // Rolling 180 days
  "1y": 525600,  // Rolling 365 days
  custom: 1440,
};

const calculateDatesForPreset = (preset: TimeRangePreset): { start: Date; end: Date } => {
  const end = new Date();
  const minutes = PRESET_MINUTES[preset] || 1440;
  const start = new Date(end.getTime() - minutes * 60 * 1000);
  return { start, end };
};

const TimeRangeContext = createContext<TimeRangeContextType | null>(null);

export const TimeRangeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [preset, setPreset] = useState<TimeRangePreset>("24h");
  const [customRange, setCustomRange] = useState<{ start: Date; end: Date }>(() =>
    calculateDatesForPreset("24h")
  );
  const [isLive, setIsLive] = useState<boolean>(false);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(new Date());
  const [refreshCount, setRefreshCount] = useState<number>(0);
  const refreshHandlersRef = React.useRef<Set<() => Promise<void>>>(new Set());

  const registerRefreshHandler = useCallback((handler: () => Promise<void>) => {
    refreshHandlersRef.current.add(handler);
    return () => {
      refreshHandlersRef.current.delete(handler);
    };
  }, []);

  const triggerRefresh = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const promises = Array.from(refreshHandlersRef.current).map((h) => h());
      await Promise.allSettled(promises);
      setLastUpdated(new Date());
      setRefreshCount((c) => c + 1);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  // Handle live auto-refresh timer (every 30 seconds if live)
  useEffect(() => {
    if (!isLive) return;
    const interval = setInterval(() => {
      triggerRefresh();
    }, 30000);
    return () => clearInterval(interval);
  }, [isLive, triggerRefresh]);

  const setTimeRangePreset = useCallback((newPreset: TimeRangePreset) => {
    setPreset(newPreset);
    if (newPreset !== "custom") {
      const { start, end } = calculateDatesForPreset(newPreset);
      setCustomRange({ start, end });
    }
  }, []);

  const setCustomTimeRange = useCallback((start: Date, end: Date) => {
    setPreset("custom");
    setCustomRange({ start, end });
  }, []);

  const timeRange: TimeRangeValue = useMemo(() => ({
    preset,
    label: preset === "custom" ? "Custom Range" : PRESET_LABELS[preset],
    startDate: customRange.start,
    endDate: customRange.end,
    isCustom: preset === "custom",
  }), [preset, customRange.start, customRange.end]);

  const contextValue = useMemo<TimeRangeContextType>(() => ({
    timeRange,
    range: preset,
    setTimeRangePreset,
    setCustomTimeRange,
    isLive,
    setIsLive,
    isRefreshing,
    lastUpdated,
    refreshCount,
    triggerRefresh,
    registerRefreshHandler,
  }), [
    timeRange,
    preset,
    setTimeRangePreset,
    setCustomTimeRange,
    isLive,
    isRefreshing,
    lastUpdated,
    refreshCount,
    triggerRefresh,
    registerRefreshHandler,
  ]);

  return (
    <TimeRangeContext.Provider value={contextValue}>
      {children}
    </TimeRangeContext.Provider>
  );
};

export const useTimeRange = (): TimeRangeContextType => {
  const ctx = useContext(TimeRangeContext);
  if (!ctx) {
    throw new Error("useTimeRange must be used within a TimeRangeProvider");
  }
  return ctx;
};
