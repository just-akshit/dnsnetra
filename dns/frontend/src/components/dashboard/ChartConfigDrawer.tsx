"use client";

import React, { useState, useEffect, useMemo, useRef } from "react";
import {
  X,
  Plus,
  Trash2,
  LineChart,
  BarChart3,
  PieChart,
  CandlestickChart as CandleIcon,
  Hash,
  ListOrdered,
  Eye,
  SlidersHorizontal,
  Clock,
  Layers,
  Database,
} from "lucide-react";
import {
  DashboardChartConfig,
  ChartType,
  DatasetId,
  SUPPORTED_DATASETS,
  CHART_TYPE_OPTIONS,
  ChartFilter,
} from "@/types/chart-config";
import { DashboardBundleData } from "@/types/api";
import { DynamicChartCard } from "@/components/dashboard/DynamicChartCard";
import { cn } from "@/lib/utils";

export interface ChartConfigDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  initialConfig: DashboardChartConfig | null;
  onSave: (config: DashboardChartConfig) => void;
  data: DashboardBundleData | null;
}

const DEFAULT_NEW_CONFIG: DashboardChartConfig = {
  id: "",
  title: "New Custom Chart",
  subtitle: "Custom analytical metric telemetry",
  chartType: "timeseries",
  dataset: "dnsAnalytics",
  metric: "total_queries",
  aggregation: "count",
  timeRange: { mode: "global" },
  interval: "auto",
  gridSpan: "half",
};

export const ChartConfigDrawer: React.FC<ChartConfigDrawerProps> = ({
  isOpen,
  onClose,
  initialConfig,
  onSave,
  data,
}) => {
  const [formState, setFormState] = useState<DashboardChartConfig>(DEFAULT_NEW_CONFIG);
  const [activeTab, setActiveTab] = useState<"general" | "data" | "time" | "filters">("general");
  const [isRendered, setIsRendered] = useState(false);
  const [isAnimating, setIsAnimating] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);

  // Smooth animation mounting & unmounting lifecycle
  useEffect(() => {
    if (isOpen) {
      setIsRendered(true);
      const timer = setTimeout(() => setIsAnimating(true), 15);
      return () => clearTimeout(timer);
    } else {
      setIsAnimating(false);
      const timer = setTimeout(() => setIsRendered(false), 220);
      return () => clearTimeout(timer);
    }
  }, [isOpen]);

  // Prevent background body scrolling when modal is open
  useEffect(() => {
    if (isOpen) {
      const origOverflow = document.body.style.overflow;
      document.body.style.overflow = "hidden";
      return () => {
        document.body.style.overflow = origOverflow;
      };
    }
  }, [isOpen]);

  // Keyboard Escape listener
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  useEffect(() => {
    if (initialConfig) {
      setFormState({ ...initialConfig });
    } else {
      setFormState({
        ...DEFAULT_NEW_CONFIG,
        id: `chart-${Date.now()}`,
        title: "New Custom Chart",
      });
    }
  }, [initialConfig, isOpen]);

  const selectedDataset = useMemo(() => {
    return SUPPORTED_DATASETS.find((d) => d.id === formState.dataset) || SUPPORTED_DATASETS[0];
  }, [formState.dataset]);

  if (!isRendered) return null;

  const handleSave = () => {
    onSave(formState);
    onClose();
  };

  const handleAddFilter = () => {
    const newFilter: ChartFilter = {
      id: `filter-${Date.now()}`,
      field: selectedDataset.dimensions[0]?.id || "category",
      operator: "=",
      value: "",
    };
    setFormState({
      ...formState,
      filters: [...(formState.filters || []), newFilter],
    });
  };

  const handleRemoveFilter = (filterId: string) => {
    setFormState({
      ...formState,
      filters: (formState.filters || []).filter((f) => f.id !== filterId),
    });
  };

  const getChartIcon = (type: ChartType) => {
    switch (type) {
      case "timeseries": return <LineChart className="w-4 h-4" />;
      case "bar": return <BarChart3 className="w-4 h-4" />;
      case "donut": return <PieChart className="w-4 h-4" />;
      case "candlestick": return <CandleIcon className="w-4 h-4" />;
      case "stat": return <Hash className="w-4 h-4" />;
      case "toplist": return <ListOrdered className="w-4 h-4" />;
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
      className={cn(
        "fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 select-none",
        "transition-opacity duration-200 ease-out",
        isAnimating ? "opacity-100" : "opacity-0"
      )}
    >
      {/* Dimmed Overlay Backdrop */}
      <div
        className={cn(
          "fixed inset-0 bg-black/50 backdrop-blur-xs transition-opacity duration-200",
          isAnimating ? "opacity-100" : "opacity-0"
        )}
        onClick={onClose}
      />

      {/* Centered Modal Dialog Window */}
      <div
        ref={dialogRef}
        className={cn(
          "relative z-50 w-full max-w-4xl max-h-[90vh] flex flex-col",
          "bg-white dark:bg-[#121826]",
          "border border-[#EBEBEB] dark:border-[#1E283D]",
          "rounded-[16px] shadow-2xl overflow-hidden",
          "transition-all duration-220 ease-out transform",
          isAnimating ? "scale-100 translate-y-0 opacity-100" : "scale-[0.98] translate-y-2 opacity-0"
        )}
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#EBEBEB] dark:border-[#1E283D] shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-[8px] bg-[#2F6FED]/10 text-[#2F6FED] flex items-center justify-center">
              <SlidersHorizontal className="w-4 h-4" />
            </div>
            <div>
              <h2 id="modal-title" className="text-[16px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em]">
                {initialConfig ? "Configure Chart" : "Add New Chart"}
              </h2>
              <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF]">
                Customize your visualization, target metrics, time overrides, and filters
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="p-1.5 rounded-[6px] text-[#6B6B6B] hover:text-[#1A1A1A] dark:text-[#9CA3AF] dark:hover:text-[#F3F4F6] hover:bg-[#F2F2F2] dark:hover:bg-[#1C2438] transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Live Real-Time Preview Area (Fixed under header) */}
        <div className="px-6 py-3.5 bg-neutral-50/80 dark:bg-[#0E1320]/80 border-b border-[#EBEBEB] dark:border-[#1E283D] shrink-0">
          <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-[#9C9C9C] dark:text-[#6B7280] mb-1.5">
            <Eye className="w-3 h-3 text-[#2F6FED]" />
            <span>Live Preview</span>
          </div>

          <div className="pointer-events-none opacity-95 max-h-[220px] overflow-hidden rounded-[10px]">
            <DynamicChartCard
              config={formState}
              data={data}
              onConfigure={() => {}}
              onDuplicate={() => {}}
              onRemove={() => {}}
              onTimeRangeChange={() => {}}
            />
          </div>
        </div>

        {/* Section Navigation Tabs */}
        <div className="flex items-center gap-1 px-6 border-b border-[#EBEBEB] dark:border-[#1E283D] bg-white dark:bg-[#121826] text-[13px] pt-1 shrink-0">
          {[
            { id: "general", label: "Chart & Layout", icon: Layers },
            { id: "data", label: "Data & Metrics", icon: Database },
            { id: "time", label: "Time & Interval", icon: Clock },
            { id: "filters", label: "Filters", icon: SlidersHorizontal },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id as any)}
                className={cn(
                  "flex items-center gap-1.5 px-3.5 py-2.5 font-medium border-b-2 transition-colors cursor-pointer text-[12px]",
                  isActive
                    ? "border-[#2F6FED] text-[#2F6FED] font-semibold"
                    : "border-transparent text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
                )}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Scrollable Form Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {/* TAB 1: GENERAL & VISUALIZATION TYPE */}
          {activeTab === "general" && (
            <div className="space-y-4">
              {/* Title & Subtitle */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-[12px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6] mb-1">
                    Chart Title
                  </label>
                  <input
                    type="text"
                    value={formState.title}
                    onChange={(e) => setFormState({ ...formState, title: e.target.value })}
                    className="w-full px-3 py-1.5 text-[13px] rounded-[6px] bg-white dark:bg-[#1C2438] border border-[#D9D9D9] dark:border-[#2D3A54] text-[#1A1A1A] dark:text-[#F3F4F6] focus:border-[#2F6FED] focus:outline-hidden"
                  />
                </div>
                <div>
                  <label className="block text-[12px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6] mb-1">
                    Subtitle (Optional)
                  </label>
                  <input
                    type="text"
                    value={formState.subtitle || ""}
                    onChange={(e) => setFormState({ ...formState, subtitle: e.target.value })}
                    className="w-full px-3 py-1.5 text-[13px] rounded-[6px] bg-white dark:bg-[#1C2438] border border-[#D9D9D9] dark:border-[#2D3A54] text-[#1A1A1A] dark:text-[#F3F4F6] focus:border-[#2F6FED] focus:outline-hidden"
                  />
                </div>
              </div>

              {/* Grid Span */}
              <div>
                <label className="block text-[12px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6] mb-1.5">
                  Layout Width
                </label>
                <div className="grid grid-cols-2 gap-2 text-[12px]">
                  <button
                    type="button"
                    onClick={() => setFormState({ ...formState, gridSpan: "half" })}
                    className={cn(
                      "p-2.5 rounded-[6px] border text-left cursor-pointer transition-all",
                      formState.gridSpan === "half"
                        ? "border-[#2F6FED] bg-[#2F6FED]/5 text-[#2F6FED] font-semibold"
                        : "border-[#D9D9D9] dark:border-[#2D3A54] text-[#6B6B6B] dark:text-[#9CA3AF] hover:border-[#9C9C9C]"
                    )}
                  >
                    <div className="font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">Half Width (50%)</div>
                    <div className="text-[11px] text-muted-foreground mt-0.5">Fits in 2-column grid row</div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setFormState({ ...formState, gridSpan: "full" })}
                    className={cn(
                      "p-2.5 rounded-[6px] border text-left cursor-pointer transition-all",
                      formState.gridSpan === "full"
                        ? "border-[#2F6FED] bg-[#2F6FED]/5 text-[#2F6FED] font-semibold"
                        : "border-[#D9D9D9] dark:border-[#2D3A54] text-[#6B6B6B] dark:text-[#9CA3AF] hover:border-[#9C9C9C]"
                    )}
                  >
                    <div className="font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">Full Width (100%)</div>
                    <div className="text-[11px] text-muted-foreground mt-0.5">Spans complete dashboard width</div>
                  </button>
                </div>
              </div>

              {/* Chart Type Selection */}
              <div>
                <label className="block text-[12px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6] mb-1.5">
                  Visualization Type
                </label>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                  {CHART_TYPE_OPTIONS.map((opt) => {
                    const isSelected = formState.chartType === opt.type;
                    return (
                      <button
                        key={opt.type}
                        type="button"
                        onClick={() => setFormState({ ...formState, chartType: opt.type })}
                        className={cn(
                          "flex flex-col p-3 rounded-[8px] border text-left cursor-pointer transition-all",
                          isSelected
                            ? "border-[#2F6FED] bg-[#2F6FED]/5 dark:bg-[#2F6FED]/10 shadow-xs"
                            : "border-[#EBEBEB] dark:border-[#1E283D] bg-white dark:bg-[#121826] hover:border-[#D9D9D9]"
                        )}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <div
                            className={cn(
                              "w-6 h-6 rounded flex items-center justify-center",
                              isSelected
                                ? "bg-[#2F6FED] text-white"
                                : "bg-neutral-100 dark:bg-neutral-800 text-[#6B6B6B] dark:text-[#9CA3AF]"
                            )}
                          >
                            {getChartIcon(opt.type)}
                          </div>
                          <span
                            className={cn(
                              "text-[13px] font-medium",
                              isSelected
                                ? "text-[#2F6FED] dark:text-[#60A5FA] font-semibold"
                                : "text-[#1A1A1A] dark:text-[#F3F4F6]"
                            )}
                          >
                            {opt.label}
                          </span>
                        </div>
                        <span className="text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF] leading-tight">
                          {opt.description}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: DATASET & METRIC */}
          {activeTab === "data" && (
            <div className="space-y-4">
              {/* Dataset Selector */}
              <div>
                <label className="block text-[12px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6] mb-1.5">
                  Dataset
                </label>
                <select
                  value={formState.dataset}
                  onChange={(e) => {
                    const nextDatasetId = e.target.value as DatasetId;
                    const nextMeta = SUPPORTED_DATASETS.find((d) => d.id === nextDatasetId);
                    setFormState({
                      ...formState,
                      dataset: nextDatasetId,
                      metric: nextMeta?.metrics[0]?.id || "total_queries",
                    });
                  }}
                  className="w-full px-3 py-2 text-[13px] rounded-[6px] bg-white dark:bg-[#1C2438] border border-[#D9D9D9] dark:border-[#2D3A54] text-[#1A1A1A] dark:text-[#F3F4F6] focus:border-[#2F6FED] focus:outline-hidden"
                >
                  {SUPPORTED_DATASETS.map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.name} — {d.description}
                    </option>
                  ))}
                </select>
              </div>

              {/* Metric Selector */}
              <div>
                <label className="block text-[12px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6] mb-1.5">
                  Target Metric
                </label>
                <select
                  value={formState.metric}
                  onChange={(e) => setFormState({ ...formState, metric: e.target.value })}
                  className="w-full px-3 py-2 text-[13px] rounded-[6px] bg-white dark:bg-[#1C2438] border border-[#D9D9D9] dark:border-[#2D3A54] text-[#1A1A1A] dark:text-[#F3F4F6] focus:border-[#2F6FED] focus:outline-hidden"
                >
                  {selectedDataset.metrics.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.name} ({m.type})
                    </option>
                  ))}
                </select>
              </div>

              {/* Aggregation */}
              <div>
                <label className="block text-[12px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6] mb-1.5">
                  Aggregation Function
                </label>
                <div className="grid grid-cols-3 sm:grid-cols-6 gap-1.5">
                  {["count", "sum", "avg", "p50", "p95", "max"].map((agg) => (
                    <button
                      key={agg}
                      type="button"
                      onClick={() => setFormState({ ...formState, aggregation: agg as any })}
                      className={cn(
                        "py-1.5 px-2 rounded-[4px] border text-center text-[12px] uppercase font-mono cursor-pointer transition-colors",
                        formState.aggregation === agg
                          ? "border-[#2F6FED] bg-[#2F6FED]/10 text-[#2F6FED] font-semibold"
                          : "border-[#D9D9D9] dark:border-[#2D3A54] text-[#6B6B6B] dark:text-[#9CA3AF] hover:border-[#9C9C9C]"
                      )}
                    >
                      {agg}
                    </button>
                  ))}
                </div>
              </div>

              {/* Group by Dimension (for Bar, Donut, TopList) */}
              {["bar", "donut", "toplist"].includes(formState.chartType) && (
                <div>
                  <label className="block text-[12px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6] mb-1.5">
                    Group By / Dimension
                  </label>
                  <select
                    value={formState.dimension || selectedDataset.dimensions[0]?.id}
                    onChange={(e) => setFormState({ ...formState, dimension: e.target.value })}
                    className="w-full px-3 py-2 text-[13px] rounded-[6px] bg-white dark:bg-[#1C2438] border border-[#D9D9D9] dark:border-[#2D3A54] text-[#1A1A1A] dark:text-[#F3F4F6] focus:border-[#2F6FED] focus:outline-hidden"
                  >
                    {selectedDataset.dimensions.map((dim) => (
                      <option key={dim.id} value={dim.id}>
                        {dim.name}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: TIME & INTERVAL */}
          {activeTab === "time" && (
            <div className="space-y-4">
              {/* Time Range Mode */}
              <div>
                <label className="block text-[12px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6] mb-1.5">
                  Time Range Mode
                </label>
                <div className="grid grid-cols-2 gap-2 text-[12px]">
                  <button
                    type="button"
                    onClick={() =>
                      setFormState({
                        ...formState,
                        timeRange: { mode: "global" },
                      })
                    }
                    className={cn(
                      "p-3 rounded-[6px] border text-left cursor-pointer transition-all",
                      formState.timeRange.mode === "global"
                        ? "border-[#2F6FED] bg-[#2F6FED]/5 text-[#2F6FED] font-semibold"
                        : "border-[#D9D9D9] dark:border-[#2D3A54] text-[#6B6B6B] dark:text-[#9CA3AF] hover:border-[#9C9C9C]"
                    )}
                  >
                    <div className="font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">Global Dashboard Range</div>
                    <div className="text-[11px] text-muted-foreground mt-0.5">
                      Inherits active time selection automatically
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() =>
                      setFormState({
                        ...formState,
                        timeRange: { mode: "custom", customRange: "1h" },
                      })
                    }
                    className={cn(
                      "p-3 rounded-[6px] border text-left cursor-pointer transition-all",
                      formState.timeRange.mode === "custom"
                        ? "border-[#2F6FED] bg-[#2F6FED]/5 text-[#2F6FED] font-semibold"
                        : "border-[#D9D9D9] dark:border-[#2D3A54] text-[#6B6B6B] dark:text-[#9CA3AF] hover:border-[#9C9C9C]"
                    )}
                  >
                    <div className="font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">Custom Chart Range</div>
                    <div className="text-[11px] text-muted-foreground mt-0.5">
                      Fixed time window independent of dashboard
                    </div>
                  </button>
                </div>
              </div>

              {/* Custom Range Selector */}
              {formState.timeRange.mode === "custom" && (
                <div>
                  <label className="block text-[12px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6] mb-1.5">
                    Custom Time Range
                  </label>
                  <div className="grid grid-cols-3 sm:grid-cols-6 gap-1.5">
                    {["5m", "15m", "1h", "6h", "24h", "7d"].map((r) => (
                      <button
                        key={r}
                        type="button"
                        onClick={() =>
                          setFormState({
                            ...formState,
                            timeRange: { mode: "custom", customRange: r },
                          })
                        }
                        className={cn(
                          "py-1.5 px-2 rounded-[4px] border text-center text-[12px] font-mono cursor-pointer transition-colors",
                          formState.timeRange.customRange === r
                            ? "border-[#2F6FED] bg-[#2F6FED]/10 text-[#2F6FED] font-semibold"
                            : "border-[#D9D9D9] dark:border-[#2D3A54] text-[#6B6B6B] dark:text-[#9CA3AF] hover:border-[#9C9C9C]"
                        )}
                      >
                        {r}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Interval / Bucket Size */}
              <div>
                <label className="block text-[12px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6] mb-1.5">
                  Interval / Bucket Size
                </label>
                <div className="grid grid-cols-3 sm:grid-cols-6 gap-1.5">
                  {["auto", "1m", "5m", "15m", "1h", "1d"].map((int) => (
                    <button
                      key={int}
                      type="button"
                      onClick={() => setFormState({ ...formState, interval: int })}
                      className={cn(
                        "py-1.5 px-2 rounded-[4px] border text-center text-[12px] font-mono cursor-pointer transition-colors",
                        (formState.interval || "auto") === int
                          ? "border-[#2F6FED] bg-[#2F6FED]/10 text-[#2F6FED] font-semibold"
                          : "border-[#D9D9D9] dark:border-[#2D3A54] text-[#6B6B6B] dark:text-[#9CA3AF] hover:border-[#9C9C9C]"
                      )}
                    >
                      {int}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: FILTERS */}
          {activeTab === "filters" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-[13px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6]">
                    Chart-Specific Filters
                  </h3>
                  <p className="text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF]">
                    Scoped only to this chart (combines with global filters)
                  </p>
                </div>
                <button
                  type="button"
                  onClick={handleAddFilter}
                  className="flex items-center gap-1 px-2.5 py-1 text-[12px] font-medium bg-[#2F6FED]/10 text-[#2F6FED] hover:bg-[#2F6FED]/20 rounded-[6px] transition-colors cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Add Filter</span>
                </button>
              </div>

              {(!formState.filters || formState.filters.length === 0) && (
                <div className="p-4 rounded-[6px] border border-dashed border-[#D9D9D9] dark:border-[#2D3A54] text-center text-[12px] text-[#9C9C9C] dark:text-[#6B7280]">
                  No local filters configured. All dataset queries will apply.
                </div>
              )}

              <div className="space-y-2">
                {(formState.filters || []).map((f) => (
                  <div
                    key={f.id}
                    className="flex items-center gap-2 p-2.5 rounded-[6px] bg-neutral-50 dark:bg-[#1C2438] border border-[#EBEBEB] dark:border-[#2D3A54]"
                  >
                    <select
                      value={f.field}
                      onChange={(e) => {
                        const updated = formState.filters?.map((fl) =>
                          fl.id === f.id ? { ...fl, field: e.target.value } : fl
                        );
                        setFormState({ ...formState, filters: updated });
                      }}
                      className="px-2 py-1 text-[12px] rounded bg-white dark:bg-[#121826] border border-[#D9D9D9] dark:border-[#2D3A54] text-[#1A1A1A] dark:text-[#F3F4F6]"
                    >
                      {selectedDataset.dimensions.map((dim) => (
                        <option key={dim.id} value={dim.id}>
                          {dim.name}
                        </option>
                      ))}
                    </select>

                    <select
                      value={f.operator}
                      onChange={(e) => {
                        const updated = formState.filters?.map((fl) =>
                          fl.id === f.id ? { ...fl, operator: e.target.value as any } : fl
                        );
                        setFormState({ ...formState, filters: updated });
                      }}
                      className="px-2 py-1 text-[12px] rounded bg-white dark:bg-[#121826] border border-[#D9D9D9] dark:border-[#2D3A54] text-[#1A1A1A] dark:text-[#F3F4F6] font-mono"
                    >
                      <option value="=">=</option>
                      <option value="!=">!=</option>
                      <option value="contains">contains</option>
                      <option value=">">&gt;</option>
                      <option value="<">&lt;</option>
                    </select>

                    <input
                      type="text"
                      placeholder="Value..."
                      value={f.value}
                      onChange={(e) => {
                        const updated = formState.filters?.map((fl) =>
                          fl.id === f.id ? { ...fl, value: e.target.value } : fl
                        );
                        setFormState({ ...formState, filters: updated });
                      }}
                      className="flex-1 px-2.5 py-1 text-[12px] rounded bg-white dark:bg-[#121826] border border-[#D9D9D9] dark:border-[#2D3A54] text-[#1A1A1A] dark:text-[#F3F4F6]"
                    />

                    <button
                      type="button"
                      onClick={() => handleRemoveFilter(f.id)}
                      className="p-1 rounded text-red-500 hover:bg-red-50 dark:hover:bg-red-950/30 transition-colors cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer Actions (Fixed at bottom) */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-[#EBEBEB] dark:border-[#1E283D] bg-white dark:bg-[#121826] shrink-0">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-[13px] font-medium text-[#6B6B6B] dark:text-[#9CA3AF] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6] rounded-[6px] hover:bg-[#F2F2F2] dark:hover:bg-[#1C2438] transition-colors cursor-pointer"
          >
            Cancel
          </button>

          <button
            type="button"
            onClick={handleSave}
            className="px-4 py-2 text-[13px] font-medium bg-[#2F6FED] hover:bg-[#255ED4] text-white rounded-[6px] shadow-xs transition-colors cursor-pointer"
          >
            {initialConfig ? "Save Changes" : "Add to Dashboard"}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ChartConfigDrawer;
