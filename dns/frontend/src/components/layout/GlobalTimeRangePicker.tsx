"use client";

import React, { useState } from "react";
import { format } from "date-fns";
import { Calendar as CalendarIcon, ChevronDown, Check } from "lucide-react";
import { Popover, PopoverTrigger, PopoverPopup } from "@/components/ui/popover";
import { Calendar } from "@/components/ui/calendar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useTimeRange, TimeRangePreset } from "@/context/TimeRangeContext";
import { cn } from "@/lib/utils";

const PRESET_OPTIONS: { label: string; preset: TimeRangePreset }[] = [
  { label: "Last 1 minute", preset: "1m" },
  { label: "Last 5 minutes", preset: "5m" },
  { label: "Last 15 minutes", preset: "15m" },
  { label: "Last 30 minutes", preset: "30m" },
  { label: "Last 1 hour", preset: "1h" },
  { label: "6 hours", preset: "6h" },
  { label: "Last 12 hours", preset: "12h" },
  { label: "Last 24 hours", preset: "24h" },
  { label: "Last 7 days", preset: "7d" },
  { label: "Last 30 days", preset: "30d" },
  { label: "Last 6 months", preset: "6mo" },
  { label: "Last 1 year", preset: "1y" },
];

export interface GlobalTimeRangePickerProps {
  trigger?: React.ReactNode;
  className?: string;
}

export const GlobalTimeRangePicker: React.FC<GlobalTimeRangePickerProps> = ({ trigger, className }) => {
  const { timeRange, setTimeRangePreset, setCustomTimeRange } = useTimeRange();
  const [open, setOpen] = useState(false);

  // Local state for custom range editing before Apply is clicked
  const [customInputText, setCustomInputText] = useState("");
  const [selectedRange, setSelectedRange] = useState<{
    from: Date | undefined;
    to: Date | undefined;
  }>({
    from: timeRange.startDate,
    to: timeRange.endDate,
  });

  const [startTimeStr, setStartTimeStr] = useState<string>(() =>
    format(timeRange.startDate, "yyyy-MM-dd HH:mm")
  );
  const [endTimeStr, setEndTimeStr] = useState<string>(() =>
    format(timeRange.endDate, "yyyy-MM-dd HH:mm")
  );

  const handleOpen = (nextOpen: boolean) => {
    if (nextOpen) {
      setSelectedRange({
        from: timeRange.startDate,
        to: timeRange.endDate,
      });
      setStartTimeStr(format(timeRange.startDate, "yyyy-MM-dd HH:mm"));
      setEndTimeStr(format(timeRange.endDate, "yyyy-MM-dd HH:mm"));
    }
    setOpen(nextOpen);
  };

  const handleSelectPreset = (preset: TimeRangePreset) => {
    setTimeRangePreset(preset);
    setOpen(false);
  };

  const handleCalendarSelect = (range: any) => {
    if (!range) return;
    const from = range.from || range.start;
    const to = range.to || range.end || from;

    setSelectedRange({ from, to });
    if (from) setStartTimeStr(format(from, "yyyy-MM-dd 00:00"));
    if (to) setEndTimeStr(format(to, "yyyy-MM-dd 23:59"));
  };

  const handleApplyCustom = () => {
    try {
      const start = new Date(startTimeStr);
      const end = new Date(endTimeStr);
      if (!isNaN(start.getTime()) && !isNaN(end.getTime()) && start <= end) {
        setCustomTimeRange(start, end);
        setOpen(false);
      }
    } catch {
      // Fallback
    }
  };

  const handleQuickInputSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const raw = customInputText.trim().toLowerCase();
    if (!raw) return;

    if (raw.includes("1m") || raw.includes("1 min")) handleSelectPreset("1m");
    else if (raw.includes("5m") || raw.includes("5 min")) handleSelectPreset("5m");
    else if (raw.includes("15m") || raw.includes("15 min")) handleSelectPreset("15m");
    else if (raw.includes("30m") || raw.includes("30 min")) handleSelectPreset("30m");
    else if (raw.includes("1h") || raw.includes("1 hour")) handleSelectPreset("1h");
    else if (raw.includes("6h") || raw.includes("6 hour")) handleSelectPreset("6h");
    else if (raw.includes("12h") || raw.includes("12 hour")) handleSelectPreset("12h");
    else if (raw.includes("24h") || raw.includes("24 hour") || raw.includes("1 day")) handleSelectPreset("24h");
    else if (raw.includes("7d") || raw.includes("7 day") || raw.includes("1 week")) handleSelectPreset("7d");
    else if (raw.includes("30d") || raw.includes("30 day") || raw.includes("1 month")) handleSelectPreset("30d");
    else if (raw.includes("6m") || raw.includes("6 month") || raw.includes("6mo")) handleSelectPreset("6mo");
    else if (raw.includes("1y") || raw.includes("1 year")) handleSelectPreset("1y");
  };

  return (
    <Popover open={open} onOpenChange={handleOpen}>
      <PopoverTrigger
        render={
          trigger ? (
            React.isValidElement(trigger) ? trigger : <button />
          ) : (
            <button
              className={cn(
                "flex items-center gap-2 px-3 py-1.5 rounded-md border border-border bg-background hover:bg-accent text-xs font-medium text-foreground transition-all duration-150 cursor-pointer shadow-xs",
                open && "ring-1 ring-ring border-ring",
                className
              )}
            />
          )
        }
      >
        {!trigger && (
          <>
            <CalendarIcon className="w-3.5 h-3.5 text-muted-foreground" />
            <span>{timeRange.label}</span>
            <ChevronDown className="w-3.5 h-3.5 text-muted-foreground ml-0.5" />
          </>
        )}
      </PopoverTrigger>

      <PopoverPopup
        align="end"
        sideOffset={6}
        className="w-[520px] p-0 bg-popover border border-border rounded-xl shadow-xl overflow-hidden z-50 text-foreground"
      >
        {/* Top Quick Custom Input */}
        <form onSubmit={handleQuickInputSubmit} className="p-3 border-b border-border bg-muted/30">
          <Input
            value={customInputText}
            onChange={(e) => setCustomInputText(e.target.value)}
            placeholder="Custom range: 3h, 3 hours, 3 m..."
            className="h-8 text-xs bg-background font-mono placeholder:font-sans placeholder:text-muted-foreground"
          />
        </form>

        {/* Main Body: Calendar Left, Presets Right */}
        <div className="grid grid-cols-[1fr_170px] divide-x divide-border">
          {/* Calendar Picker */}
          <div className="p-3 flex items-center justify-center">
            <Calendar
              mode="range"
              selected={selectedRange as any}
              onSelect={handleCalendarSelect}
              numberOfMonths={1}
              className="text-xs"
            />
          </div>

          {/* Presets List */}
          <div className="py-2 flex flex-col gap-0.5 bg-muted/10 max-h-[290px] overflow-y-auto">
            {PRESET_OPTIONS.map((item) => {
              const isSelected = !timeRange.isCustom && timeRange.preset === item.preset;
              return (
                <button
                  key={item.preset}
                  onClick={() => handleSelectPreset(item.preset)}
                  className={cn(
                    "flex items-center justify-between px-3.5 py-1.5 text-xs text-left transition-colors hover:bg-accent hover:text-accent-foreground cursor-pointer font-sans",
                    isSelected
                      ? "bg-primary/10 text-primary font-medium dark:bg-primary/20"
                      : "text-foreground"
                  )}
                >
                  <span>{item.label}</span>
                  {isSelected && <Check className="w-3.5 h-3.5 text-primary" />}
                </button>
              );
            })}
          </div>
        </div>

        {/* Bottom Bar: Datetime inputs + Apply Button */}
        <div className="p-3 border-t border-border bg-muted/20 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs">
            <div className="flex flex-col gap-1">
              <span className="text-[10px] text-muted-foreground uppercase font-mono">Start</span>
              <div className="flex items-center gap-1.5 px-2 py-1 bg-background border border-border rounded text-xs font-mono">
                <CalendarIcon className="w-3 h-3 text-muted-foreground" />
                <input
                  type="text"
                  value={startTimeStr}
                  onChange={(e) => setStartTimeStr(e.target.value)}
                  className="w-32 bg-transparent text-xs font-mono outline-none text-foreground"
                />
              </div>
            </div>

            <div className="flex flex-col gap-1">
              <span className="text-[10px] text-muted-foreground uppercase font-mono">End</span>
              <div className="flex items-center gap-1.5 px-2 py-1 bg-background border border-border rounded text-xs font-mono">
                <CalendarIcon className="w-3 h-3 text-muted-foreground" />
                <input
                  type="text"
                  value={endTimeStr}
                  onChange={(e) => setEndTimeStr(e.target.value)}
                  className="w-32 bg-transparent text-xs font-mono outline-none text-foreground"
                />
              </div>
            </div>
          </div>

          <Button
            size="sm"
            onClick={handleApplyCustom}
            className="px-4 text-xs font-medium bg-blue-600 hover:bg-blue-700 text-white rounded-md cursor-pointer self-end"
          >
            Apply
          </Button>
        </div>
      </PopoverPopup>
    </Popover>
  );
};
