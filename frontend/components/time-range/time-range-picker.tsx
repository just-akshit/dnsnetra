"use client"

import * as React from "react"
import { CalendarIcon, ChevronDownIcon, ClockIcon } from "lucide-react"
import { Button, buttonVariants } from "@/components/ui/button"
import {
  Popover,
  PopoverTrigger,
  PopoverContent,
} from "@/components/ui/popover"
import { TimeRangeCalendar } from "./time-range-calendar"
import { useTimeRange } from "./time-range-context"
import {
  PRESET_OPTIONS,
  type TimeRangePreset,
} from "@/lib/time-range/types"
import {
  formatDateTimeInput,
  getPresetDates,
  parseDateTimeInput,
  validateCustomRange,
} from "@/lib/time-range/utils"
import { cn } from "cn"

interface TimeRangePickerProps {
  className?: string
  align?: "start" | "center" | "end"
}

export function TimeRangePicker({
  className,
  align = "end",
}: TimeRangePickerProps) {
  const { timeRange, setTimeRange, label } = useTimeRange()
  const [open, setOpen] = React.useState(false)

  // Pending range states inside the popover
  const [pendingType, setPendingType] = React.useState<"preset" | "custom">(
    timeRange.type
  )
  const [pendingPreset, setPendingPreset] = React.useState<TimeRangePreset>(
    timeRange.type === "preset" ? timeRange.preset : "24h"
  )
  const [startInput, setStartInput] = React.useState<string>("")
  const [endInput, setEndInput] = React.useState<string>("")
  const [currentMonth, setCurrentMonth] = React.useState<Date>(new Date())
  const [validationError, setValidationError] = React.useState<string | null>(null)

  const handleOpenChange = React.useCallback(
    (newOpen: boolean) => {
      setOpen(newOpen)
      if (newOpen) {
        setPendingType(timeRange.type)
        setValidationError(null)

        if (timeRange.type === "preset") {
          setPendingPreset(timeRange.preset)
          const { start, end } = getPresetDates(timeRange.preset)
          setStartInput(formatDateTimeInput(start))
          setEndInput(formatDateTimeInput(end))
          setCurrentMonth(new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), 1)))
        } else {
          const start = parseDateTimeInput(timeRange.startTime) || new Date()
          const end = parseDateTimeInput(timeRange.endTime) || new Date()
          setStartInput(formatDateTimeInput(start))
          setEndInput(formatDateTimeInput(end))
          setCurrentMonth(new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), 1)))
        }
      }
    },
    [timeRange]
  )

  // Handle preset click in list
  const handleSelectPreset = (presetId: TimeRangePreset) => {
    setPendingType("preset")
    setPendingPreset(presetId)
    setValidationError(null)

    const { start, end } = getPresetDates(presetId)
    setStartInput(formatDateTimeInput(start))
    setEndInput(formatDateTimeInput(end))
    setCurrentMonth(new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), 1)))
  }

  // Handle calendar day range selection
  const handleCalendarRangeSelect = (start: Date, end: Date | null) => {
    setPendingType("custom")
    setValidationError(null)
    setStartInput(formatDateTimeInput(start))

    if (end) {
      setEndInput(formatDateTimeInput(end))
    }
  }

  // Handle manual input changes
  const handleStartInputChange = (val: string) => {
    setStartInput(val)
    setPendingType("custom")
    const validation = validateCustomRange(val, endInput)
    if (!validation.valid) {
      setValidationError(validation.error || "Invalid range")
    } else {
      setValidationError(null)
      if (validation.startDate) {
        setCurrentMonth(
          new Date(
            Date.UTC(
              validation.startDate.getUTCFullYear(),
              validation.startDate.getUTCMonth(),
              1
            )
          )
        )
      }
    }
  }

  const handleEndInputChange = (val: string) => {
    setEndInput(val)
    setPendingType("custom")
    const validation = validateCustomRange(startInput, val)
    if (!validation.valid) {
      setValidationError(validation.error || "Invalid range")
    } else {
      setValidationError(null)
    }
  }

  // Handle Apply button
  const handleApply = () => {
    if (pendingType === "preset") {
      setTimeRange({
        type: "preset",
        preset: pendingPreset,
      })
      setOpen(false)
      return
    }

    const validation = validateCustomRange(startInput, endInput)
    if (!validation.valid || !validation.startDate || !validation.endDate) {
      setValidationError(validation.error || "Please specify a valid start and end time.")
      return
    }

    setTimeRange({
      type: "custom",
      startTime: startInput,
      endTime: endInput,
    })
    setOpen(false)
  }

  // Quick reset to 24 hours
  const handleReset = () => {
    handleSelectPreset("24h")
  }

  const calendarStartDate = parseDateTimeInput(startInput)
  const calendarEndDate = parseDateTimeInput(endInput)

  return (
    <Popover open={open} onOpenChange={handleOpenChange}>
      <PopoverTrigger
        className={cn(
          buttonVariants({ variant: "outline", size: "sm" }),
          "h-8 gap-2 px-3 text-xs font-medium border-border/80 bg-background/80 shadow-2xs hover:bg-muted/60 transition-colors cursor-pointer",
          className
        )}
      >
        <CalendarIcon className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="font-medium text-foreground">{label}</span>
        <ChevronDownIcon className="h-3.5 w-3.5 text-muted-foreground transition-transform duration-200" />
      </PopoverTrigger>

      <PopoverContent
        align={align}
        sideOffset={6}
        className="w-[490px] max-w-[95vw] p-0 rounded-xl border border-border bg-card text-card-foreground shadow-2xl"
      >
        {/* Top Header: Custom range hint */}
        <div className="border-b border-border/70 px-4 py-2.5 bg-muted/20 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <ClockIcon className="h-3.5 w-3.5" />
            <span>Custom range: 30m, 1h, 24h, or explicit date range</span>
          </div>
          {pendingType === "custom" && (
            <button
              type="button"
              onClick={handleReset}
              className="text-xs text-primary hover:underline font-medium"
            >
              Reset to 24h
            </button>
          )}
        </div>

        {/* Middle Body: Calendar on Left, Presets on Right */}
        <div className="flex flex-col sm:flex-row divide-y sm:divide-y-0 sm:divide-x divide-border/70">
          {/* Calendar Picker (Left) */}
          <div className="flex-1 flex justify-center">
            <TimeRangeCalendar
              startDate={calendarStartDate}
              endDate={calendarEndDate}
              onRangeSelect={handleCalendarRangeSelect}
              currentMonth={currentMonth}
              onMonthChange={setCurrentMonth}
            />
          </div>

          {/* Presets List (Right) */}
          <div className="w-full sm:w-[170px] p-3 flex flex-col gap-1 bg-muted/10">
            <div className="px-2.5 py-1 text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">
              Presets
            </div>
            {PRESET_OPTIONS.map((option) => {
              const isSelected =
                pendingType === "preset" && pendingPreset === option.id
              return (
                <button
                  key={option.id}
                  type="button"
                  onClick={() => handleSelectPreset(option.id)}
                  className={cn(
                    "w-full text-left px-2.5 py-1.5 text-xs rounded-lg transition-colors flex items-center justify-between",
                    isSelected
                      ? "bg-muted font-semibold text-foreground shadow-2xs dark:bg-muted/80"
                      : "text-muted-foreground hover:bg-muted/50 hover:text-foreground font-normal"
                  )}
                >
                  <span>{option.label}</span>
                </button>
              )
            })}
          </div>
        </div>

        {/* Bottom Inputs & Apply Row */}
        <div className="border-t border-border/70 p-4 bg-muted/10 flex flex-col gap-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {/* Start Datetime */}
            <div className="flex flex-col gap-1">
              <label className="text-[11px] font-medium text-muted-foreground">
                Start
              </label>
              <div className="relative flex items-center">
                <CalendarIcon className="absolute left-2.5 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
                <input
                  type="text"
                  value={startInput}
                  onChange={(e) => handleStartInputChange(e.target.value)}
                  placeholder="YYYY-MM-DD HH:mm"
                  className={cn(
                    "w-full h-8 pl-8 pr-2.5 text-xs font-mono rounded-lg border bg-background text-foreground transition-all outline-none focus:border-ring focus:ring-2 focus:ring-ring/20",
                    validationError ? "border-destructive" : "border-border"
                  )}
                />
              </div>
            </div>

            {/* End Datetime */}
            <div className="flex flex-col gap-1">
              <label className="text-[11px] font-medium text-muted-foreground">
                End
              </label>
              <div className="relative flex items-center">
                <CalendarIcon className="absolute left-2.5 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
                <input
                  type="text"
                  value={endInput}
                  onChange={(e) => handleEndInputChange(e.target.value)}
                  placeholder="YYYY-MM-DD HH:mm"
                  className={cn(
                    "w-full h-8 pl-8 pr-2.5 text-xs font-mono rounded-lg border bg-background text-foreground transition-all outline-none focus:border-ring focus:ring-2 focus:ring-ring/20",
                    validationError ? "border-destructive" : "border-border"
                  )}
                />
              </div>
            </div>
          </div>

          {/* Validation Error Feedback */}
          {validationError && (
            <div className="text-[11px] text-destructive font-medium px-1">
              {validationError}
            </div>
          )}

          {/* Actions Footer */}
          <div className="flex items-center justify-between pt-1">
            <span className="text-[11px] text-muted-foreground">
              Times are in UTC
            </span>
            <Button
              type="button"
              variant="default"
              size="sm"
              onClick={handleApply}
              disabled={Boolean(validationError)}
              className="h-8 px-5 text-xs font-semibold rounded-lg bg-blue-600 hover:bg-blue-700 text-white shadow-xs"
            >
              Apply
            </Button>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  )
}
