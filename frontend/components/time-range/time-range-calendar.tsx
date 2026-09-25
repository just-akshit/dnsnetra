"use client"

import * as React from "react"
import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { cn } from "cn"

interface TimeRangeCalendarProps {
  startDate: Date | null
  endDate: Date | null
  onRangeSelect: (start: Date, end: Date | null) => void
  currentMonth: Date
  onMonthChange: (month: Date) => void
}

const WEEKDAYS = ["Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"]
const MONTH_NAMES = [
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December"
]

export function TimeRangeCalendar({
  startDate,
  endDate,
  onRangeSelect,
  currentMonth,
  onMonthChange,
}: TimeRangeCalendarProps) {
  const year = currentMonth.getUTCFullYear()
  const month = currentMonth.getUTCMonth()

  const handlePrevMonth = () => {
    onMonthChange(new Date(Date.UTC(year, month - 1, 1)))
  }

  const handleNextMonth = () => {
    onMonthChange(new Date(Date.UTC(year, month + 1, 1)))
  }

  const daysInCurrentMonth = new Date(Date.UTC(year, month + 1, 0)).getUTCDate()
  const daysInPrevMonth = new Date(Date.UTC(year, month, 0)).getUTCDate()
  const firstDayOfWeek = new Date(Date.UTC(year, month, 1)).getUTCDay()

  const startDayMs = startDate
    ? Date.UTC(startDate.getUTCFullYear(), startDate.getUTCMonth(), startDate.getUTCDate())
    : null
  const endDayMs = endDate
    ? Date.UTC(endDate.getUTCFullYear(), endDate.getUTCMonth(), endDate.getUTCDate())
    : null

  // Generate cells (42 cells: 6 weeks x 7 days for consistent height)
  const cells: Array<{
    date: Date
    dayNumber: number
    isCurrentMonth: boolean
    isStart: boolean
    isEnd: boolean
    isInRange: boolean
  }> = []

  // Prev month padding
  for (let i = 0; i < firstDayOfWeek; i++) {
    const dayNum = daysInPrevMonth - firstDayOfWeek + 1 + i
    const d = new Date(Date.UTC(year, month - 1, dayNum))
    const dMs = d.getTime()
    cells.push({
      date: d,
      dayNumber: dayNum,
      isCurrentMonth: false,
      isStart: Boolean(startDayMs && dMs === startDayMs),
      isEnd: Boolean(endDayMs && dMs === endDayMs),
      isInRange: Boolean(startDayMs && endDayMs && dMs > startDayMs && dMs < endDayMs),
    })
  }

  // Current month
  for (let dayNum = 1; dayNum <= daysInCurrentMonth; dayNum++) {
    const d = new Date(Date.UTC(year, month, dayNum))
    const dMs = d.getTime()
    cells.push({
      date: d,
      dayNumber: dayNum,
      isCurrentMonth: true,
      isStart: Boolean(startDayMs && dMs === startDayMs),
      isEnd: Boolean(endDayMs && dMs === endDayMs),
      isInRange: Boolean(startDayMs && endDayMs && dMs > startDayMs && dMs < endDayMs),
    })
  }

  // Next month padding to reach 35 or 42 cells
  const remaining = 35 - cells.length > 0 ? 35 - cells.length : 42 - cells.length
  for (let dayNum = 1; dayNum <= remaining; dayNum++) {
    const d = new Date(Date.UTC(year, month + 1, dayNum))
    const dMs = d.getTime()
    cells.push({
      date: d,
      dayNumber: dayNum,
      isCurrentMonth: false,
      isStart: Boolean(startDayMs && dMs === startDayMs),
      isEnd: Boolean(endDayMs && dMs === endDayMs),
      isInRange: Boolean(startDayMs && endDayMs && dMs > startDayMs && dMs < endDayMs),
    })
  }

  const handleCellClick = (cellDate: Date) => {
    if (!startDate || (startDate && endDate)) {
      // First selection of new range: preserve existing start time or default to 00:00
      const newStart = new Date(cellDate.getTime())
      if (startDate) {
        newStart.setUTCHours(startDate.getUTCHours(), startDate.getUTCMinutes(), 0, 0)
      } else {
        newStart.setUTCHours(0, 0, 0, 0)
      }
      onRangeSelect(newStart, null)
    } else {
      // Second selection: complete range
      const cellMs = cellDate.getTime()
      const startMs = startDate.getTime()

      if (cellMs < startMs) {
        // Clicked before start: make this the new start
        const newStart = new Date(cellDate.getTime())
        newStart.setUTCHours(startDate.getUTCHours(), startDate.getUTCMinutes(), 0, 0)
        onRangeSelect(newStart, null)
      } else {
        const newEnd = new Date(cellDate.getTime())
        newEnd.setUTCHours(23, 59, 0, 0)
        onRangeSelect(startDate, newEnd)
      }
    }
  }

  return (
    <div className="w-[280px] select-none p-3">
      {/* Month & Navigation Header */}
      <div className="flex items-center justify-between mb-3 px-1">
        <span className="text-sm font-semibold text-foreground tracking-tight">
          {MONTH_NAMES[month]} {year}
        </span>
        <div className="flex items-center gap-1">
          <Button
            type="button"
            variant="ghost"
            size="icon-xs"
            onClick={handlePrevMonth}
            className="h-7 w-7 text-muted-foreground hover:text-foreground"
            aria-label="Previous month"
          >
            <ChevronLeftIcon className="h-4 w-4" />
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="icon-xs"
            onClick={handleNextMonth}
            className="h-7 w-7 text-muted-foreground hover:text-foreground"
            aria-label="Next month"
          >
            <ChevronRightIcon className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Weekday Labels */}
      <div className="grid grid-cols-7 gap-1 text-center mb-1">
        {WEEKDAYS.map((day) => (
          <div
            key={day}
            className="h-6 flex items-center justify-center text-[11px] font-medium text-muted-foreground"
          >
            {day}
          </div>
        ))}
      </div>

      {/* Days Grid */}
      <div className="grid grid-cols-7 gap-y-1">
        {cells.map((cell, idx) => {
          const isSelectedEndpoint = cell.isStart || cell.isEnd
          const isSingleSelected = cell.isStart && (!endDate || cell.isEnd)

          return (
            <div
              key={idx}
              className={cn(
                "relative h-8 flex items-center justify-center transition-colors",
                cell.isInRange && "bg-primary/10 dark:bg-primary/15",
                cell.isStart && endDate && "rounded-l-md bg-primary/10 dark:bg-primary/15",
                cell.isEnd && startDate && "rounded-r-md bg-primary/10 dark:bg-primary/15"
              )}
            >
              <button
                type="button"
                onClick={() => handleCellClick(cell.date)}
                className={cn(
                  "h-7 w-7 rounded-md text-xs font-normal transition-all flex items-center justify-center outline-none",
                  !cell.isCurrentMonth && "text-muted-foreground/40",
                  cell.isCurrentMonth && !isSelectedEndpoint && !cell.isInRange && "text-foreground hover:bg-muted/80",
                  cell.isInRange && !isSelectedEndpoint && "text-foreground hover:bg-primary/20",
                  isSelectedEndpoint &&
                    "bg-foreground text-background font-semibold shadow-xs hover:bg-foreground/90 dark:bg-primary dark:text-primary-foreground",
                  isSingleSelected && "rounded-md"
                )}
              >
                {cell.dayNumber}
              </button>
            </div>
          )
        })}
      </div>
    </div>
  )
}
