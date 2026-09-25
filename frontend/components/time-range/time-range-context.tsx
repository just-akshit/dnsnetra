"use client"

import * as React from "react"
import { useSearchParams, useRouter, usePathname } from "next/navigation"
import {
  type TimeRange,
  type TimeRangePreset,
  type TimeRangeContextValue,
} from "@/lib/time-range/types"
import {
  formatDisplayLabel,
  toIsoUtcString,
} from "@/lib/time-range/utils"

const TimeRangeContext = React.createContext<TimeRangeContextValue | null>(null)

interface TimeRangeProviderProps {
  children: React.ReactNode
  defaultPreset?: TimeRangePreset
}

export function TimeRangeProvider({
  children,
  defaultPreset = "24h",
}: TimeRangeProviderProps) {
  const searchParams = useSearchParams()
  const router = useRouter()
  const pathname = usePathname()
  const searchParamsStr = searchParams?.toString() ?? ""

  // Initialize from URL search params or fallback to defaultPreset
  const initialRange = React.useMemo<TimeRange>(() => {
    const params = new URLSearchParams(searchParamsStr)
    const startParam = params.get("start_time")
    const endParam = params.get("end_time")
    const windowParam = params.get("window")

    if (startParam && endParam) {
      return {
        type: "custom",
        startTime: startParam,
        endTime: endParam,
      }
    }

    if (windowParam) {
      const validPresets: TimeRangePreset[] = [
        "30m", "1h", "6h", "12h", "24h", "7d", "30d"
      ]
      if (validPresets.includes(windowParam as TimeRangePreset)) {
        return {
          type: "preset",
          preset: windowParam as TimeRangePreset,
        }
      }
    }

    return {
      type: "preset",
      preset: defaultPreset,
    }
  }, [searchParamsStr, defaultPreset])

  const [timeRange, setTimeRangeState] = React.useState<TimeRange>(initialRange)
  const [isLiveRefresh, setIsLiveRefresh] = React.useState<boolean>(false)
  const lastParamsRef = React.useRef(searchParamsStr)

  // Keep state in sync only if searchParams string changes externally (e.g. browser back/forward)
  React.useEffect(() => {
    if (searchParamsStr !== lastParamsRef.current) {
      lastParamsRef.current = searchParamsStr
      setTimeRangeState(initialRange)
    }
  }, [searchParamsStr, initialRange])

  // Sync to URL when range changes
  const setTimeRange = React.useCallback(
    (newRange: TimeRange) => {
      setTimeRangeState(newRange)

      const params = new URLSearchParams(searchParamsStr)
      if (newRange.type === "preset") {
        params.delete("start_time")
        params.delete("end_time")
        params.set("window", newRange.preset)
      } else {
        params.delete("window")
        params.set("start_time", toIsoUtcString(newRange.startTime))
        params.set("end_time", toIsoUtcString(newRange.endTime))
      }

      const nextStr = params.toString()
      lastParamsRef.current = nextStr
      router.replace(`${pathname}?${nextStr}`, { scroll: false })
    },
    [router, pathname, searchParamsStr]
  )

  const label = React.useMemo(() => formatDisplayLabel(timeRange), [timeRange])

  const backendParams = React.useMemo(() => {
    if (timeRange.type === "preset") {
      return { window: timeRange.preset }
    }
    return {
      start_time: toIsoUtcString(timeRange.startTime),
      end_time: toIsoUtcString(timeRange.endTime),
    }
  }, [timeRange])

  const value: TimeRangeContextValue = React.useMemo(
    () => ({
      timeRange,
      setTimeRange,
      isLiveRefresh,
      setIsLiveRefresh,
      label,
      backendParams,
    }),
    [timeRange, setTimeRange, isLiveRefresh, setIsLiveRefresh, label, backendParams]
  )

  return (
    <TimeRangeContext.Provider value={value}>
      {children}
    </TimeRangeContext.Provider>
  )
}

export function useTimeRange(): TimeRangeContextValue {
  const context = React.useContext(TimeRangeContext)
  if (!context) {
    throw new Error("useTimeRange must be used within a TimeRangeProvider")
  }
  return context
}
