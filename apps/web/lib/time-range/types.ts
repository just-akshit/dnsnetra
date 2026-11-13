/**
 * Authoritative types for the DNSNetra Global Time Range Engine.
 */

export type TimeRangePreset =
  | "30s"
  | "1m"
  | "5m"
  | "10m"
  | "15m"
  | "30m"
  | "1h"
  | "6h"
  | "12h"
  | "24h"
  | "7d"
  | "30d"
  | "90d"
  | "6m"
  | "1y"
  | "all_time"

export interface PresetOption {
  id: TimeRangePreset
  label: string
  durationMinutes: number
}

export const PRESET_OPTIONS: PresetOption[] = [
  { id: "30s", label: "Last 30 seconds", durationMinutes: 0.5 },
  { id: "1m", label: "Last 1 minute", durationMinutes: 1 },
  { id: "5m", label: "Last 5 minutes", durationMinutes: 5 },
  { id: "10m", label: "Last 10 minutes", durationMinutes: 10 },
  { id: "15m", label: "Last 15 minutes", durationMinutes: 15 },
  { id: "30m", label: "Last 30 minutes", durationMinutes: 30 },
  { id: "1h", label: "Last 1 hour", durationMinutes: 60 },
  { id: "6h", label: "Last 6 hours", durationMinutes: 360 },
  { id: "12h", label: "Last 12 hours", durationMinutes: 720 },
  { id: "24h", label: "Last 24 hours", durationMinutes: 1440 },
  { id: "7d", label: "Last 7 days", durationMinutes: 10080 },
  { id: "30d", label: "Last 30 days", durationMinutes: 43200 },
  { id: "90d", label: "Last 90 days", durationMinutes: 129600 },
  { id: "6m", label: "Last 6 months", durationMinutes: 259200 },
  { id: "1y", label: "Last 1 year", durationMinutes: 525600 },
  { id: "all_time", label: "All Time", durationMinutes: 525600 },
]

export type TimeRange =
  | {
      type: "preset"
      preset: TimeRangePreset
    }
  | {
      type: "custom"
      startTime: string // ISO string or YYYY-MM-DD HH:mm
      endTime: string   // ISO string or YYYY-MM-DD HH:mm
      label?: string
    }

export interface TimeRangeContextValue {
  timeRange: TimeRange
  setTimeRange: (range: TimeRange) => void
  isLiveRefresh: boolean
  setIsLiveRefresh: (active: boolean) => void
  label: string
  backendParams: {
    window?: string
    start_time?: string
    end_time?: string
  }
}
