/**
 * Authoritative types for the DNSNetra Global Time Range Engine.
 */

export type TimeRangePreset =
  | "30m"
  | "1h"
  | "6h"
  | "12h"
  | "24h"
  | "7d"
  | "30d"

export interface PresetOption {
  id: TimeRangePreset
  label: string
  durationMinutes: number
}

export const PRESET_OPTIONS: PresetOption[] = [
  { id: "30m", label: "Last 30 minutes", durationMinutes: 30 },
  { id: "1h", label: "Last 1 hour", durationMinutes: 60 },
  { id: "6h", label: "Last 6 hours", durationMinutes: 360 },
  { id: "12h", label: "Last 12 hours", durationMinutes: 720 },
  { id: "24h", label: "Last 24 hours", durationMinutes: 1440 },
  { id: "7d", label: "Last 7 days", durationMinutes: 10080 },
  { id: "30d", label: "Last 30 days", durationMinutes: 43200 },
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
