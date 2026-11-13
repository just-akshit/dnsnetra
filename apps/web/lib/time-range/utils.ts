import { PRESET_OPTIONS, type TimeRange, type TimeRangePreset } from "./types"

const pad = (n: number) => n.toString().padStart(2, "0")

/**
 * Formats a Date object as `YYYY-MM-DD HH:mm` in UTC.
 */
export function formatDateTimeInput(date: Date): string {
  const y = date.getUTCFullYear()
  const m = pad(date.getUTCMonth() + 1)
  const d = pad(date.getUTCDate())
  const h = pad(date.getUTCHours())
  const min = pad(date.getUTCMinutes())
  return `${y}-${m}-${d} ${h}:${min}`
}

/**
 * Parses a `YYYY-MM-DD HH:mm` or ISO-8601 string into a Date object (treated as UTC).
 */
export function parseDateTimeInput(str: string): Date | null {
  if (!str || typeof str !== "string") return null
  const trimmed = str.trim()

  // Match YYYY-MM-DD HH:mm or YYYY-MM-DDTHH:mm
  const match = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(:(\d{2}))?/.exec(trimmed)
  if (!match) {
    const parsed = new Date(trimmed)
    return isNaN(parsed.getTime()) ? null : parsed
  }

  const year = parseInt(match[1], 10)
  const month = parseInt(match[2], 10) - 1
  const day = parseInt(match[3], 10)
  const hours = parseInt(match[4], 10)
  const minutes = parseInt(match[5], 10)
  const seconds = match[7] ? parseInt(match[7], 10) : 0

  if (month < 0 || month > 11 || day < 1 || day > 31 || hours < 0 || hours > 23 || minutes < 0 || minutes > 59) {
    return null
  }

  const d = new Date(Date.UTC(year, month, day, hours, minutes, seconds))
  if (isNaN(d.getTime())) return null
  // Verify day rollover (e.g. Feb 31)
  if (d.getUTCDate() !== day || d.getUTCMonth() !== month) return null

  return d
}

/**
 * Returns UTC start and end dates for a given relative preset.
 */
export function getPresetDates(
  preset: TimeRangePreset,
  refNow = new Date()
): { start: Date; end: Date } {
  const option = PRESET_OPTIONS.find((o) => o.id === preset)
  const durationMinutes = option ? option.durationMinutes : 1440
  const end = new Date(refNow.getTime())
  const start = new Date(end.getTime() - durationMinutes * 60 * 1000)
  return { start, end }
}

const MONTH_NAMES_SHORT = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
]

/**
 * Formats a user-facing label for the Time Range button.
 */
export function formatDisplayLabel(timeRange: TimeRange): string {
  if (timeRange.type === "preset") {
    const found = PRESET_OPTIONS.find((p) => p.id === timeRange.preset)
    return found ? found.label : "Last 24 hours"
  }

  if (timeRange.label) return timeRange.label

  const start = parseDateTimeInput(timeRange.startTime)
  const end = parseDateTimeInput(timeRange.endTime)

  if (!start || !end) return "Custom Range"

  const sMonth = MONTH_NAMES_SHORT[start.getUTCMonth()]
  const sDay = start.getUTCDate()
  const sTime = `${pad(start.getUTCHours())}:${pad(start.getUTCMinutes())}`

  const eMonth = MONTH_NAMES_SHORT[end.getUTCMonth()]
  const eDay = end.getUTCDate()
  const eTime = `${pad(end.getUTCHours())}:${pad(end.getUTCMinutes())}`

  if (sMonth === eMonth && start.getUTCFullYear() === end.getUTCFullYear()) {
    if (sDay === eDay) {
      return `${sMonth} ${sDay}, ${sTime} – ${eTime}`
    }
  }

  return `${sMonth} ${sDay}, ${sTime} – ${eMonth} ${eDay}, ${eTime}`
}

/**
 * Converts a date or string into canonical ISO UTC string format (e.g. 2026-09-24T17:59:00.000Z).
 */
export function toIsoUtcString(dateOrStr: Date | string): string {
  if (dateOrStr instanceof Date) {
    return dateOrStr.toISOString()
  }
  const parsed = parseDateTimeInput(dateOrStr)
  if (parsed) {
    return parsed.toISOString()
  }
  return new Date(dateOrStr).toISOString()
}

/**
 * Validates custom start and end datetime inputs.
 */
export function validateCustomRange(
  startStr: string,
  endStr: string
): {
  valid: boolean
  error?: string
  startDate?: Date
  endDate?: Date
} {
  const startDate = parseDateTimeInput(startStr)
  if (!startDate) {
    return { valid: false, error: "Invalid start date format (YYYY-MM-DD HH:mm)" }
  }

  const endDate = parseDateTimeInput(endStr)
  if (!endDate) {
    return { valid: false, error: "Invalid end date format (YYYY-MM-DD HH:mm)" }
  }

  if (startDate.getTime() >= endDate.getTime()) {
    return {
      valid: false,
      error: "Start time must be before end time.",
      startDate,
      endDate,
    }
  }

  return { valid: true, startDate, endDate }
}
