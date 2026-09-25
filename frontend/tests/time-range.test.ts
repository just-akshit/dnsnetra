import { describe, it, expect } from "vitest"
import {
  formatDateTimeInput,
  parseDateTimeInput,
  formatDisplayLabel,
  getPresetDates,
  toIsoUtcString,
  validateCustomRange,
} from "@/lib/time-range/utils"
import type { TimeRange } from "@/lib/time-range/types"

describe("Time Range Utilities", () => {
  it("formats date to YYYY-MM-DD HH:mm accurately in UTC", () => {
    const d = new Date(Date.UTC(2026, 8, 24, 17, 59, 0))
    expect(formatDateTimeInput(d)).toBe("2026-09-24 17:59")
  })

  it("parses valid YYYY-MM-DD HH:mm string", () => {
    const d = parseDateTimeInput("2026-09-24 17:59")
    expect(d).not.toBeNull()
    expect(d?.getUTCFullYear()).toBe(2026)
    expect(d?.getUTCMonth()).toBe(8)
    expect(d?.getUTCDate()).toBe(24)
    expect(d?.getUTCHours()).toBe(17)
    expect(d?.getUTCMinutes()).toBe(59)
  })

  it("returns null for invalid datetime input", () => {
    expect(parseDateTimeInput("not-a-date")).toBeNull()
    expect(parseDateTimeInput("2026-99-99 99:99")).toBeNull()
  })

  it("calculates preset start and end dates correctly", () => {
    const now = new Date(Date.UTC(2026, 8, 24, 12, 0, 0))
    const { start, end } = getPresetDates("24h", now)
    expect(end.toISOString()).toBe("2026-09-24T12:00:00.000Z")
    expect(start.toISOString()).toBe("2026-09-23T12:00:00.000Z")

    const res30m = getPresetDates("30m", now)
    expect(res30m.start.toISOString()).toBe("2026-09-24T11:30:00.000Z")
  })

  it("formats display label for presets and custom ranges", () => {
    const presetRange: TimeRange = { type: "preset", preset: "24h" }
    expect(formatDisplayLabel(presetRange)).toBe("Last 24 hours")

    const preset7d: TimeRange = { type: "preset", preset: "7d" }
    expect(formatDisplayLabel(preset7d)).toBe("Last 7 days")

    const customRange: TimeRange = {
      type: "custom",
      startTime: "2026-09-23T17:59:00Z",
      endTime: "2026-09-24T17:59:00Z",
    }
    expect(formatDisplayLabel(customRange)).toBe("Sep 23, 17:59 – Sep 24, 17:59")
  })

  it("validates custom range boundaries correctly", () => {
    // Valid
    const valid = validateCustomRange("2026-09-23 17:59", "2026-09-24 17:59")
    expect(valid.valid).toBe(true)
    expect(valid.error).toBeUndefined()

    // Inverted (start >= end)
    const inverted = validateCustomRange("2026-09-25 17:59", "2026-09-24 17:59")
    expect(inverted.valid).toBe(false)
    expect(inverted.error).toContain("Start time must be before end time")

    // Equal (start == end)
    const equal = validateCustomRange("2026-09-24 17:59", "2026-09-24 17:59")
    expect(equal.valid).toBe(false)
    expect(equal.error).toContain("Start time must be before end time")

    // Invalid format
    const invalid = validateCustomRange("bad-date", "2026-09-24 17:59")
    expect(invalid.valid).toBe(false)
    expect(invalid.error).toContain("Invalid start date format")
  })

  it("converts dates to canonical ISO UTC string", () => {
    const d = new Date(Date.UTC(2026, 8, 24, 17, 59, 0))
    expect(toIsoUtcString(d)).toBe("2026-09-24T17:59:00.000Z")
    expect(toIsoUtcString("2026-09-24 17:59")).toBe("2026-09-24T17:59:00.000Z")
  })
})
