import { fireEvent, render, screen } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { TimeRangePicker } from "@/components/time-range"
import { TimeRangeProvider } from "@/components/time-range"
import { getPresetDates, formatDisplayLabel } from "@/lib/time-range/utils"

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => "/reports",
}))

describe("time range presets", () => {
  beforeEach(() => vi.restoreAllMocks())

  it("computes short preset durations", () => {
    const now = new Date("2026-11-12T12:00:00Z")
    expect(getPresetDates("30s", now).start.toISOString()).toBe(
      "2026-11-12T11:59:30.000Z"
    )
    expect(getPresetDates("1m", now).start.toISOString()).toBe(
      "2026-11-12T11:59:00.000Z"
    )
    expect(getPresetDates("5m", now).start.toISOString()).toBe(
      "2026-11-12T11:55:00.000Z"
    )
    expect(getPresetDates("10m", now).start.toISOString()).toBe(
      "2026-11-12T11:50:00.000Z"
    )
    expect(getPresetDates("15m", now).start.toISOString()).toBe(
      "2026-11-12T11:45:00.000Z"
    )
  })

  it("labels the new presets", () => {
    expect(formatDisplayLabel({ type: "preset", preset: "30s" })).toBe(
      "Last 30 seconds"
    )
    expect(formatDisplayLabel({ type: "preset", preset: "10m" })).toBe(
      "Last 10 minutes"
    )
  })
})

describe("time range calendar", () => {
  it("clears the end when a new start is selected", () => {
    render(
      <TimeRangeProvider>
        <TimeRangePicker />
      </TimeRangeProvider>
    )

    fireEvent.click(screen.getByRole("button", { name: /last 24 hours/i }))

    fireEvent.click(screen.getByRole("button", { name: "2026-11-10" }))
    fireEvent.click(screen.getByRole("button", { name: "2026-11-15" }))

    expect(screen.getByLabelText("Start")).toHaveValue("2026-11-10 00:00")
    expect(screen.getByLabelText("End")).toHaveValue("2026-11-15 23:59")

    fireEvent.click(screen.getByRole("button", { name: "2026-11-20" }))

    expect(screen.getByLabelText("Start")).toHaveValue("2026-11-20 00:00")
    expect(screen.getByLabelText("End")).toHaveValue("")
  })
})
