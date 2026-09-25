import * as React from "react"
import { describe, it, expect, vi } from "vitest"
import { render, screen, fireEvent, waitFor } from "@testing-library/react"
import { TimeRangePicker } from "@/components/time-range/time-range-picker"
import { TimeRangeProvider } from "@/components/time-range/time-range-context"

// Mock next/navigation
vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams("window=24h"),
  useRouter: () => ({
    replace: vi.fn(),
    push: vi.fn(),
  }),
  usePathname: () => "/dashboard",
}))

describe("TimeRangePicker Component", () => {
  it("renders with default label 'Last 24 hours'", () => {
    render(
      <TimeRangeProvider>
        <TimeRangePicker />
      </TimeRangeProvider>
    )

    expect(screen.getByText("Last 24 hours")).toBeDefined()
  })

  it("opens popover with presets on button click", async () => {
    render(
      <TimeRangeProvider>
        <TimeRangePicker />
      </TimeRangeProvider>
    )

    const trigger = screen.getByRole("button", { name: /Last 24 hours/i })
    fireEvent.click(trigger)

    await waitFor(() => {
      expect(screen.getByText("Last 30 minutes")).toBeDefined()
      expect(screen.getByText("Last 1 hour")).toBeDefined()
      expect(screen.getByText("Last 7 days")).toBeDefined()
      expect(screen.getByText("Apply")).toBeDefined()
    })
  })

  it("switches preset and updates pending range", async () => {
    render(
      <TimeRangeProvider>
        <TimeRangePicker />
      </TimeRangeProvider>
    )

    const trigger = screen.getByRole("button", { name: /Last 24 hours/i })
    fireEvent.click(trigger)

    await waitFor(() => {
      expect(screen.getByText("Last 7 days")).toBeDefined()
    })

    const preset7d = screen.getByText("Last 7 days")
    fireEvent.click(preset7d)

    const applyButton = screen.getByRole("button", { name: "Apply" })
    fireEvent.click(applyButton)

    await waitFor(() => {
      expect(screen.getByText("Last 7 days")).toBeDefined()
    })
  })

  it("shows error and disables Apply when start is after end", async () => {
    render(
      <TimeRangeProvider>
        <TimeRangePicker />
      </TimeRangeProvider>
    )

    const trigger = screen.getByRole("button", { name: /Last 24 hours/i })
    fireEvent.click(trigger)

    await waitFor(() => {
      expect(screen.getAllByPlaceholderText("YYYY-MM-DD HH:mm")).toHaveLength(2)
    })

    const inputs = screen.getAllByPlaceholderText("YYYY-MM-DD HH:mm")
    const startInput = inputs[0]
    const endInput = inputs[1]

    // Set inverted times
    fireEvent.change(startInput, { target: { value: "2026-09-25 12:00" } })
    fireEvent.change(endInput, { target: { value: "2026-09-24 12:00" } })

    await waitFor(() => {
      expect(screen.getByText(/Start time must be before end time/i)).toBeDefined()
    })

    const applyButton = screen.getByRole("button", { name: "Apply" })
    expect(applyButton.hasAttribute("disabled")).toBe(true)
  })

  it("applies valid custom range and updates trigger label", async () => {
    render(
      <TimeRangeProvider>
        <TimeRangePicker />
      </TimeRangeProvider>
    )

    const trigger = screen.getByRole("button", { name: /Last 24 hours/i })
    fireEvent.click(trigger)

    await waitFor(() => {
      expect(screen.getAllByPlaceholderText("YYYY-MM-DD HH:mm")).toHaveLength(2)
    })

    const inputs = screen.getAllByPlaceholderText("YYYY-MM-DD HH:mm")
    fireEvent.change(inputs[0], { target: { value: "2026-09-20 10:00" } })
    fireEvent.change(inputs[1], { target: { value: "2026-09-24 18:00" } })

    const applyButton = screen.getByRole("button", { name: "Apply" })
    expect(applyButton.hasAttribute("disabled")).toBe(false)
    fireEvent.click(applyButton)

    await waitFor(() => {
      expect(screen.getByText("Sep 20, 10:00 – Sep 24, 18:00")).toBeDefined()
    })
  })
})
