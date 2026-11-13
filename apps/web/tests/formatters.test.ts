import { describe, it, expect } from "vitest"
import {
  formatDnsnetraTimestamp,
  formatNumber,
  formatScore,
  formatPercent,
  truncateMiddle,
} from "@/lib/data-table/formatters"

describe("formatDnsnetraTimestamp", () => {
  it("strictly formats timestamps as YYYY-MM-DD HH:mm:ss without timezone offset or browser locale", () => {
    const isoString = "2026-09-24T17:42:31.000Z"
    const formatted = formatDnsnetraTimestamp(isoString)
    expect(formatted).toBe("2026-09-24 17:42:31")
  })

  it("handles null and undefined gracefully", () => {
    expect(formatDnsnetraTimestamp(null)).toBe("—")
    expect(formatDnsnetraTimestamp(undefined)).toBe("—")
    expect(formatDnsnetraTimestamp("")).toBe("—")
  })

  it("handles Date objects", () => {
    const d = new Date(Date.UTC(2026, 0, 15, 8, 5, 9))
    expect(formatDnsnetraTimestamp(d)).toBe("2026-01-15 08:05:09")
  })
})

describe("formatNumber", () => {
  it("formats numbers with commas", () => {
    expect(formatNumber(18421)).toBe("18,421")
    expect(formatNumber(1204)).toBe("1,204")
    expect(formatNumber(0)).toBe("0")
  })

  it("handles null/undefined", () => {
    expect(formatNumber(null)).toBe("—")
    expect(formatNumber(undefined)).toBe("—")
  })
})

describe("formatScore and formatPercent", () => {
  it("formats scores with precision", () => {
    expect(formatScore(94.234, 1)).toBe("94.2")
    expect(formatScore(null)).toBe("—")
  })

  it("formats percentages", () => {
    expect(formatPercent(98.42)).toBe("98.4%")
    expect(formatPercent(null)).toBe("—")
  })

  it("truncates long strings with middle ellipsis", () => {
    expect(truncateMiddle("very-long-domain-name-exceeding-limit.threat-actor.org", 24)).toContain("...")
    expect(truncateMiddle("short.com", 24)).toBe("short.com")
  })
})
