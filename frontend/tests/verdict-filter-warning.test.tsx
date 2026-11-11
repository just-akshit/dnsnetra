import { renderHook } from "@testing-library/react"
import { useTable } from "@tanstack/react-table"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { createDomainColumns } from "@/features/domains/domain-columns"
import { dnsnetraTableFeatures } from "@/lib/data-table/features"
import type { DomainItem } from "@/lib/data-table/api-client"

describe("verdict column filter registration", () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("resolves the verdict column filter without an unregistered warning", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {})

    const { result } = renderHook(() =>
      useTable({
        features: dnsnetraTableFeatures,
        data: [] as DomainItem[],
        columns: createDomainColumns() as any,
        state: { columnFilters: [{ id: "verdict", value: "Benign" }] },
        manualFiltering: true,
      })
    )

    expect(result.current.getColumn("verdict")?.getFilterFn()).toBeDefined()

    const messages = warn.mock.calls.map((call) => call.join(" ")).join("\n")
    expect(messages).not.toContain("weakEquals")
  })
})
