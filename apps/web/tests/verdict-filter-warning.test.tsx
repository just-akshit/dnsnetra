import { renderHook } from "@testing-library/react"
import { useTable, type ColumnDef } from "@tanstack/react-table"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { createDomainColumns } from "@/features/domains/domain-columns"
import { dnsnetraTableFeatures } from "@/lib/data-table/features"
import type { DnsnetraTableFeatures } from "@/lib/data-table/features"
import type { DomainItem } from "@/lib/data-table/api-client"

/**
 * `createDomainColumns()` returns a heterogeneous array whose per-column value
 * types (string, number, ...) do not widen to a single `ColumnDef` element type,
 * so the array is viewed at the table's `unknown` value type for this check.
 */
type TableColumns = readonly ColumnDef<DnsnetraTableFeatures, DomainItem, unknown>[]

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
        columns: createDomainColumns() as unknown as TableColumns,
        state: { columnFilters: [{ id: "verdict", value: "Benign" }] },
        manualFiltering: true,
      })
    )

    expect(result.current.getColumn("verdict")?.getFilterFn()).toBeDefined()

    const messages = warn.mock.calls.map((call) => call.join(" ")).join("\n")
    expect(messages).not.toContain("weakEquals")
  })
})
