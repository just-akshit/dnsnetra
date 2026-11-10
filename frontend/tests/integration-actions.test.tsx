import { fireEvent, render, screen } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import ReportDetailPage from "@/app/(dashboard)/reports/saved/[public_id]/page"
import { dnsnetraApi } from "@/lib/data-table/api-client"

vi.mock("next/navigation", () => ({
  useParams: () => ({ public_id: "RPT-2026-000001" }),
}))

const report = {
  public_id: "RPT-2026-000001",
  kind: "entity_domain",
  entity_type: "domain",
  entity_value: "example.com",
  title: "example.com review",
  status: "draft",
  verdict: null,
  conclusion: null,
  row_count: 1,
  filters: {},
  snapshot: { schema_version: 1, kind: "entity_domain",
    entity: { type: "domain", value: "example.com" },
    observed_in_network: false,
    dossier: { profile: {}, recent_queries: [], live_intel: {} },
    provenance: { sources: [] } },
  created_at: "2026-11-10T00:00:00Z",
}

describe("report to case", () => {
  beforeEach(() => vi.restoreAllMocks())

  it("creates a case from a report", async () => {
    vi.spyOn(dnsnetraApi, "getSavedReport").mockResolvedValue(report as any)
    const create = vi.spyOn(dnsnetraApi, "createCase").mockResolvedValue({
      public_id: "CASE-2026-000001",
      title: "Investigate example.com",
      status: "open",
      priority: "medium",
      entity_type: "domain",
      entity_value: "example.com",
      assigned_to: null,
      created_by: 1,
      resolution: null,
      created_at: "2026-11-10T00:00:00Z",
      updated_at: "2026-11-10T00:00:00Z",
      events: [],
      reports: ["RPT-2026-000001"],
    } as any)

    render(<ReportDetailPage />)
    fireEvent.click(await screen.findByRole("button", { name: "Open case" }))
    expect(create).toHaveBeenCalledWith({
      title: "Investigate example.com",
      priority: "medium",
      entity_type: "domain",
      entity_value: "example.com",
      report_id: "RPT-2026-000001",
    })
  })
})
