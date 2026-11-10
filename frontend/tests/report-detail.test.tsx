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
  row_count: 4,
  filters: {},
  snapshot: {
    schema_version: 1,
    kind: "entity_domain",
    entity: { type: "domain", value: "example.com" },
    observed_in_network: false,
    dossier: {
      domain: "example.com",
      profile: { total_queries: 7, unique_clients: 2 },
      recent_queries: [],
      live_intel: { verdict: { state: "unknown" }, checked_at: "2026-11-10T00:00:00Z" },
    },
    provenance: { sources: ["domain_query_history"] },
  },
  created_at: "2026-11-10T00:00:00Z",
}

describe("ReportDetailPage", () => {
  beforeEach(() => vi.restoreAllMocks())

  it("renders the snapshot and marks it reviewed", async () => {
    vi.spyOn(dnsnetraApi, "getSavedReport").mockResolvedValue(report as any)
    const reviewSpy = vi.spyOn(dnsnetraApi, "reviewSavedReport").mockResolvedValue({
      ...report,
      status: "reviewed",
    } as any)

    render(<ReportDetailPage />)
    expect(await screen.findByText(/example\.com/)).toBeInTheDocument()
    expect(screen.getByText("No local telemetry for this window.")).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText("Conclusion"), {
      target: { value: "Not observed locally." },
    })
    fireEvent.click(screen.getByRole("button", { name: "Mark reviewed" }))

    expect(await screen.findByText("reviewed")).toBeInTheDocument()
    expect(reviewSpy).toHaveBeenCalledWith("RPT-2026-000001", {
      status: "reviewed",
      conclusion: "Not observed locally.",
      verdict: undefined,
    })
  })

  it("seeds the conclusion and shows review metadata for a reviewed report", async () => {
    vi.spyOn(dnsnetraApi, "getSavedReport").mockResolvedValue({
      ...report,
      status: "reviewed",
      conclusion: "Known benign resolver.",
      reviewed_at: "2026-11-11T12:00:00Z",
      reviewed_by: 7,
    } as any)

    render(<ReportDetailPage />)

    expect(await screen.findByDisplayValue("Known benign resolver.")).toBeInTheDocument()
    expect(screen.getByText(/2026-11-11T12:00:00Z/)).toBeInTheDocument()
    expect(screen.getByText(/by 7/)).toBeInTheDocument()
    expect(screen.getByText("reviewed")).toBeInTheDocument()
  })

  it("exports XLSX", async () => {
    vi.spyOn(dnsnetraApi, "getSavedReport").mockResolvedValue(report as any)
    const spy = vi.spyOn(dnsnetraApi, "downloadSavedReport").mockResolvedValue()
    render(<ReportDetailPage />)
    fireEvent.click(await screen.findByRole("button", { name: "Export XLSX" }))
    expect(spy).toHaveBeenCalledWith("RPT-2026-000001", "xlsx")
  })
})
