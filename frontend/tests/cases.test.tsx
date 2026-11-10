import { fireEvent, render, screen } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import CasesPage from "@/app/(dashboard)/cases/page"
import CaseDetailPage from "@/app/(dashboard)/cases/[public_id]/page"
import { dnsnetraApi } from "@/lib/data-table/api-client"

vi.mock("next/navigation", () => ({
  useParams: () => ({ public_id: "CASE-2026-000001" }),
}))

const caseSummary = {
  public_id: "CASE-2026-000001",
  title: "Investigate beacon.example",
  status: "open",
  priority: "high",
  entity_type: "domain",
  entity_value: "beacon.example",
  assigned_to: null,
  created_by: 1,
  resolution: null,
  created_at: "2026-11-10T00:00:00Z",
  updated_at: "2026-11-10T00:00:00Z",
}

describe("cases UI", () => {
  beforeEach(() => vi.restoreAllMocks())

  it("lists cases", async () => {
    vi.spyOn(dnsnetraApi, "listCases").mockResolvedValue({
      total: 1, limit: 50, offset: 0, items: [caseSummary],
    })
    render(<CasesPage />)
    expect(await screen.findByText("Investigate beacon.example")).toBeInTheDocument()
  })

  it("moves a case to triaged", async () => {
    vi.spyOn(dnsnetraApi, "getCase").mockResolvedValue({
      ...caseSummary,
      description: null,
      events: [],
      reports: [],
    } as any)
    const update = vi.spyOn(dnsnetraApi, "updateCase").mockResolvedValue({
      ...caseSummary,
      status: "triaged",
      events: [],
      reports: [],
    } as any)

    render(<CaseDetailPage />)
    fireEvent.click(await screen.findByRole("button", { name: "Start triage" }))
    expect(update).toHaveBeenCalledWith("CASE-2026-000001", { status: "triaged" })
  })
})
