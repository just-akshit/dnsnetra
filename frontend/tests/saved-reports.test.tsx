import { render, screen, waitFor } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import SavedReportsPage from "@/app/(dashboard)/reports/saved/page"
import { dnsnetraApi } from "@/lib/data-table/api-client"

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }))

describe("SavedReportsPage", () => {
  beforeEach(() => vi.restoreAllMocks())

  it("lists saved reports", async () => {
    vi.spyOn(dnsnetraApi, "listSavedReports").mockResolvedValue({
      total: 1,
      limit: 50,
      offset: 0,
      items: [{
        public_id: "RPT-2026-000001",
        kind: "entity_domain",
        entity_type: "domain",
        entity_value: "example.com",
        title: "example.com review",
        status: "reviewed",
        verdict: "Malicious",
        created_by: 1,
        reviewed_at: "2026-11-10T00:00:00Z",
        case_public_id: null,
        created_at: "2026-11-10T00:00:00Z",
      }],
    })

    render(<SavedReportsPage />)
    expect(await screen.findByText("example.com review")).toBeInTheDocument()
    expect(screen.getByText("RPT-2026-000001")).toBeInTheDocument()
    await waitFor(() => expect(dnsnetraApi.listSavedReports).toHaveBeenCalled())
  })

  it("shows an empty state", async () => {
    vi.spyOn(dnsnetraApi, "listSavedReports").mockResolvedValue({
      total: 0, limit: 50, offset: 0, items: [],
    })
    render(<SavedReportsPage />)
    expect(await screen.findByText("No saved reports yet.")).toBeInTheDocument()
  })
})
