import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import CasesPage from "@/app/(dashboard)/cases/page"
import CaseDetailPage from "@/app/(dashboard)/cases/[public_id]/page"
import { dnsnetraApi } from "@/lib/data-table/api-client"
import type { CaseDetail } from "@/lib/reporting/types"

const mockUser = vi.hoisted(() => ({
  current: { id: 1, username: "analyst", role: "ANALYST" },
}))

vi.mock("next/navigation", () => ({
  useParams: () => ({ public_id: "CASE-2026-000001" }),
}))

vi.mock("@/components/auth/AuthGuard", () => ({
  useAuthUser: () => mockUser.current,
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

function caseDetail(overrides: Partial<CaseDetail> = {}): CaseDetail {
  return {
    ...caseSummary,
    description: null,
    events: [],
    reports: [],
    ...overrides,
  }
}

function listOf(...items: (typeof caseSummary)[]) {
  return { total: items.length, limit: 50, offset: 0, has_more: false, items }
}

describe("cases UI", () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    mockUser.current = { id: 1, username: "analyst", role: "ANALYST" }
  })

  it("lists cases", async () => {
    vi.spyOn(dnsnetraApi, "listCases").mockResolvedValue(listOf(caseSummary))
    render(<CasesPage />)
    expect(await screen.findByText("Investigate beacon.example")).toBeInTheDocument()
  })

  it("moves a case to triaged", async () => {
    vi.spyOn(dnsnetraApi, "getCase").mockResolvedValue(caseDetail())
    const update = vi.spyOn(dnsnetraApi, "updateCase").mockResolvedValue(
      caseDetail({ status: "triaged" })
    )

    render(<CaseDetailPage />)
    fireEvent.click(await screen.findByRole("button", { name: "Start triage" }))
    expect(update).toHaveBeenCalledWith("CASE-2026-000001", { status: "triaged" })
  })

  it("shows no action buttons for support", async () => {
    mockUser.current = { id: 2, username: "support", role: "SUPPORT" }
    vi.spyOn(dnsnetraApi, "getCase").mockResolvedValue(caseDetail())

    render(<CaseDetailPage />)
    expect(await screen.findByText("Investigate beacon.example")).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Start triage" })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Close" })).not.toBeInTheDocument()
  })

  it("hides the comment form from support", async () => {
    mockUser.current = { id: 2, username: "support", role: "SUPPORT" }
    vi.spyOn(dnsnetraApi, "getCase").mockResolvedValue(caseDetail())

    render(<CaseDetailPage />)
    expect(await screen.findByText("Investigate beacon.example")).toBeInTheDocument()
    expect(screen.queryByLabelText("Comment")).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Comment" })).not.toBeInTheDocument()
  })

  it("does not let an analyst act on a teammate's case", async () => {
    vi.spyOn(dnsnetraApi, "getCase").mockResolvedValue(
      caseDetail({ assigned_to: 99 })
    )

    render(<CaseDetailPage />)
    expect(await screen.findByText("Investigate beacon.example")).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Start triage" })).not.toBeInTheDocument()
    // Analysts still have cases:write, so comments remain available.
    expect(screen.getByLabelText("Comment")).toBeInTheDocument()
  })

  it("lets analysts reopen but not close a resolved case", async () => {
    vi.spyOn(dnsnetraApi, "getCase").mockResolvedValue(
      caseDetail({ status: "resolved", resolution: "true_positive" })
    )

    render(<CaseDetailPage />)
    expect(await screen.findByText("Investigate beacon.example")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Reopen" })).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Close" })).not.toBeInTheDocument()
  })

  it("sends the selected resolution when resolving", async () => {
    vi.spyOn(dnsnetraApi, "getCase").mockResolvedValue(
      caseDetail({ status: "investigating" })
    )
    const update = vi.spyOn(dnsnetraApi, "updateCase").mockResolvedValue(
      caseDetail({ status: "resolved", resolution: "false_positive" })
    )

    render(<CaseDetailPage />)
    await screen.findByText("Investigate beacon.example")
    fireEvent.change(screen.getByLabelText("Resolution"), {
      target: { value: "false_positive" },
    })
    fireEvent.click(screen.getByRole("button", { name: "Resolve" }))

    await waitFor(() =>
      expect(update).toHaveBeenCalledWith("CASE-2026-000001", {
        status: "resolved",
        resolution: "false_positive",
      })
    )
  })

  it("announces an empty case detail timeline", async () => {
    vi.spyOn(dnsnetraApi, "getCase").mockResolvedValue({
      ...caseSummary,
      description: null,
      events: [],
      reports: [],
    } as any)

    render(<CaseDetailPage />)
    expect(await screen.findByText("No events yet.")).toBeInTheDocument()
    expect(screen.getByText("No linked reports.")).toBeInTheDocument()
    // Status is rendered as text, not color-only.
    expect(screen.getByText("open")).toBeInTheDocument()
    expect(screen.getByLabelText("Comment")).toBeInTheDocument()
  })

  it("blocks a second comment while the first is pending", async () => {
    vi.spyOn(dnsnetraApi, "getCase").mockResolvedValue(caseDetail())
    let resolveComment!: (value: CaseDetail) => void
    const comment = vi.spyOn(dnsnetraApi, "commentCase").mockReturnValue(
      new Promise<CaseDetail>((resolve) => {
        resolveComment = resolve
      })
    )

    render(<CaseDetailPage />)
    await screen.findByText("Investigate beacon.example")
    fireEvent.change(screen.getByLabelText("Comment"), {
      target: { value: "note" },
    })
    const button = screen.getByRole("button", { name: "Comment" })
    fireEvent.click(button)
    fireEvent.click(button)

    expect(comment).toHaveBeenCalledTimes(1)
    expect(button).toHaveTextContent("Working…")

    resolveComment(
      caseDetail({
        events: [{
          id: 1,
          kind: "comment",
          body: "note",
          metadata: {},
          created_at: "2026-11-10T00:00:00Z",
        }],
      })
    )
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Comment" })).not.toBeDisabled()
    )
  })
})
