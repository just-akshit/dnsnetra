import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import ClientProfilePage from "@/app/(dashboard)/clients/[client_ip]/page"
import DomainProfilePage from "@/app/(dashboard)/domains/[domain]/page"
import ReportDetailPage from "@/app/(dashboard)/reports/saved/[public_id]/page"
import { dnsnetraApi } from "@/lib/data-table/api-client"

vi.mock("next/navigation", () => ({
  useParams: () => ({
    public_id: "RPT-2026-000001",
    domain: "example.com",
    client_ip: "203.0.113.10",
  }),
  useRouter: () => ({ push: () => {} }),
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
    expect(
      await screen.findByRole("link", { name: "CASE-2026-000001" })
    ).toHaveAttribute("href", "/cases/CASE-2026-000001")
  })

  it("disables Open case while the request is pending", async () => {
    vi.spyOn(dnsnetraApi, "getSavedReport").mockResolvedValue(report as any)
    let resolveCase!: (value: any) => void
    vi.spyOn(dnsnetraApi, "createCase").mockReturnValue(
      new Promise((resolve) => {
        resolveCase = resolve
      })
    )

    render(<ReportDetailPage />)
    const button = await screen.findByRole("button", { name: "Open case" })
    fireEvent.click(button)

    expect(button).toBeDisabled()
    expect(button).toHaveAttribute("aria-busy", "true")

    resolveCase({
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
    })
    await waitFor(() => expect(button).not.toBeDisabled())
  })
})

describe("dossier case actions", () => {
  beforeEach(() => vi.restoreAllMocks())

  const domainDetail = {
    domain: "example.com",
    observed_in_network: true,
    live_intel: null,
    profile: {
      domain: "example.com",
      first_seen: "2026-11-01T00:00:00Z",
      last_seen: "2026-11-10T00:00:00Z",
      total_queries: 4,
      unique_clients: 1,
      benign_queries: 4,
      malicious_queries: 0,
      review_needed_queries: 0,
      unknown_queries: 0,
      query_type_distribution: {},
      last_client_ip: null,
      last_label: "Benign",
      last_ti_source: null,
    },
    top_querying_clients: [],
    threat_intel: {},
    recent_queries: [],
    registration: null,
    dns_records: null,
  }

  const clientDetail = {
    client_ip: "203.0.113.10",
    observed_in_network: true,
    live_intel: null,
    profile: {
      client_ip: "203.0.113.10",
      first_seen: "2026-11-01T00:00:00Z",
      last_seen: "2026-11-10T00:00:00Z",
      total_queries: 4,
      unique_domains: 2,
      benign_queries: 4,
      malicious_queries: 0,
      review_needed_queries: 0,
      unknown_queries: 0,
      last_domain: "example.com",
      last_query_type: "A",
    },
    top_domains: [],
    threat_activity: [],
    recent_queries: [],
  }

  const createdCase = {
    public_id: "CASE-2026-000009",
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
    reports: [],
  }

  it("opens a case from a domain dossier", async () => {
    vi.spyOn(dnsnetraApi, "getDomainInvestigation").mockResolvedValue(domainDetail as any)
    const create = vi.spyOn(dnsnetraApi, "createCase").mockResolvedValue(createdCase as any)

    render(<DomainProfilePage />)
    fireEvent.click(await screen.findByRole("button", { name: "Open case" }))

    await waitFor(() =>
      expect(create).toHaveBeenCalledWith({
        title: "Investigate example.com",
        priority: "medium",
        entity_type: "domain",
        entity_value: "example.com",
      })
    )
  })

  it("opens a case from a client dossier", async () => {
    vi.spyOn(dnsnetraApi, "getClientInvestigation").mockResolvedValue(clientDetail as any)
    const create = vi.spyOn(dnsnetraApi, "createCase").mockResolvedValue({
      ...createdCase,
      title: "Investigate 203.0.113.10",
      entity_type: "client",
      entity_value: "203.0.113.10",
    } as any)

    render(<ClientProfilePage />)
    fireEvent.click(await screen.findByRole("button", { name: "Open case" }))

    await waitFor(() =>
      expect(create).toHaveBeenCalledWith({
        title: "Investigate 203.0.113.10",
        priority: "medium",
        entity_type: "client",
        entity_value: "203.0.113.10",
      })
    )
  })
})
