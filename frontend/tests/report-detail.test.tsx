import { fireEvent, render, screen, waitFor } from "@testing-library/react"
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
    expect(await screen.findByRole("heading", { name: "example.com review" })).toBeInTheDocument()
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

  it("seeds and sends the assessed verdict on review", async () => {
    vi.spyOn(dnsnetraApi, "getSavedReport").mockResolvedValue({
      ...report,
      verdict: "Benign",
    } as any)
    const reviewSpy = vi.spyOn(dnsnetraApi, "reviewSavedReport").mockResolvedValue({
      ...report,
      status: "reviewed",
      verdict: "Malicious",
    } as any)

    render(<ReportDetailPage />)

    const verdictSelect = await screen.findByLabelText("Assessed verdict")
    expect(verdictSelect).toHaveValue("Benign")
    expect(screen.getByText("Benign", { selector: "span" })).toBeInTheDocument()

    fireEvent.change(verdictSelect, { target: { value: "Malicious" } })
    fireEvent.change(screen.getByLabelText("Conclusion"), {
      target: { value: "Confirmed malicious." },
    })
    fireEvent.click(screen.getByRole("button", { name: "Mark reviewed" }))

    await waitFor(() =>
      expect(reviewSpy).toHaveBeenCalledWith("RPT-2026-000001", {
        status: "reviewed",
        conclusion: "Confirmed malicious.",
        verdict: "Malicious",
      })
    )
  })

  it("renders the sectioned snapshot without inventing data", async () => {
    vi.spyOn(dnsnetraApi, "getSavedReport").mockResolvedValue({
      ...report,
      snapshot: {
        ...report.snapshot,
        observed_in_network: true,
        dossier: {
          domain: "example.com",
          profile: {
            total_queries: 9,
            unique_clients: 3,
            benign_queries: 4,
            malicious_queries: 2,
            review_needed_queries: 2,
            unknown_queries: 1,
          },
          registration: {
            status: "AVAILABLE",
            registrar: "Example Registrar",
            created_at: "2020-01-01T00:00:00Z",
            nameservers: ["ns1.example.com"],
          },
          recent_queries: [
            {
              id: 1,
              timestamp: "2026-11-10T00:00:00Z",
              client_ip: "10.0.0.5",
              domain: "example.com",
              query_type: "A",
              final_label: "Malicious",
              ti_source: "feed",
            },
          ],
          threat_intel: {
            reputation: {
              status: "malicious",
              source: "local-feed",
              last_seen: "2026-11-09T00:00:00Z",
            },
          },
          live_intel: {
            checked_at: "2026-11-10T00:00:00Z",
            verdict: { state: "malicious", confidence: 0.8 },
            providers: [
              {
                provider: "virustotal",
                status: "ok",
                malicious: 3,
                suspicious: 0,
                harmless: 60,
                total: 70,
              },
            ],
          },
        },
        provenance: {
          sources: ["domain_query_history", "live_intel"],
          generated_at: "2026-11-10T00:00:00Z",
        },
      },
    } as any)

    render(<ReportDetailPage />)

    expect(await screen.findByText("Identity & registration")).toBeInTheDocument()
    expect(screen.getByText("Example Registrar")).toBeInTheDocument()
    expect(screen.getByText("Local telemetry")).toBeInTheDocument()
    expect(screen.getByText("Recent queries")).toBeInTheDocument()
    expect(screen.getByText("10.0.0.5")).toBeInTheDocument()
    expect(screen.getByText("Persisted intelligence")).toBeInTheDocument()
    expect(screen.getByText("local-feed")).toBeInTheDocument()
    expect(screen.getByText("Provenance")).toBeInTheDocument()
    expect(screen.getByText("domain_query_history, live_intel")).toBeInTheDocument()
    expect(screen.getByText("Live intelligence")).toBeInTheDocument()
    expect(screen.getByText("virustotal")).toBeInTheDocument()
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
