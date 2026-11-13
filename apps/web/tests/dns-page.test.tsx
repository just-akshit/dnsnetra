import { fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import DnsPage from "@/app/(dashboard)/dns/page"
import { dnsnetraApi } from "@/lib/data-table/api-client"

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => "/dns",
}))

const row = {
  domain: "ads.example.com",
  registered_domain: "example.com",
  query_type: "A",
  client_ip: "10.0.0.12",
  first_seen: "2026-09-01T10:00:00Z",
  last_seen: "2026-09-29T20:20:18Z",
  total_queries: 42,
}

describe("DNS page", () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(dnsnetraApi, "getDnsDomains").mockResolvedValue({
      total: 1,
      limit: 25,
      offset: 0,
      has_more: false,
      items: [row],
    })
    vi.spyOn(dnsnetraApi, "getDomainDetail").mockResolvedValue({
      domain: "ads.example.com",
      observed_in_network: true,
      profile: null,
      top_querying_clients: [],
      threat_intel: {},
      recent_queries: [],
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("shows one row per domain with first/last seen, type, and client", async () => {
    render(<DnsPage />)

    expect(await screen.findByText("ads.example.com")).toBeInTheDocument()
    expect(screen.getByText("example.com")).toBeInTheDocument()
    expect(screen.getByText("First seen")).toBeInTheDocument()
    expect(screen.getByText("Last seen")).toBeInTheDocument()
    expect(screen.getByText("Type")).toBeInTheDocument()
    expect(screen.getByText("Client IP")).toBeInTheDocument()
    expect(screen.getByText("A")).toBeInTheDocument()
    expect(screen.getByText("10.0.0.12")).toBeInTheDocument()
  })

  it("opens the full domain profile from the query name", async () => {
    render(<DnsPage />)

    fireEvent.click(await screen.findByText("ads.example.com"))

    await waitFor(() =>
      expect(dnsnetraApi.getDomainDetail).toHaveBeenCalledWith("ads.example.com")
    )
  })
})
