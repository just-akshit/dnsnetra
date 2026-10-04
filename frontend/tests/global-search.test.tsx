import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { render, screen, fireEvent, cleanup } from "@testing-library/react"
import * as React from "react"
import { GlobalIntelligenceSearch } from "@/components/global-intelligence-search"
import { dnsnetraApi } from "@/lib/data-table/api-client"

const mockPush = vi.fn()
vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: mockPush,
  }),
  usePathname: () => "/dashboard",
  useSearchParams: () => new URLSearchParams(),
}))

describe("dnsnetraApi.searchIntelligence", () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    mockPush.mockClear()
  })

  afterEach(() => {
    cleanup()
  })

  it("returns empty arrays when query is empty or whitespace", async () => {
    const result = await dnsnetraApi.searchIntelligence("   ")
    expect(result).toEqual({ domains: [], clients: [], queries: [] })
  })

  it("prioritizes exact domain match over partial matches", async () => {
    vi.spyOn(dnsnetraApi, "getDomains").mockResolvedValue({
      total: 3,
      limit: 10,
      offset: 0,
      has_more: false,
      items: [
        {
          domain: "googleusercontent.com",
          total_queries: 10000,
          unique_clients: 5,
          benign_queries: 10000,
          malicious_queries: 0,
          review_needed_queries: 0,
          unknown_queries: 0,
          first_seen: "2026-09-01T00:00:00Z",
          last_seen: "2026-10-01T00:00:00Z",
        },
        {
          domain: "google.com",
          total_queries: 500,
          unique_clients: 2,
          benign_queries: 500,
          malicious_queries: 0,
          review_needed_queries: 0,
          unknown_queries: 0,
          first_seen: "2026-09-01T00:00:00Z",
          last_seen: "2026-10-01T00:00:00Z",
        },
        {
          domain: "googleapis.com",
          total_queries: 8000,
          unique_clients: 4,
          benign_queries: 8000,
          malicious_queries: 0,
          review_needed_queries: 0,
          unknown_queries: 0,
          first_seen: "2026-09-01T00:00:00Z",
          last_seen: "2026-10-01T00:00:00Z",
        },
      ],
    })
    vi.spyOn(dnsnetraApi, "getClients").mockResolvedValue({
      total: 0,
      limit: 10,
      offset: 0,
      has_more: false,
      items: [],
    })
    vi.spyOn(dnsnetraApi, "getQueries").mockResolvedValue({
      total: 0,
      limit: 10,
      offset: 0,
      has_more: false,
      items: [],
    })

    const result = await dnsnetraApi.searchIntelligence("google.com")
    // Exact match "google.com" must be first despite lower total_queries
    expect(result.domains[0].domain).toBe("google.com")
  })

  it("prioritizes exact client IP match", async () => {
    vi.spyOn(dnsnetraApi, "getDomains").mockResolvedValue({
      total: 0,
      limit: 10,
      offset: 0,
      has_more: false,
      items: [],
    })
    vi.spyOn(dnsnetraApi, "getClients").mockResolvedValue({
      total: 2,
      limit: 10,
      offset: 0,
      has_more: false,
      items: [
        {
          client_ip: "192.168.1.114",
          total_queries: 5000,
          unique_domains: 10,
          benign_queries: 5000,
          malicious_queries: 0,
          review_needed_queries: 0,
          unknown_queries: 0,
          first_seen: "2026-09-01T00:00:00Z",
          last_seen: "2026-10-01T00:00:00Z",
        },
        {
          client_ip: "192.168.1.1",
          total_queries: 100,
          unique_domains: 2,
          benign_queries: 100,
          malicious_queries: 0,
          review_needed_queries: 0,
          unknown_queries: 0,
          first_seen: "2026-09-01T00:00:00Z",
          last_seen: "2026-10-01T00:00:00Z",
        },
      ],
    })
    vi.spyOn(dnsnetraApi, "getQueries").mockResolvedValue({
      total: 0,
      limit: 10,
      offset: 0,
      has_more: false,
      items: [],
    })

    const result = await dnsnetraApi.searchIntelligence("192.168.1.1")
    expect(result.clients[0].client_ip).toBe("192.168.1.1")
  })
})

describe("GlobalIntelligenceSearch Component", () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    mockPush.mockClear()
  })

  afterEach(() => {
    cleanup()
  })

  it("renders desktop and mobile trigger buttons with placeholder", () => {
    render(<GlobalIntelligenceSearch />)
    expect(
      screen.getByText("Search domain, client, query...")
    ).toBeInTheDocument()
  })

  it("opens dialog when trigger button is clicked", async () => {
    render(<GlobalIntelligenceSearch />)
    const trigger = screen.getAllByRole("button", {
      name: "Search DNSNetra Intelligence",
    })[0]
    fireEvent.click(trigger)

    expect(
      await screen.findByPlaceholderText("Search domain, client, query...")
    ).toBeInTheDocument()
  })

  it("opens dialog on Cmd+K / Ctrl+K keyboard shortcut", async () => {
    render(<GlobalIntelligenceSearch />)
    fireEvent.keyDown(window, { key: "k", metaKey: true })

    expect(
      await screen.findByPlaceholderText("Search domain, client, query...")
    ).toBeInTheDocument()
  })

  it("displays categorized results when search query is entered", async () => {
    vi.spyOn(dnsnetraApi, "searchIntelligence")
      .mockResolvedValue({
        domains: [
          {
            domain: "malicious-c2.org",
            total_queries: 42,
            unique_clients: 2,
            benign_queries: 0,
            malicious_queries: 42,
            review_needed_queries: 0,
            unknown_queries: 0,
            latest_verdict: "Malicious",
            first_seen: "2026-09-15T00:00:00Z",
            last_seen: "2026-10-01T05:00:00Z",
          },
        ],
        clients: [
          {
            client_ip: "10.0.0.99",
            total_queries: 120,
            unique_domains: 15,
            benign_queries: 100,
            malicious_queries: 20,
            review_needed_queries: 0,
            unknown_queries: 0,
            first_seen: "2026-09-15T00:00:00Z",
            last_seen: "2026-10-01T05:00:00Z",
          },
        ],
        queries: [
          {
            id: 9999,
            timestamp: "2026-10-01T05:00:00Z",
            client_ip: "10.0.0.77",
            domain: "query-target.com",
            query_type: "A",
            final_label: "Malicious",
          },
        ],
      })

    render(<GlobalIntelligenceSearch />)
    const trigger = screen.getAllByRole("button", {
      name: "Search DNSNetra Intelligence",
    })[0]
    fireEvent.click(trigger)

    const input = await screen.findByPlaceholderText(
      "Search domain, client, query..."
    )
    fireEvent.change(input, { target: { value: "malicious" } })

    const domainItem = await screen.findByText("malicious-c2.org")
    expect(domainItem).toBeInTheDocument()
    expect(await screen.findByText("10.0.0.99")).toBeInTheDocument()
    expect(await screen.findByText("query-target.com")).toBeInTheDocument()
  })

  it("navigates to domain profile when domain result is clicked", async () => {
    vi.spyOn(dnsnetraApi, "searchIntelligence").mockResolvedValue({
      domains: [
        {
          domain: "threat-sample.com",
          total_queries: 10,
          unique_clients: 1,
          benign_queries: 0,
          malicious_queries: 10,
          review_needed_queries: 0,
          unknown_queries: 0,
          latest_verdict: "Malicious",
          first_seen: "2026-09-15T00:00:00Z",
          last_seen: "2026-10-01T05:00:00Z",
        },
      ],
      clients: [],
      queries: [],
    })

    render(<GlobalIntelligenceSearch />)
    const trigger = screen.getAllByRole("button", {
      name: "Search DNSNetra Intelligence",
    })[0]
    fireEvent.click(trigger)

    const input = await screen.findByPlaceholderText(
      "Search domain, client, query..."
    )
    fireEvent.change(input, { target: { value: "threat" } })

    const domainItem = await screen.findByText("threat-sample.com")
    fireEvent.click(domainItem)

    expect(mockPush).toHaveBeenCalledWith("/domains/threat-sample.com")
  })
})
