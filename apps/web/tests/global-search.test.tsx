import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import {
  render,
  screen,
  fireEvent,
  cleanup,
  waitFor,
  act,
} from "@testing-library/react"
import * as React from "react"
import { GlobalIntelligenceSearch } from "@/components/global-intelligence-search"
import { dnsnetraApi } from "@/lib/data-table/api-client"
import type { GlobalSearchResult } from "@/lib/data-table/api-client"

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

  it("keeps healthy categories and reports the failed one", async () => {
    vi.spyOn(dnsnetraApi, "getDomains").mockResolvedValue({
      total: 1,
      limit: 10,
      offset: 0,
      has_more: false,
      items: [
        {
          domain: "partial.example",
          total_queries: 1,
          unique_clients: 1,
          benign_queries: 1,
          malicious_queries: 0,
          review_needed_queries: 0,
          unknown_queries: 0,
          first_seen: "2026-09-01T00:00:00Z",
          last_seen: "2026-10-01T00:00:00Z",
        },
      ],
    })
    vi.spyOn(dnsnetraApi, "getClients").mockRejectedValue(new Error("403"))
    vi.spyOn(dnsnetraApi, "getQueries").mockResolvedValue({
      total: 0,
      limit: 10,
      offset: 0,
      has_more: false,
      items: [],
    })

    const result = await dnsnetraApi.searchIntelligence("partial")

    expect(result.domains[0].domain).toBe("partial.example")
    expect(result.clients).toEqual([])
    expect(result.unavailable).toEqual(["clients"])
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
      screen.getByText("Search any domain or IP...")
    ).toBeInTheDocument()
  })

  it("opens dialog when trigger button is clicked", async () => {
    render(<GlobalIntelligenceSearch />)
    const trigger = screen.getAllByRole("button", {
      name: "Search DNSNetra Intelligence",
    })[0]
    fireEvent.click(trigger)

    expect(
      await screen.findByPlaceholderText("Search any domain or IP...")
    ).toBeInTheDocument()
  })

  it("opens dialog on Cmd+K / Ctrl+K keyboard shortcut", async () => {
    render(<GlobalIntelligenceSearch />)
    fireEvent.keyDown(window, { key: "k", metaKey: true })

    expect(
      await screen.findByPlaceholderText("Search any domain or IP...")
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
      "Search any domain or IP..."
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
      "Search any domain or IP..."
    )
    fireEvent.change(input, { target: { value: "threat" } })

    const domainItem = await screen.findByText("threat-sample.com")
    fireEvent.click(domainItem)

    expect(mockPush).toHaveBeenCalledWith("/domains/threat-sample.com")
  })

  it("investigates an arbitrary unobserved domain directly from the search bar", async () => {
    vi.spyOn(dnsnetraApi, "searchIntelligence").mockResolvedValue({
      domains: [],
      clients: [],
      queries: [],
    })

    render(<GlobalIntelligenceSearch />)
    fireEvent.click(
      screen.getAllByRole("button", { name: "Search DNSNetra Intelligence" })[0]
    )

    const input = await screen.findByPlaceholderText("Search any domain or IP...")
    fireEvent.change(input, { target: { value: "unseen-domain.example" } })

    expect(await screen.findByText("unseen-domain.example")).toBeInTheDocument()

    fireEvent.keyDown(input, { key: "Enter" })
    expect(mockPush).toHaveBeenCalledWith("/domains/unseen-domain.example")
  })

  it("normalizes pasted URLs before investigating", async () => {
    vi.spyOn(dnsnetraApi, "searchIntelligence").mockResolvedValue({
      domains: [],
      clients: [],
      queries: [],
    })

    render(<GlobalIntelligenceSearch />)
    fireEvent.click(
      screen.getAllByRole("button", { name: "Search DNSNetra Intelligence" })[0]
    )

    const input = await screen.findByPlaceholderText("Search any domain or IP...")
    fireEvent.change(input, { target: { value: "https://Evil.Example/login?x=1" } })

    expect(await screen.findByText("evil.example")).toBeInTheDocument()

    fireEvent.keyDown(input, { key: "Enter" })
    expect(mockPush).toHaveBeenCalledWith("/domains/evil.example")
  })

  it("opens client activity when an IP address is entered", async () => {
    vi.spyOn(dnsnetraApi, "searchIntelligence").mockResolvedValue({
      domains: [],
      clients: [],
      queries: [],
    })

    render(<GlobalIntelligenceSearch />)
    fireEvent.click(
      screen.getAllByRole("button", { name: "Search DNSNetra Intelligence" })[0]
    )

    const input = await screen.findByPlaceholderText("Search any domain or IP...")
    fireEvent.change(input, { target: { value: "203.0.113.9" } })
    fireEvent.keyDown(input, { key: "Enter" })

    expect(mockPush).toHaveBeenCalledWith("/clients/203.0.113.9")
  })

  it("shows validation feedback for input that is not a domain or IP", async () => {
    vi.spyOn(dnsnetraApi, "searchIntelligence").mockResolvedValue({
      domains: [],
      clients: [],
      queries: [],
    })

    render(<GlobalIntelligenceSearch />)
    fireEvent.click(
      screen.getAllByRole("button", { name: "Search DNSNetra Intelligence" })[0]
    )

    const input = await screen.findByPlaceholderText("Search any domain or IP...")
    fireEvent.change(input, { target: { value: "not a domain" } })

    expect(
      await screen.findByText("Spaces are not valid in a domain or IP.")
    ).toBeInTheDocument()

    fireEvent.keyDown(input, { key: "Enter" })
    expect(mockPush).not.toHaveBeenCalled()
  })

  it("does not query until the minimum search length is met", async () => {
    const spy = vi.spyOn(dnsnetraApi, "searchIntelligence").mockResolvedValue({
      domains: [],
      clients: [],
      queries: [],
    })

    render(<GlobalIntelligenceSearch />)
    fireEvent.click(
      screen.getAllByRole("button", { name: "Search DNSNetra Intelligence" })[0]
    )

    const input = await screen.findByPlaceholderText("Search any domain or IP...")
    fireEvent.change(input, { target: { value: "a" } })

    expect(
      screen.getByText("Type at least 2 characters to search telemetry.")
    ).toBeInTheDocument()

    await new Promise((resolve) => setTimeout(resolve, 350))
    expect(spy).not.toHaveBeenCalled()
  })

  it("shows which categories failed but keeps the rest", async () => {
    vi.spyOn(dnsnetraApi, "searchIntelligence").mockResolvedValue({
      domains: [
        {
          domain: "partial.example",
          total_queries: 1,
          unique_clients: 1,
          benign_queries: 1,
          malicious_queries: 0,
          review_needed_queries: 0,
          unknown_queries: 0,
          latest_verdict: "Benign",
          first_seen: "2026-09-15T00:00:00Z",
          last_seen: "2026-10-01T05:00:00Z",
        },
      ],
      clients: [],
      queries: [],
      unavailable: ["clients", "queries"],
    })

    render(<GlobalIntelligenceSearch />)
    fireEvent.click(
      screen.getAllByRole("button", { name: "Search DNSNetra Intelligence" })[0]
    )

    const input = await screen.findByPlaceholderText("Search any domain or IP...")
    fireEvent.change(input, { target: { value: "partial" } })

    expect(await screen.findByText("partial.example")).toBeInTheDocument()
    expect(
      screen.getByText("Partial results — clients, queries unavailable.")
    ).toBeInTheDocument()
  })

  it("does not leave the spinner stuck when the dialog closes mid-search", async () => {
    // Never resolves: the request is still in flight when the user closes.
    vi.spyOn(dnsnetraApi, "searchIntelligence").mockImplementation(
      () => new Promise<GlobalSearchResult>(() => {})
    )

    render(<GlobalIntelligenceSearch />)
    fireEvent.click(
      screen.getAllByRole("button", { name: "Search DNSNetra Intelligence" })[0]
    )

    const input = await screen.findByPlaceholderText("Search any domain or IP...")
    fireEvent.change(input, { target: { value: "slow.example" } })
    expect(
      await screen.findByText("Searching DNS intelligence...")
    ).toBeInTheDocument()

    fireEvent.keyDown(input, { key: "Escape" })

    fireEvent.click(
      screen.getAllByRole("button", { name: "Search DNSNetra Intelligence" })[0]
    )

    expect(
      await screen.findByText("Global DNSNetra SOC Intelligence")
    ).toBeInTheDocument()
    expect(
      screen.queryByText("Searching DNS intelligence...")
    ).not.toBeInTheDocument()
  })

  it("ignores a stale response that arrives after a newer query", async () => {
    let resolveSlow: (value: GlobalSearchResult) => void = () => {}
    let resolveFast: (value: GlobalSearchResult) => void = () => {}
    const slow = new Promise<GlobalSearchResult>((resolve) => {
      resolveSlow = resolve
    })
    const fast = new Promise<GlobalSearchResult>((resolve) => {
      resolveFast = resolve
    })

    const spy = vi
      .spyOn(dnsnetraApi, "searchIntelligence")
      .mockImplementationOnce(() => slow)
      .mockImplementationOnce(() => fast)

    render(<GlobalIntelligenceSearch />)
    fireEvent.click(
      screen.getAllByRole("button", { name: "Search DNSNetra Intelligence" })[0]
    )

    const input = await screen.findByPlaceholderText("Search any domain or IP...")
    fireEvent.change(input, { target: { value: "slow" } })

    // Wait past the debounce so the first (slow) request is actually in flight.
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1))

    fireEvent.change(input, { target: { value: "fast" } })
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(2))

    // The newer request resolves first.
    await act(async () => {
      resolveFast({
        domains: [
          {
            domain: "fast-result.com",
            total_queries: 5,
            unique_clients: 1,
            benign_queries: 5,
            malicious_queries: 0,
            review_needed_queries: 0,
            unknown_queries: 0,
            latest_verdict: "Benign",
            first_seen: "2026-09-15T00:00:00Z",
            last_seen: "2026-10-01T05:00:00Z",
          },
        ],
        clients: [],
        queries: [],
      })
    })
    expect(await screen.findByText("fast-result.com")).toBeInTheDocument()

    // The older request resolves late; its results must be dropped.
    await act(async () => {
      resolveSlow({
        domains: [
          {
            domain: "stale-result.com",
            total_queries: 5,
            unique_clients: 1,
            benign_queries: 5,
            malicious_queries: 0,
            review_needed_queries: 0,
            unknown_queries: 0,
            latest_verdict: "Benign",
            first_seen: "2026-09-15T00:00:00Z",
            last_seen: "2026-10-01T05:00:00Z",
          },
        ],
        clients: [],
        queries: [],
      })
    })

    await waitFor(() =>
      expect(screen.queryByText("stale-result.com")).not.toBeInTheDocument()
    )
    expect(screen.getByText("fast-result.com")).toBeInTheDocument()
  })
})
