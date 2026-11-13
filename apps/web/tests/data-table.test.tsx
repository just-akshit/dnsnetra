import * as React from "react"
import { describe, it, expect, vi } from "vitest"
import { render, screen, fireEvent } from "@testing-library/react"
import { DataTable } from "@/components/data-table/data-table"
import { createDomainColumns } from "@/features/domains/domain-columns"
import { DataTableStatus } from "@/components/data-table/data-table-status"
import { DataTableEntity } from "@/components/data-table/data-table-entity"
import type { DomainItem } from "@/lib/data-table/api-client"

const mockDomains: DomainItem[] = [
  {
    domain: "google.com",
    total_queries: 18421,
    unique_clients: 312,
    benign_queries: 18421,
    malicious_queries: 0,
    review_needed_queries: 0,
    unknown_queries: 0,
    latest_verdict: "Benign",
    first_seen: "2026-09-01T12:00:00.000Z",
    last_seen: "2026-09-24T17:42:31.000Z",
  },
  {
    domain: "malicious-c2.net",
    total_queries: 42,
    unique_clients: 3,
    benign_queries: 0,
    malicious_queries: 42,
    review_needed_queries: 0,
    unknown_queries: 0,
    latest_verdict: "Malicious",
    first_seen: "2026-09-20T10:00:00.000Z",
    last_seen: "2026-09-24T16:00:00.000Z",
  },
  {
    domain: "suspicious-dga.org",
    total_queries: 156,
    unique_clients: 8,
    benign_queries: 20,
    malicious_queries: 0,
    review_needed_queries: 136,
    unknown_queries: 0,
    latest_verdict: "Review Needed",
    first_seen: "2026-09-22T08:00:00.000Z",
    last_seen: "2026-09-24T15:30:00.000Z",
  },
]

describe("DataTable Component System", () => {
  it("renders table with columns and data", () => {
    const columns = createDomainColumns()
    render(
      <DataTable
        tableId="test-domains"
        data={mockDomains}
        columns={columns}
      />
    )

    // Verify headers
    expect(screen.getByText("Domain")).toBeInTheDocument()
    expect(screen.getByText("Verdict")).toBeInTheDocument()
    expect(screen.getByText("Queries")).toBeInTheDocument()
    expect(screen.getByText("Clients")).toBeInTheDocument()
    expect(screen.getByText("First Seen")).toBeInTheDocument()
    expect(screen.getByText("Last Seen")).toBeInTheDocument()

    // Verify rows rendered
    expect(screen.getByText("google.com")).toBeInTheDocument()
    expect(screen.getByText("malicious-c2.net")).toBeInTheDocument()
    expect(screen.getByText("suspicious-dga.org")).toBeInTheDocument()

    // Verify formatted metrics
    expect(screen.getByText("18,421")).toBeInTheDocument()
    expect(screen.getByText("312")).toBeInTheDocument()

    // Verify strict timestamp format YYYY-MM-DD HH:mm:ss
    expect(screen.getByText("2026-09-24 17:42:31")).toBeInTheDocument()
  })

  it("handles sorting interaction with 3-way cycle", () => {
    const columns = createDomainColumns()
    const onSortingChange = vi.fn()
    render(
      <DataTable
        tableId="test-sorting"
        data={mockDomains}
        columns={columns}
        onSortingChange={onSortingChange}
      />
    )

    const domainHeader = screen.getByText("Domain")
    expect(domainHeader).toBeInTheDocument()

    // 1st click -> asc
    fireEvent.click(domainHeader)
    expect(onSortingChange).toHaveBeenCalled()
  })

  it("renders loading skeleton state without breaking headers", () => {
    const columns = createDomainColumns()
    render(
      <DataTable
        tableId="test-loading"
        data={[]}
        columns={columns}
        loading={true}
      />
    )

    // Table header should remain visible during loading
    expect(screen.getByText("Domain")).toBeInTheDocument()
    expect(screen.getByText("Verdict")).toBeInTheDocument()
  })

  it("renders empty state and distinguishes filtered empty state", () => {
    const columns = createDomainColumns()
    const { rerender } = render(
      <DataTable
        tableId="test-empty"
        data={[]}
        columns={columns}
        loading={false}
      />
    )

    expect(screen.getByText("No records found")).toBeInTheDocument()

    // Filtered empty state with clear filters
    const onClear = vi.fn()
    rerender(
      <DataTable
        tableId="test-empty"
        data={[]}
        columns={columns}
        loading={false}
        searchQuery="nonexistent-xyz"
        onClearFilters={onClear}
      />
    )

    expect(screen.getByText("No matching records found")).toBeInTheDocument()
    const clearBtn = screen.getByText("Clear Filters")
    expect(clearBtn).toBeInTheDocument()
    fireEvent.click(clearBtn)
    expect(onClear).toHaveBeenCalled()
  })

  it("renders error state with retry action", () => {
    const columns = createDomainColumns()
    const onRetry = vi.fn()
    render(
      <DataTable
        tableId="test-error"
        data={[]}
        columns={columns}
        error="Network timeout to FastAPI"
        onRetry={onRetry}
      />
    )

    expect(screen.getByText("Unable to load data")).toBeInTheDocument()
    expect(screen.getByText("Network timeout to FastAPI")).toBeInTheDocument()
    const retryBtn = screen.getByText("Retry")
    expect(retryBtn).toBeInTheDocument()
    fireEvent.click(retryBtn)
    expect(onRetry).toHaveBeenCalled()
  })

  it("triggers entity click without making the entire row globally clickable", () => {
    const onEntityClick = vi.fn()
    const columns = createDomainColumns({ onEntityClick })
    render(
      <DataTable
        tableId="test-click"
        data={mockDomains}
        columns={columns}
      />
    )

    const googleEntity = screen.getByText("google.com")
    fireEvent.click(googleEntity)

    expect(onEntityClick).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "domain",
        id: "google.com",
      })
    )
  })

  it("supports keyboard interaction on clickable entity", () => {
    const onClick = vi.fn()
    render(
      <DataTableEntity
        type="domain"
        id="test.com"
        label="test.com"
        onClick={onClick}
      />
    )

    const btn = screen.getByRole("button")
    fireEvent.keyDown(btn, { key: "Enter" })
    expect(onClick).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "domain",
        id: "test.com",
      })
    )
  })
})

describe("DataTableStatus semantic states", () => {
  it("renders clean/benign status correctly", () => {
    render(<DataTableStatus status="Benign" />)
    expect(screen.getByText("Clean")).toBeInTheDocument()
  })

  it("renders malicious status correctly", () => {
    render(<DataTableStatus status="Malicious" />)
    expect(screen.getByText("Malicious")).toBeInTheDocument()
  })

  it("renders review needed status correctly", () => {
    render(<DataTableStatus status="Review Needed" />)
    expect(screen.getByText("Review Needed")).toBeInTheDocument()
  })

  it("renders unknown status gracefully", () => {
    render(<DataTableStatus status={null} />)
    expect(screen.getByText("Unknown")).toBeInTheDocument()
  })
})
