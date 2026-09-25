"use client"

import * as React from "react"
import { DataTable } from "@/components/data-table"
import { createDomainColumns } from "@/features/domains/domain-columns"
import { domainFilters, domainDefaultSort } from "@/features/domains/domain-table-config"
import { DomainDetails } from "@/features/domains/domain-details"
import { dnsnetraApi, type DomainItem } from "@/lib/data-table/api-client"
import { useTableUrlState } from "@/lib/data-table/url-state"
import { TimeRangePicker, useTimeRange } from "@/components/time-range"
import type { EntityIdentifier } from "@/lib/data-table/types"
import { toast } from "sonner"

function DomainsContent() {
  const { backendParams, label } = useTimeRange()

  const {
    pagination,
    sorting,
    search,
    verdict,
    columnFilters,
    onPaginationChange,
    onSortingChange,
    onSearchChange,
    onColumnFiltersChange,
    resetFilters,
  } = useTableUrlState({
    defaultPageSize: 25,
    defaultSort: domainDefaultSort,
  })

  const [data, setData] = React.useState<DomainItem[]>([])
  const [totalRows, setTotalRows] = React.useState(0)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)
  const [activeEntity, setActiveEntity] = React.useState<EntityIdentifier | null>(null)

  // Fetch domains from backend API with composed filters: search, verdict, and time range
  React.useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      try {
        const res = await dnsnetraApi.getDomains({
          page: pagination.pageIndex + 1,
          pageSize: pagination.pageSize,
          search: search || undefined,
          verdict: verdict || undefined,
          window: backendParams.window,
          start_time: backendParams.start_time,
          end_time: backendParams.end_time,
        })
        if (!cancelled) {
          setData(res.items ?? [])
          setTotalRows(res.total ?? 0)
          setError(null)
          setLoading(false)
        }
      } catch (err: unknown) {
        if (!cancelled) {
          const msg =
            err instanceof Error ? err.message : "Failed to connect to DNSNetra API."
          setError(msg)
          setLoading(false)
        }
      }
    }

    load()

    return () => {
      cancelled = true
    }
  }, [
    pagination.pageIndex,
    pagination.pageSize,
    search,
    verdict,
    backendParams.window,
    backendParams.start_time,
    backendParams.end_time,
  ])

  const handleRetry = React.useCallback(() => {
    setLoading(true)
    dnsnetraApi
      .getDomains({
        page: pagination.pageIndex + 1,
        pageSize: pagination.pageSize,
        search: search || undefined,
        verdict: verdict || undefined,
        window: backendParams.window,
        start_time: backendParams.start_time,
        end_time: backendParams.end_time,
      })
      .then((res) => {
        setData(res.items ?? [])
        setTotalRows(res.total ?? 0)
        setError(null)
      })
      .catch((err: unknown) => {
        const msg =
          err instanceof Error ? err.message : "Failed to connect to DNSNetra API."
        setError(msg)
      })
      .finally(() => setLoading(false))
  }, [
    pagination.pageIndex,
    pagination.pageSize,
    search,
    verdict,
    backendParams.window,
    backendParams.start_time,
    backendParams.end_time,
  ])

  const columns = React.useMemo(
    () =>
      createDomainColumns({
        onEntityClick: (entity) => setActiveEntity(entity),
      }),
    []
  )

  const handleExport = React.useCallback(async () => {
    try {
      await dnsnetraApi.downloadExportCsv({
        search: search || undefined,
        verdict: verdict || undefined,
        window: backendParams.window,
        start_time: backendParams.start_time,
        end_time: backendParams.end_time,
      })
      toast.success("Streaming filtered queries export for observed domains...")
    } catch {
      toast.error("Export failed.")
    }
  }, [search, verdict, backendParams])

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-col gap-1">
        <h2 className="text-xl font-semibold tracking-tight text-foreground">
          Observed Domains
        </h2>
        <p className="text-xs text-muted-foreground">
          Authoritative catalog of all queried domains across monitored DNS resolvers with forensic verdict triage ({label}).
        </p>
      </div>

      <DataTable
        tableId="domains"
        data={data}
        columns={columns}
        totalRows={totalRows}
        loading={loading}
        error={error}
        onRetry={handleRetry}
        manualPagination={true}
        manualSorting={true}
        manualFiltering={true}
        pagination={pagination}
        onPaginationChange={onPaginationChange}
        sorting={sorting}
        onSortingChange={onSortingChange}
        searchQuery={search}
        onSearchChange={onSearchChange}
        searchPlaceholder="Search domains (e.g. google.com)..."
        filters={domainFilters}
        columnFilters={columnFilters}
        onColumnFiltersChange={onColumnFiltersChange}
        timeRangeControl={<TimeRangePicker />}
        onClearFilters={resetFilters}
        selectedEntity={activeEntity}
        onSelectedEntityChange={setActiveEntity}
        detailRenderer={(entity, onClose) => (
          <DomainDetails domain={entity.id} onClose={onClose} />
        )}
        bulkActions={[
          {
            id: "export-selected",
            label: "Export Selected",
            onClick: (rows) => {
              toast.success(`Exporting ${rows.length} domains...`)
            },
          },
        ]}
        onExport={handleExport}
      />
    </div>
  )
}

export default function DomainsPage() {
  return (
    <React.Suspense
      fallback={
        <div className="flex flex-col gap-4 p-4 lg:p-6">
          <div className="h-8 w-48 animate-pulse rounded bg-muted" />
          <div className="h-96 w-full animate-pulse rounded-md border border-border bg-card/40" />
        </div>
      }
    >
      <DomainsContent />
    </React.Suspense>
  )
}
