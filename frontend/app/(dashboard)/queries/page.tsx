"use client"

import * as React from "react"
import { DataTable } from "@/components/data-table"
import { createQueryColumns } from "@/features/queries/query-columns"
import { queryTabs, queryFilters, queryDefaultSort } from "@/features/queries/query-table-config"
import { QueryDetails } from "@/features/queries/query-details"
import { DomainDetails } from "@/features/domains/domain-details"
import { ClientDetails } from "@/features/clients/client-details"
import { dnsnetraApi, type QueryItem } from "@/lib/data-table/api-client"
import { useTableUrlState } from "@/lib/data-table/url-state"
import { TimeRangePicker, useTimeRange } from "@/components/time-range"
import type { EntityIdentifier } from "@/lib/data-table/types"
import { toast } from "sonner"

function QueriesContent() {
  const { backendParams, label } = useTimeRange()

  const {
    pagination,
    sorting,
    search,
    tab,
    verdict,
    columnFilters,
    onPaginationChange,
    onSortingChange,
    onSearchChange,
    onTabChange,
    onColumnFiltersChange,
    resetFilters,
  } = useTableUrlState({
    defaultPageSize: 25,
    defaultSort: queryDefaultSort,
  })

  const [data, setData] = React.useState<QueryItem[]>([])
  const [totalRows, setTotalRows] = React.useState(0)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)
  const [activeEntity, setActiveEntity] = React.useState<EntityIdentifier | null>(null)

  // Current tab filter mapping composed with direct verdict filter
  const currentTab = tab || "all"
  const tabVerdict =
    currentTab === "suspicious"
      ? "Review Needed"
      : currentTab === "blocked"
      ? "Malicious"
      : undefined

  const effectiveVerdict = verdict || tabVerdict

  // Fetch queries from backend API whenever pagination, search, filters, or time range changes
  React.useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      try {
        const res = await dnsnetraApi.getQueries({
          page: pagination.pageIndex + 1,
          pageSize: pagination.pageSize,
          search: search || undefined,
          verdict: effectiveVerdict,
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
    effectiveVerdict,
    backendParams.window,
    backendParams.start_time,
    backendParams.end_time,
  ])

  const handleRetry = React.useCallback(() => {
    setLoading(true)
    dnsnetraApi
      .getQueries({
        page: pagination.pageIndex + 1,
        pageSize: pagination.pageSize,
        search: search || undefined,
        verdict: effectiveVerdict,
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
    effectiveVerdict,
    backendParams.window,
    backendParams.start_time,
    backendParams.end_time,
  ])

  const columns = React.useMemo(
    () =>
      createQueryColumns({
        onEntityClick: (entity) => setActiveEntity(entity),
      }),
    []
  )

  const handleExport = React.useCallback(async () => {
    try {
      await dnsnetraApi.downloadExportCsv({
        search: search || undefined,
        verdict: effectiveVerdict,
        window: backendParams.window,
        start_time: backendParams.start_time,
        end_time: backendParams.end_time,
      })
      toast.success("Streaming query telemetry CSV export...")
    } catch {
      toast.error("Export failed.")
    }
  }, [search, effectiveVerdict, backendParams])

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-col gap-1">
        <h2 className="text-xl font-semibold tracking-tight text-foreground">
          DNS Query Telemetry
        </h2>
        <p className="text-xs text-muted-foreground">
          Event-level telemetry log from authoritative resolver feeds with real-time classification ({label}).
        </p>
      </div>

      <DataTable
        tableId="queries"
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
        searchPlaceholder="Search domain or client IP..."
        tabs={queryTabs}
        activeTab={currentTab}
        onTabChange={onTabChange}
        filters={queryFilters}
        columnFilters={columnFilters}
        onColumnFiltersChange={onColumnFiltersChange}
        timeRangeControl={<TimeRangePicker />}
        onClearFilters={resetFilters}
        selectedEntity={activeEntity}
        onSelectedEntityChange={setActiveEntity}
        detailRenderer={(entity, onClose) => {
          if (entity.type === "domain") {
            return <DomainDetails domain={entity.id} onClose={onClose} />
          }
          if (entity.type === "client") {
            return <ClientDetails clientIp={entity.id} onClose={onClose} />
          }
          return (
            <QueryDetails
              queryId={entity.id}
              query={entity.data as QueryItem}
              onInspectEntity={(related) => setActiveEntity(related)}
              onClose={onClose}
            />
          )
        }}
        bulkActions={[
          {
            id: "export-selected-queries",
            label: "Export Selected",
            onClick: (rows) => {
              toast.success(`Exporting ${rows.length} query records...`)
            },
          },
        ]}
        onExport={handleExport}
      />
    </div>
  )
}

export default function QueriesPage() {
  return (
    <React.Suspense
      fallback={
        <div className="flex flex-col gap-4 p-4 lg:p-6">
          <div className="h-8 w-48 animate-pulse rounded bg-muted" />
          <div className="h-96 w-full animate-pulse rounded-md border border-border bg-card/40" />
        </div>
      }
    >
      <QueriesContent />
    </React.Suspense>
  )
}
