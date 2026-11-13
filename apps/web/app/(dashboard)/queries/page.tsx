"use client"

import * as React from "react"
import { useSearchParams } from "next/navigation"
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
  const searchParams = useSearchParams()
  const queryIdParam = searchParams.get("id")
  const { backendParams, label } = useTimeRange()

  const {
    pagination,
    sorting,
    search,
    tab,
    verdict,
    columnFilters,
    setVerdict,
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

  // Current tab filter mapping harmonized with verdict filter
  const currentTab =
    verdict === "Review Needed"
      ? "suspicious"
      : verdict === "Malicious"
      ? "blocked"
      : tab || "all"

  const tabVerdict =
    currentTab === "suspicious"
      ? "Review Needed"
      : currentTab === "blocked"
      ? "Malicious"
      : undefined

  const effectiveVerdict = verdict || tabVerdict

  const handleCustomTabChange = React.useCallback(
    (newTab: string) => {
      onTabChange(newTab)
      if (newTab === "suspicious") {
        setVerdict("Review Needed")
      } else if (newTab === "blocked") {
        setVerdict("Malicious")
      } else {
        setVerdict(null)
      }
    },
    [onTabChange, setVerdict]
  )

  const activeSort = sorting.length > 0 ? sorting[0].id : undefined
  const activeOrder = sorting.length > 0 ? (sorting[0].desc ? "desc" : "asc") : undefined

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
          sort: activeSort,
          order: activeOrder,
          window: backendParams.window,
          start_time: backendParams.start_time,
          end_time: backendParams.end_time,
        })
        if (!cancelled) {
          const items = res.items ?? []
          setData(items)
          setTotalRows(res.total ?? 0)
          setError(null)
          setLoading(false)

          if (queryIdParam) {
            const match = items.find((q) => String(q.id) === queryIdParam)
            if (match) {
              setActiveEntity({
                type: "query",
                id: String(match.id),
                label: `${match.domain} (${match.query_type})`,
                data: match,
              })
            }
          }
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
    activeSort,
    activeOrder,
    backendParams.window,
    backendParams.start_time,
    backendParams.end_time,
    queryIdParam,
  ])

  const handleRetry = React.useCallback(() => {
    setLoading(true)
    dnsnetraApi
      .getQueries({
        page: pagination.pageIndex + 1,
        pageSize: pagination.pageSize,
        search: search || undefined,
        verdict: effectiveVerdict,
        sort: activeSort,
        order: activeOrder,
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
    activeSort,
    activeOrder,
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
        onTabChange={handleCustomTabChange}
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
