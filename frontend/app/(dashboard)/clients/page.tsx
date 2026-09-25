"use client"

import * as React from "react"
import { DataTable } from "@/components/data-table"
import { createClientColumns } from "@/features/clients/client-columns"
import { clientDefaultSort } from "@/features/clients/client-table-config"
import { ClientDetails } from "@/features/clients/client-details"
import { dnsnetraApi, type ClientItem } from "@/lib/data-table/api-client"
import { useTableUrlState } from "@/lib/data-table/url-state"
import { TimeRangePicker, useTimeRange } from "@/components/time-range"
import type { EntityIdentifier } from "@/lib/data-table/types"
import { toast } from "sonner"

function ClientsContent() {
  const { backendParams, label } = useTimeRange()

  const {
    pagination,
    sorting,
    search,
    columnFilters,
    onPaginationChange,
    onSortingChange,
    onSearchChange,
    onColumnFiltersChange,
    resetFilters,
  } = useTableUrlState({
    defaultPageSize: 25,
    defaultSort: clientDefaultSort,
  })

  const [data, setData] = React.useState<ClientItem[]>([])
  const [totalRows, setTotalRows] = React.useState(0)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)
  const [activeEntity, setActiveEntity] = React.useState<EntityIdentifier | null>(null)

  // Fetch clients from backend API whenever pagination, search, or time range changes
  React.useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      try {
        const res = await dnsnetraApi.getClients({
          page: pagination.pageIndex + 1,
          pageSize: pagination.pageSize,
          search: search || undefined,
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
    backendParams.window,
    backendParams.start_time,
    backendParams.end_time,
  ])

  const handleRetry = React.useCallback(() => {
    setLoading(true)
    dnsnetraApi
      .getClients({
        page: pagination.pageIndex + 1,
        pageSize: pagination.pageSize,
        search: search || undefined,
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
    backendParams.window,
    backendParams.start_time,
    backendParams.end_time,
  ])

  const columns = React.useMemo(
    () =>
      createClientColumns({
        onEntityClick: (entity) => setActiveEntity(entity),
      }),
    []
  )

  const handleExport = React.useCallback(async () => {
    try {
      await dnsnetraApi.downloadExportCsv({
        client_ip: search || undefined,
        window: backendParams.window,
        start_time: backendParams.start_time,
        end_time: backendParams.end_time,
      })
      toast.success("Downloading clients query export...")
    } catch {
      toast.error("Export failed.")
    }
  }, [search, backendParams])

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-col gap-1">
        <h2 className="text-xl font-semibold tracking-tight text-foreground">
          Client Endpoints
        </h2>
        <p className="text-xs text-muted-foreground">
          Resolver client endpoints ranked by query volume and monitored for malicious activity ({label}).
        </p>
      </div>

      <DataTable
        tableId="clients"
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
        searchPlaceholder="Search client IP (e.g. 192.168.1.1)..."
        columnFilters={columnFilters}
        onColumnFiltersChange={onColumnFiltersChange}
        timeRangeControl={<TimeRangePicker />}
        onClearFilters={resetFilters}
        selectedEntity={activeEntity}
        onSelectedEntityChange={setActiveEntity}
        detailRenderer={(entity, onClose) => (
          <ClientDetails clientIp={entity.id} onClose={onClose} />
        )}
        bulkActions={[
          {
            id: "export-selected-clients",
            label: "Export Selected",
            onClick: (rows) => {
              toast.success(`Exporting ${rows.length} client endpoints...`)
            },
          },
        ]}
        onExport={handleExport}
      />
    </div>
  )
}

export default function ClientsPage() {
  return (
    <React.Suspense
      fallback={
        <div className="flex flex-col gap-4 p-4 lg:p-6">
          <div className="h-8 w-48 animate-pulse rounded bg-muted" />
          <div className="h-96 w-full animate-pulse rounded-md border border-border bg-card/40" />
        </div>
      }
    >
      <ClientsContent />
    </React.Suspense>
  )
}
