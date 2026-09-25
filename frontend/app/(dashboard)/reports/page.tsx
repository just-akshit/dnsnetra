"use client"

import * as React from "react"
import { DataTable } from "@/components/data-table"
import { createDomainColumns } from "@/features/domains/domain-columns"
import { createClientColumns } from "@/features/clients/client-columns"
import { createQueryColumns } from "@/features/queries/query-columns"
import { reportTabs } from "@/features/reports/reports-table-config"
import { DomainDetails } from "@/features/domains/domain-details"
import { ClientDetails } from "@/features/clients/client-details"
import { QueryDetails } from "@/features/queries/query-details"
import { dnsnetraApi, type DomainItem, type ClientItem, type QueryItem } from "@/lib/data-table/api-client"
import { useTableUrlState } from "@/lib/data-table/url-state"
import { TimeRangePicker, useTimeRange } from "@/components/time-range"
import type { EntityIdentifier } from "@/lib/data-table/types"
import { toast } from "sonner"

type ReportItem = DomainItem | ClientItem | QueryItem

function ReportsContent() {
  const { backendParams, label } = useTimeRange()

  const {
    pagination,
    sorting,
    search,
    tab,
    onPaginationChange,
    onSortingChange,
    onSearchChange,
    onTabChange,
    resetFilters,
  } = useTableUrlState({
    defaultPageSize: 25,
  })

  const currentTab = tab || "domains"
  const [data, setData] = React.useState<ReportItem[]>([])
  const [totalRows, setTotalRows] = React.useState(0)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)
  const [activeEntity, setActiveEntity] = React.useState<EntityIdentifier | null>(null)

  const handleRetry = React.useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      if (currentTab === "clients") {
        const res = await dnsnetraApi.getClients({
          page: pagination.pageIndex + 1,
          pageSize: pagination.pageSize,
          search: search || undefined,
          window: backendParams.window,
          start_time: backendParams.start_time,
          end_time: backendParams.end_time,
        })
        setData(res.items ?? [])
        setTotalRows(res.total ?? 0)
      } else if (currentTab === "queries") {
        const res = await dnsnetraApi.getQueries({
          page: pagination.pageIndex + 1,
          pageSize: pagination.pageSize,
          search: search || undefined,
          window: backendParams.window,
          start_time: backendParams.start_time,
          end_time: backendParams.end_time,
        })
        setData(res.items ?? [])
        setTotalRows(res.total ?? 0)
      } else if (currentTab === "malicious") {
        const res = await dnsnetraApi.getMaliciousDomains({
          page: pagination.pageIndex + 1,
          pageSize: pagination.pageSize,
          window: backendParams.window,
        })
        setData(res.items ?? [])
        setTotalRows(res.total ?? 0)
      } else {
        // Default: domains
        const res = await dnsnetraApi.getDomains({
          page: pagination.pageIndex + 1,
          pageSize: pagination.pageSize,
          search: search || undefined,
          window: backendParams.window,
          start_time: backendParams.start_time,
          end_time: backendParams.end_time,
        })
        setData(res.items ?? [])
        setTotalRows(res.total ?? 0)
      }
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : "Failed to connect to DNSNetra API."
      setError(msg)
    } finally {
      setLoading(false)
    }
  }, [
    currentTab,
    pagination.pageIndex,
    pagination.pageSize,
    search,
    backendParams.window,
    backendParams.start_time,
    backendParams.end_time,
  ])

  React.useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      try {
        if (currentTab === "clients") {
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
        } else if (currentTab === "queries") {
          const res = await dnsnetraApi.getQueries({
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
        } else if (currentTab === "malicious") {
          const res = await dnsnetraApi.getMaliciousDomains({
            page: pagination.pageIndex + 1,
            pageSize: pagination.pageSize,
            window: backendParams.window,
          })
          if (!cancelled) {
            setData(res.items ?? [])
            setTotalRows(res.total ?? 0)
            setError(null)
            setLoading(false)
          }
        } else {
          // Default: domains
          const res = await dnsnetraApi.getDomains({
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
    currentTab,
    pagination.pageIndex,
    pagination.pageSize,
    search,
    backendParams.window,
    backendParams.start_time,
    backendParams.end_time,
  ])

  const domainColumns = React.useMemo(
    () =>
      createDomainColumns({
        onEntityClick: (entity) => setActiveEntity(entity),
      }),
    []
  )

  const clientColumns = React.useMemo(
    () =>
      createClientColumns({
        onEntityClick: (entity) => setActiveEntity(entity),
      }),
    []
  )

  const queryColumns = React.useMemo(
    () =>
      createQueryColumns({
        onEntityClick: (entity) => setActiveEntity(entity),
      }),
    []
  )

  const sharedProps = {
    totalRows,
    loading,
    error,
    onRetry: handleRetry,
    manualPagination: true,
    manualSorting: true,
    manualFiltering: true,
    pagination,
    onPaginationChange,
    sorting,
    onSortingChange,
    searchQuery: search,
    onSearchChange,
    searchPlaceholder: `Filter ${currentTab}...`,
    tabs: reportTabs,
    activeTab: currentTab,
    onTabChange,
    timeRangeControl: <TimeRangePicker />,
    onClearFilters: resetFilters,
    selectedEntity: activeEntity,
    onSelectedEntityChange: setActiveEntity,
    detailRenderer: (entity: EntityIdentifier, onClose: () => void) => {
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
    },
    bulkActions: [
      {
        id: "export-report-selection",
        label: "Export Selected Records",
        onClick: (rows: unknown[]) => {
          toast.success(`Exporting ${rows.length} report records...`)
        },
      },
    ],
    onExport: async () => {
      try {
        await dnsnetraApi.downloadExportCsv({
          search: search || undefined,
          window: backendParams.window,
          start_time: backendParams.start_time,
          end_time: backendParams.end_time,
        })
        toast.success(`Downloading ${currentTab} report export...`)
      } catch {
        toast.error("Export failed.")
      }
    },
  }

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-col gap-1">
        <h2 className="text-xl font-semibold tracking-tight text-foreground">
          Analytical Reports & Audit Logs
        </h2>
        <p className="text-xs text-muted-foreground">
          Exportable telemetry collections across domains, clients, and query forensic sequences ({label}).
        </p>
      </div>

      {currentTab === "clients" ? (
        <DataTable<ClientItem>
          tableId="reports-clients"
          data={data as ClientItem[]}
          columns={clientColumns}
          {...sharedProps}
        />
      ) : currentTab === "queries" ? (
        <DataTable<QueryItem>
          tableId="reports-queries"
          data={data as QueryItem[]}
          columns={queryColumns}
          {...sharedProps}
        />
      ) : (
        <DataTable<DomainItem>
          tableId="reports-domains"
          data={data as DomainItem[]}
          columns={domainColumns}
          {...sharedProps}
        />
      )}
    </div>
  )
}

export default function ReportsPage() {
  return (
    <React.Suspense
      fallback={
        <div className="flex flex-col gap-4 p-4 lg:p-6">
          <div className="h-8 w-48 animate-pulse rounded bg-muted" />
          <div className="h-96 w-full animate-pulse rounded-md border border-border bg-card/40" />
        </div>
      }
    >
      <ReportsContent />
    </React.Suspense>
  )
}
