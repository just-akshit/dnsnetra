"use client"

import * as React from "react"
import { DataTable } from "@/components/data-table"
import { createDnsColumns } from "@/features/dns/dns-columns"
import { DomainDetails } from "@/features/domains/domain-details"
import { ClientDetails } from "@/features/clients/client-details"
import { dnsnetraApi, type DnsDomainItem } from "@/lib/data-table/api-client"
import { useTableUrlState } from "@/lib/data-table/url-state"
import type { EntityIdentifier } from "@/lib/data-table/types"

function DnsContent() {
  const {
    pagination,
    sorting,
    search,
    onPaginationChange,
    onSortingChange,
    onSearchChange,
    resetFilters,
  } = useTableUrlState({
    defaultPageSize: 25,
    defaultSort: { id: "last_seen", desc: true },
  })

  const [data, setData] = React.useState<DnsDomainItem[]>([])
  const [totalRows, setTotalRows] = React.useState(0)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)
  const [activeEntity, setActiveEntity] = React.useState<EntityIdentifier | null>(null)

  const activeSort = sorting.length > 0 ? sorting[0].id : undefined
  const activeOrder = sorting.length > 0 ? (sorting[0].desc ? "desc" : "asc") : undefined

  React.useEffect(() => {
    let cancelled = false

    dnsnetraApi
      .getDnsDomains({
        page: pagination.pageIndex + 1,
        pageSize: pagination.pageSize,
        search: search || undefined,
        sort: activeSort,
        order: activeOrder,
      })
      .then((res) => {
        if (cancelled) return
        setData(res.items ?? [])
        setTotalRows(res.total ?? 0)
        setError(null)
      })
      .catch((err: unknown) => {
        if (cancelled) return
        setError(err instanceof Error ? err.message : "Failed to load DNS domains.")
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [
    pagination.pageIndex,
    pagination.pageSize,
    search,
    activeSort,
    activeOrder,
  ])

  const columns = React.useMemo(
    () => createDnsColumns({ onEntityClick: (entity) => setActiveEntity(entity) }),
    []
  )

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-col gap-1">
        <h2 className="text-xl font-semibold tracking-tight text-foreground">DNS</h2>
        <p className="text-xs text-muted-foreground">
          One row per queried domain: first and last seen, latest query type, and client IP.
        </p>
      </div>

      <DataTable<DnsDomainItem>
        tableId="dns"
        data={data}
        columns={columns}
        totalRows={totalRows}
        loading={loading}
        error={error}
        manualPagination
        manualSorting
        manualFiltering
        enableRowSelection={false}
        pagination={pagination}
        onPaginationChange={onPaginationChange}
        sorting={sorting}
        onSortingChange={onSortingChange}
        searchQuery={search}
        onSearchChange={onSearchChange}
        searchPlaceholder="Search domain or query name..."
        onClearFilters={resetFilters}
        selectedEntity={activeEntity}
        onSelectedEntityChange={setActiveEntity}
        detailRenderer={(entity, onClose) => {
          if (entity.type === "domain") {
            return <DomainDetails domain={entity.id} onClose={onClose} />
          }
          return <ClientDetails clientIp={entity.id} onClose={onClose} />
        }}
      />
    </div>
  )
}

export default function DnsPage() {
  return (
    <React.Suspense
      fallback={
        <div className="flex flex-col gap-4 p-4 lg:p-6">
          <div className="h-8 w-48 animate-pulse rounded bg-muted" />
          <div className="h-96 w-full animate-pulse rounded-md border border-border bg-card/40" />
        </div>
      }
    >
      <DnsContent />
    </React.Suspense>
  )
}
