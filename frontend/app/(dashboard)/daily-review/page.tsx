"use client"

import * as React from "react"
import { DataTable } from "@/components/data-table"
import { createDailyReviewColumns } from "@/features/daily-review/daily-review-columns"
import { dailyReviewTabs, dailyReviewFilters } from "@/features/daily-review/daily-review-table-config"
import { DomainDetails } from "@/features/domains/domain-details"
import { dnsnetraApi, type DailyReviewItem } from "@/lib/data-table/api-client"
import { useTableUrlState } from "@/lib/data-table/url-state"
import type { EntityIdentifier } from "@/lib/data-table/types"
import { toast } from "sonner"

function DailyReviewContent() {
  const {
    pagination,
    sorting,
    search,
    tab,
    status,
    columnFilters,
    onPaginationChange,
    onSortingChange,
    onSearchChange,
    onTabChange,
    onColumnFiltersChange,
    resetFilters,
  } = useTableUrlState({
    defaultPageSize: 25,
  })

  const [data, setData] = React.useState<DailyReviewItem[]>([])
  const [totalRows, setTotalRows] = React.useState(0)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)
  const [activeEntity, setActiveEntity] = React.useState<EntityIdentifier | null>(null)

  const currentTab = tab || "all"
  const tabStatus = currentTab !== "all" ? currentTab : undefined
  const effectiveStatus = status || tabStatus || "review_needed"

  // Fetch daily review items from backend API whenever pagination, search, or status changes
  React.useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      try {
        const res = await dnsnetraApi.getDailyReview({
          page: pagination.pageIndex + 1,
          pageSize: pagination.pageSize,
          status: effectiveStatus,
          search: search || undefined,
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
  }, [pagination.pageIndex, pagination.pageSize, effectiveStatus, search])

  const handleRetry = React.useCallback(() => {
    setLoading(true)
    dnsnetraApi
      .getDailyReview({
        page: pagination.pageIndex + 1,
        pageSize: pagination.pageSize,
        status: effectiveStatus,
        search: search || undefined,
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
  }, [pagination.pageIndex, pagination.pageSize, effectiveStatus, search])

  const handlePromoteClean = React.useCallback(
    async (domain: string) => {
      try {
        await dnsnetraApi.overrideVerdict(domain, "clean", "Analyst confirmed clean")
        toast.success(`Promoted ${domain} to Clean`)
        handleRetry()
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Failed to override verdict"
        toast.error(msg)
      }
    },
    [handleRetry]
  )

  const handlePromoteMalicious = React.useCallback(
    async (domain: string) => {
      try {
        await dnsnetraApi.overrideVerdict(domain, "malicious", "Analyst confirmed malicious")
        toast.error(`Flagged ${domain} as Malicious`)
        handleRetry()
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Failed to override verdict"
        toast.error(msg)
      }
    },
    [handleRetry]
  )

  const columns = React.useMemo(
    () =>
      createDailyReviewColumns({
        onEntityClick: (entity) => setActiveEntity(entity),
        onPromoteClean: handlePromoteClean,
        onPromoteMalicious: handlePromoteMalicious,
      }),
    [handlePromoteClean, handlePromoteMalicious]
  )

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-col gap-1">
        <h2 className="text-xl font-semibold tracking-tight text-foreground">
          Daily Review Queue
        </h2>
        <p className="text-xs text-muted-foreground">
          Domains flagged for scheduled re-evaluation, analyst override, and threat intelligence feedback.
        </p>
      </div>

      <DataTable
        tableId="daily-review"
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
        searchPlaceholder="Search review domains..."
        tabs={dailyReviewTabs}
        activeTab={currentTab}
        onTabChange={onTabChange}
        filters={dailyReviewFilters}
        columnFilters={columnFilters}
        onColumnFiltersChange={onColumnFiltersChange}
        onClearFilters={resetFilters}
        selectedEntity={activeEntity}
        onSelectedEntityChange={setActiveEntity}
        detailRenderer={(entity, onClose) => (
          <DomainDetails domain={entity.id} onClose={onClose} />
        )}
      />
    </div>
  )
}

export default function DailyReviewPage() {
  return (
    <React.Suspense
      fallback={
        <div className="flex flex-col gap-4 p-4 lg:p-6">
          <div className="h-8 w-48 animate-pulse rounded bg-muted" />
          <div className="h-96 w-full animate-pulse rounded-md border border-border bg-card/40" />
        </div>
      }
    >
      <DailyReviewContent />
    </React.Suspense>
  )
}
