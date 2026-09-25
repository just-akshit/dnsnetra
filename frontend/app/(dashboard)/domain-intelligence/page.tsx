"use client"

import * as React from "react"
import { DataTable } from "@/components/data-table"
import { createDomainColumns } from "@/features/domains/domain-columns"
import { DomainDetails } from "@/features/domains/domain-details"
import { dnsnetraApi, type DomainItem } from "@/lib/data-table/api-client"
import { useTableUrlState } from "@/lib/data-table/url-state"
import type { EntityIdentifier } from "@/lib/data-table/types"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { SearchIcon, ShieldAlertIcon, RefreshCwIcon, AlertCircleIcon } from "lucide-react"
import { toast } from "sonner"

function DomainIntelligenceContent() {
  const {
    pagination,
    search,
    onPaginationChange,
    onSearchChange,
  } = useTableUrlState({
    defaultPageSize: 25,
  })

  const [data, setData] = React.useState<DomainItem[]>([])
  const [totalRows, setTotalRows] = React.useState(0)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)
  const [activeEntity, setActiveEntity] = React.useState<EntityIdentifier | null>(null)
  const [directSearchTerm, setDirectSearchTerm] = React.useState("")

  React.useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const res = await dnsnetraApi.getMaliciousDomains({
          page: pagination.pageIndex + 1,
          pageSize: pagination.pageSize,
        })
        if (!cancelled) {
          setData(res.items ?? [])
          setTotalRows(res.total ?? 0)
          setError(null)
          setLoading(false)
        }
      } catch (err: unknown) {
        if (!cancelled) {
          const msg = err instanceof Error ? err.message : "Failed to load threat intelligence domains."
          setError(msg)
          setLoading(false)
        }
      }
    }

    load()

    return () => {
      cancelled = true
    }
  }, [pagination.pageIndex, pagination.pageSize])

  const handleRetry = React.useCallback(() => {
    setLoading(true)
    setError(null)
    dnsnetraApi
      .getMaliciousDomains({
        page: pagination.pageIndex + 1,
        pageSize: pagination.pageSize,
      })
      .then((res) => {
        setData(res.items ?? [])
        setTotalRows(res.total ?? 0)
        setError(null)
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : "Failed to load threat intelligence domains."
        setError(msg)
      })
      .finally(() => setLoading(false))
  }, [pagination.pageIndex, pagination.pageSize])

  const handleDirectInvestigate = (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = directSearchTerm.trim().toLowerCase()
    if (!trimmed) return
    setActiveEntity({ type: "domain", id: trimmed })
  }

  const handleExport = React.useCallback(async () => {
    try {
      await dnsnetraApi.downloadExportCsv({
        verdict: "malicious",
      })
      toast.success("Streaming threat intelligence CSV export initiated.")
    } catch {
      toast.error("Export failed.")
    }
  }, [])

  const columns = React.useMemo(
    () =>
      createDomainColumns({
        onEntityClick: (entity) => setActiveEntity(entity),
      }),
    []
  )

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* Header and Lookup Banner */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <ShieldAlertIcon className="h-5 w-5 text-destructive" />
            <h1 className="text-xl font-semibold tracking-tight text-foreground">
              Domain Threat Intelligence
            </h1>
          </div>
          <p className="text-sm text-muted-foreground">
            Authoritative reputation feed indicators, high-risk matches, and forensic domain profiles.
          </p>
        </div>

        {/* Direct Domain Lookup */}
        <form onSubmit={handleDirectInvestigate} className="flex items-center gap-2">
          <div className="relative w-64 sm:w-80">
            <SearchIcon className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              type="text"
              placeholder="Investigate domain..."
              className="pl-9 font-mono text-xs"
              value={directSearchTerm}
              onChange={(e) => setDirectSearchTerm(e.target.value)}
            />
          </div>
          <Button type="submit" size="sm" variant="secondary">
            Investigate
          </Button>
        </form>
      </div>

      {/* Main Threat Intel Table */}
      {error ? (
        <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-destructive/20 bg-destructive/5 p-8 text-center text-sm">
          <AlertCircleIcon className="h-6 w-6 text-destructive" />
          <div className="font-semibold text-destructive">Failed to load threat intelligence records</div>
          <p className="text-muted-foreground">{error}</p>
          <Button variant="outline" size="sm" onClick={handleRetry} className="gap-2">
            <RefreshCwIcon className="h-3.5 w-3.5" />
            Retry Request
          </Button>
        </div>
      ) : (
        <DataTable<DomainItem>
          tableId="domain-intelligence-table"
          data={data}
          columns={columns}
          loading={loading}
          totalRows={totalRows}
          pagination={pagination}
          onPaginationChange={onPaginationChange}
          searchPlaceholder="Search active threat indicators..."
          showSearch={true}
          searchQuery={search}
          onSearchChange={onSearchChange}
          onExport={handleExport}
          tabs={[
            { id: "reputation", label: "Confirmed Threat Matches", count: totalRows },
          ]}
          selectedEntity={activeEntity}
          onSelectedEntityChange={setActiveEntity}
          detailRenderer={(entity, onClose) => (
            <DomainDetails domain={entity.id} onClose={onClose} />
          )}
          meta={{
            onEntityClick: (entity: EntityIdentifier) => setActiveEntity(entity),
          }}
        />
      )}
    </div>
  )
}

export default function DomainIntelligencePage() {
  return (
    <React.Suspense
      fallback={
        <div className="flex flex-col gap-4 p-4 lg:p-6">
          <div className="h-8 w-48 animate-pulse rounded bg-muted" />
          <div className="h-96 w-full animate-pulse rounded-md border border-border bg-card/40" />
        </div>
      }
    >
      <DomainIntelligenceContent />
    </React.Suspense>
  )
}
