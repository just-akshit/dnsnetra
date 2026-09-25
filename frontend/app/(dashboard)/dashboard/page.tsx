"use client"

import * as React from "react"
import { ChartAreaInteractive } from "@/components/chart-area-interactive"
import { DataTable } from "@/components/data-table"
import { SectionCards } from "@/components/section-cards"
import { DomainDetails } from "@/features/domains/domain-details"
import { createDomainColumns } from "@/features/domains/domain-columns"
import {
  dnsnetraApi,
  type DashboardResponse,
  type DomainItem,
} from "@/lib/data-table/api-client"
import type { EntityIdentifier } from "@/lib/data-table/types"
import { Button } from "@/components/ui/button"
import {
  TimeRangeProvider,
  TimeRangePicker,
  useTimeRange,
} from "@/components/time-range"
import {
  RefreshCwIcon,
  AlertCircleIcon,
  FilterIcon,
} from "lucide-react"
import { toast } from "sonner"
import { cn } from "cn"

function DashboardContent() {
  const { backendParams, isLiveRefresh, setIsLiveRefresh, label } = useTimeRange()

  const [data, setData] = React.useState<DashboardResponse | null>(null)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)
  const [activeTab, setActiveTab] = React.useState("all")
  const [activeEntity, setActiveEntity] = React.useState<EntityIdentifier | null>(null)

  // Initial and reactive load on time-range change
  React.useEffect(() => {
    let cancelled = false

    async function fetchBundle() {
      try {
        const res = await dnsnetraApi.getDashboard(backendParams)
        if (!cancelled) {
          setData(res)
          setError(null)
          setLoading(false)
        }
      } catch (err: unknown) {
        if (!cancelled) {
          const msg = err instanceof Error ? err.message : "Failed to load dashboard data."
          setError(msg)
          setLoading(false)
        }
      }
    }

    fetchBundle()

    return () => {
      cancelled = true
    }
  }, [backendParams])

  // Live Refresh polling interval (30s)
  React.useEffect(() => {
    if (!isLiveRefresh) return
    const timer = setInterval(() => {
      dnsnetraApi
        .getDashboard(backendParams)
        .then((res) => setData(res))
        .catch(() => {})
    }, 30000)

    return () => clearInterval(timer)
  }, [isLiveRefresh, backendParams])

  const handleRetry = React.useCallback(() => {
    setLoading(true)
    setError(null)
    dnsnetraApi
      .getDashboard(backendParams)
      .then((res) => {
        setData(res)
        setError(null)
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : "Failed to load dashboard data."
        setError(msg)
      })
      .finally(() => setLoading(false))
  }, [backendParams])

  const tableData: DomainItem[] = React.useMemo(() => {
    if (!data) return []
    if (activeTab === "malicious") return data.top_malicious_domains || []
    if (activeTab === "benign") return data.top_benign_domains || []
    return data.top_domains || []
  }, [data, activeTab])

  const columns = React.useMemo(
    () =>
      createDomainColumns({
        onEntityClick: (entity) => setActiveEntity(entity),
      }),
    []
  )

  const handleExport = React.useCallback(async () => {
    try {
      await dnsnetraApi.downloadExportCsv(backendParams)
      toast.success("Streaming CSV export initiated from FastAPI backend.")
    } catch {
      toast.error("Export failed.")
    }
  }, [backendParams])

  const handleScrollToFilters = () => {
    const el = document.getElementById("dashboard-top-domains")
    if (el) {
      el.scrollIntoView({ behavior: "smooth" })
    }
  }

  return (
    <div className="flex flex-col gap-4 py-4 md:gap-6 md:py-6">
      {/* 1. Global Dashboard Toolbar Header */}
      <div className="flex flex-col gap-3 px-4 lg:px-6 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-col gap-0.5">
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-foreground">
              DNS Analytics
            </h1>
            <span className="text-xs text-muted-foreground font-mono">
              / Overview
            </span>
          </div>
          <p className="text-xs text-muted-foreground">
            DNS telemetry and threat activity across observed network traffic ({label}).
          </p>
        </div>

        {/* Global Toolbar Controls */}
        <div className="flex items-center gap-2 self-start sm:self-auto flex-wrap">
          {/* Add Filter shortcut */}
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleScrollToFilters}
            className="h-8 gap-1.5 text-xs font-medium cursor-pointer"
          >
            <FilterIcon className="h-3.5 w-3.5 text-muted-foreground" />
            <span>Add filter</span>
          </Button>

          {/* Live Refresh Button */}
          <Button
            type="button"
            variant={isLiveRefresh ? "default" : "outline"}
            size="sm"
            onClick={() => {
              if (!isLiveRefresh) {
                setIsLiveRefresh(true)
                handleRetry()
                toast.success("Live refresh enabled (polling every 30s).")
              } else {
                setIsLiveRefresh(false)
                toast.info("Live refresh paused.")
              }
            }}
            className={cn(
              "h-8 gap-1.5 text-xs font-medium cursor-pointer transition-colors",
              isLiveRefresh && "bg-emerald-600 hover:bg-emerald-700 text-white"
            )}
          >
            <RefreshCwIcon
              className={cn("h-3.5 w-3.5", isLiveRefresh && "animate-spin")}
            />
            <span>{isLiveRefresh ? "Live refresh ON" : "Live refresh"}</span>
          </Button>

          {/* Global Time Range Engine Control */}
          <TimeRangePicker />
        </div>
      </div>

      {/* 2. Metric Overview Cards */}
      <SectionCards kpis={data?.summary} />

      {/* 3. Interactive DNS Telemetry Timeseries Chart */}
      <div className="px-4 lg:px-6">
        <ChartAreaInteractive
          timeseries={data?.timeseries}
          loading={loading}
        />
      </div>

      {/* 4. Operational Domain Telemetry Table */}
      <div id="dashboard-top-domains" className="px-4 lg:px-6">
        {error ? (
          <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-destructive/20 bg-destructive/5 p-8 text-center text-sm">
            <AlertCircleIcon className="h-6 w-6 text-destructive" />
            <div className="font-semibold text-destructive">
              Failed to load dashboard telemetry
            </div>
            <p className="text-muted-foreground">{error}</p>
            <Button
              variant="outline"
              size="sm"
              onClick={handleRetry}
              className="gap-2"
            >
              <RefreshCwIcon className="h-3.5 w-3.5" />
              Retry Request
            </Button>
          </div>
        ) : (
          <DataTable<DomainItem>
            tableId="dashboard-top-domains"
            data={tableData}
            columns={columns}
            loading={loading}
            showSearch={true}
            searchPlaceholder="Filter domains..."
            tabs={[
              {
                id: "all",
                label: "Top Queried",
                count: data?.top_domains?.length,
              },
              {
                id: "malicious",
                label: "Malicious Matches",
                count: data?.top_malicious_domains?.length,
              },
              {
                id: "benign",
                label: "Benign Traffic",
                count: data?.top_benign_domains?.length,
              },
            ]}
            activeTab={activeTab}
            onTabChange={setActiveTab}
            onExport={handleExport}
            selectedEntity={activeEntity}
            onSelectedEntityChange={setActiveEntity}
            detailRenderer={(entity, onClose) => (
              <DomainDetails domain={entity.id} onClose={onClose} />
            )}
            meta={{
              onEntityClick: (entity: EntityIdentifier) =>
                setActiveEntity(entity),
            }}
          />
        )}
      </div>
    </div>
  )
}

export default function DashboardPage() {
  return (
    <React.Suspense
      fallback={
        <div className="flex h-48 w-full items-center justify-center text-xs text-muted-foreground">
          Loading dashboard...
        </div>
      }
    >
      <DashboardContent />
    </React.Suspense>
  )
}
