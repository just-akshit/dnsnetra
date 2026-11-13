"use client"

import * as React from "react"
import { dnsnetraApi, type SystemStatusResponse } from "@/lib/data-table/api-client"
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { formatDnsnetraTimestamp, formatNumber } from "@/lib/data-table/formatters"
import { SettingsIcon, DatabaseIcon, CpuIcon, CheckCircle2Icon, AlertCircleIcon, RefreshCwIcon, ServerIcon } from "lucide-react"

export default function SettingsPage() {
  const [statusData, setStatusData] = React.useState<SystemStatusResponse | null>(null)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  React.useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const res = await dnsnetraApi.getSystemStatus()
        if (!cancelled) {
          setStatusData(res)
          setError(null)
          setLoading(false)
        }
      } catch (err: unknown) {
        if (!cancelled) {
          const msg = err instanceof Error ? err.message : "Failed to load system status."
          setError(msg)
          setLoading(false)
        }
      }
    }

    load()

    return () => {
      cancelled = true
    }
  }, [])

  const handleRetry = React.useCallback(() => {
    setLoading(true)
    setError(null)
    dnsnetraApi
      .getSystemStatus()
      .then((res) => {
        setStatusData(res)
        setError(null)
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : "Failed to load system status."
        setError(msg)
      })
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6 max-w-5xl">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <SettingsIcon className="h-5 w-5 text-primary" />
            <h1 className="text-xl font-semibold tracking-tight text-foreground">
              System Settings & Architecture
            </h1>
          </div>
          <p className="text-sm text-muted-foreground">
            Authoritative DNSNetra backend service configuration, database connectivity, and telemetry ingestion pipeline state.
          </p>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={handleRetry}
          disabled={loading}
          className="gap-2 self-start"
        >
          <RefreshCwIcon className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh Status
        </Button>
      </div>

      {error ? (
        <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-destructive/20 bg-destructive/5 p-8 text-center text-sm">
          <AlertCircleIcon className="h-6 w-6 text-destructive" />
          <div className="font-semibold text-destructive">Backend System Unreachable</div>
          <p className="text-muted-foreground">{error}</p>
          <Button variant="outline" size="sm" onClick={handleRetry} className="gap-2">
            <RefreshCwIcon className="h-3.5 w-3.5" />
            Retry
          </Button>
        </div>
      ) : (
        <div className="flex flex-col gap-6">
          {/* Service Overview */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-3">
              <div className="space-y-1">
                <CardTitle className="text-base flex items-center gap-2">
                  <ServerIcon className="h-4 w-4 text-primary" />
                  FastAPI Application Server
                </CardTitle>
                <CardDescription>
                  Core orchestration service running on {process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}
                </CardDescription>
              </div>
              <Badge variant="outline" className="text-success border-success/30 flex items-center gap-1.5">
                <CheckCircle2Icon className="h-3.5 w-3.5 text-success" />
                {statusData?.status?.toUpperCase() ?? "HEALTHY"}
              </Badge>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
                <div className="rounded-md border p-3 bg-muted/20">
                  <div className="text-muted-foreground mb-1">Service Name</div>
                  <div className="font-semibold text-foreground">{statusData?.service ?? "dnsnetra-backend"}</div>
                </div>
                <div className="rounded-md border p-3 bg-muted/20">
                  <div className="text-muted-foreground mb-1">Architecture Version</div>
                  <div className="font-semibold text-foreground">v{statusData?.version ?? "2.0.0"}</div>
                </div>
                <div className="rounded-md border p-3 bg-muted/20">
                  <div className="text-muted-foreground mb-1">Heartbeat Timestamp</div>
                  <div className="font-semibold text-foreground">
                    {statusData?.timestamp ? formatDnsnetraTimestamp(statusData.timestamp) : "..."}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Database Health */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-3">
              <div className="space-y-1">
                <CardTitle className="text-base flex items-center gap-2">
                  <DatabaseIcon className="h-4 w-4 text-primary" />
                  PostgreSQL Data Store
                </CardTitle>
                <CardDescription>
                  Primary authoritative relational storage for DNS telemetry, domain profiles, and threat intelligence.
                </CardDescription>
              </div>
              <Badge variant="outline" className="text-success border-success/30">
                {statusData?.database?.connected ? "CONNECTED" : "DISCONNECTED"}
              </Badge>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
                <div className="rounded-md border p-3 bg-muted/20">
                  <div className="text-muted-foreground mb-1">Database Name</div>
                  <div className="font-semibold text-foreground">{statusData?.database?.database ?? "dns_threat_detection"}</div>
                </div>
                <div className="rounded-md border p-3 bg-muted/20">
                  <div className="text-muted-foreground mb-1">Ping Latency</div>
                  <div className="font-semibold text-foreground">{statusData?.database?.latency_ms ?? 0} ms</div>
                </div>
                <div className="rounded-md border p-3 bg-muted/20">
                  <div className="text-muted-foreground mb-1">Connection State</div>
                  <div className="font-semibold text-success">Active Pool</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Aggregation Engine Pipeline */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-3">
              <div className="space-y-1">
                <CardTitle className="text-base flex items-center gap-2">
                  <CpuIcon className="h-4 w-4 text-primary" />
                  Telemetry Rollup & Aggregation Pipeline
                </CardTitle>
                <CardDescription>
                  Continuous event ingestion watermark and automated hourly rollups.
                </CardDescription>
              </div>
              <Badge variant="outline">
                {statusData?.aggregation?.status?.toUpperCase() ?? "IDLE"}
              </Badge>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
                <div className="rounded-md border p-3 bg-muted/20">
                  <div className="text-muted-foreground mb-1">Job Identifier</div>
                  <div className="font-semibold text-foreground truncate">{statusData?.aggregation?.job_name ?? "dnsnetra_aggregator"}</div>
                </div>
                <div className="rounded-md border p-3 bg-muted/20">
                  <div className="text-muted-foreground mb-1">Watermark ID</div>
                  <div className="font-semibold text-foreground">{formatNumber(statusData?.aggregation?.watermark_id ?? 0)}</div>
                </div>
                <div className="rounded-md border p-3 bg-muted/20">
                  <div className="text-muted-foreground mb-1">Events Processed</div>
                  <div className="font-semibold text-foreground">{formatNumber(statusData?.aggregation?.total_events_processed ?? 0)}</div>
                </div>
                <div className="rounded-md border p-3 bg-muted/20">
                  <div className="text-muted-foreground mb-1">Pending Ingestion Queue</div>
                  <div className="font-semibold text-foreground">{statusData?.aggregation?.pending_events ?? 0}</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}
