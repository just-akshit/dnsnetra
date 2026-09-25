"use client"

import * as React from "react"
import { dnsnetraApi, type DomainAnalyticsResponse } from "@/lib/data-table/api-client"
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { formatDnsnetraTimestamp, formatNumber } from "@/lib/data-table/formatters"
import { BarChart3Icon, ActivityIcon, ShieldAlertIcon, RefreshCwIcon, AlertCircleIcon, LayersIcon, UsersIcon } from "lucide-react"

export default function AnalyticsPage() {
  const [windowPreset, setWindowPreset] = React.useState("30d")
  const [data, setData] = React.useState<DomainAnalyticsResponse | null>(null)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  React.useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const res = await dnsnetraApi.getDomainAnalytics({ window: windowPreset })
        if (!cancelled) {
          setData(res)
          setError(null)
          setLoading(false)
        }
      } catch (err: unknown) {
        if (!cancelled) {
          const msg = err instanceof Error ? err.message : "Failed to load telemetry analytics."
          setError(msg)
          setLoading(false)
        }
      }
    }

    load()

    return () => {
      cancelled = true
    }
  }, [windowPreset])

  const handleRetry = React.useCallback(() => {
    setLoading(true)
    setError(null)
    dnsnetraApi
      .getDomainAnalytics({ window: windowPreset })
      .then((res) => {
        setData(res)
        setError(null)
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : "Failed to load telemetry analytics."
        setError(msg)
      })
      .finally(() => setLoading(false))
  }, [windowPreset])

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* Page Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <BarChart3Icon className="h-5 w-5 text-primary" />
            <h1 className="text-xl font-semibold tracking-tight text-foreground">
              Telemetry Analytics
            </h1>
          </div>
          <p className="text-sm text-muted-foreground">
            Deeper statistical analysis, query verdict timelines, and domain entropy trends.
          </p>
        </div>

        {/* Time Window Selector */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Analysis Window:</span>
          <Select value={windowPreset} onValueChange={(val) => { if (val) setWindowPreset(val) }}>
            <SelectTrigger className="w-32 h-8 text-xs font-mono">
              <SelectValue placeholder="Window" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="1h">Last 1 Hour</SelectItem>
              <SelectItem value="24h">Last 24 Hours</SelectItem>
              <SelectItem value="7d">Last 7 Days</SelectItem>
              <SelectItem value="30d">Last 30 Days</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {error ? (
        <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-destructive/20 bg-destructive/5 p-8 text-center text-sm">
          <AlertCircleIcon className="h-6 w-6 text-destructive" />
          <div className="font-semibold text-destructive">Failed to fetch analytics metrics</div>
          <p className="text-muted-foreground">{error}</p>
          <Button variant="outline" size="sm" onClick={handleRetry} className="gap-2">
            <RefreshCwIcon className="h-3.5 w-3.5" />
            Retry Request
          </Button>
        </div>
      ) : (
        <>
          {/* Key Metrics Grid */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
            <Card>
              <CardHeader className="pb-2">
                <CardDescription className="text-xs">Total Queries</CardDescription>
                <CardTitle className="text-2xl font-bold font-mono">
                  {loading ? "..." : formatNumber(data?.metrics.total_queries ?? 0)}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
                  <ActivityIcon className="h-3 w-3 text-primary" />
                  <span>Telemetry volume</span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardDescription className="text-xs">Unique Domains</CardDescription>
                <CardTitle className="text-2xl font-bold font-mono">
                  {loading ? "..." : formatNumber(data?.metrics.unique_domains ?? 0)}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
                  <LayersIcon className="h-3 w-3 text-muted-foreground" />
                  <span>Observed FQDNs</span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardDescription className="text-xs">Unique Clients</CardDescription>
                <CardTitle className="text-2xl font-bold font-mono">
                  {loading ? "..." : formatNumber(data?.metrics.unique_clients ?? 0)}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
                  <UsersIcon className="h-3 w-3 text-muted-foreground" />
                  <span>Active Endpoints</span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardDescription className="text-xs">Malicious</CardDescription>
                <CardTitle className="text-2xl font-bold font-mono text-destructive">
                  {loading ? "..." : formatNumber(data?.metrics.malicious_domains ?? 0)}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-1 text-[11px] text-destructive">
                  <ShieldAlertIcon className="h-3 w-3" />
                  <span>High-risk indicators</span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardDescription className="text-xs">Review Needed</CardDescription>
                <CardTitle className="text-2xl font-bold font-mono text-warning">
                  {loading ? "..." : formatNumber(data?.metrics.review_needed_domains ?? 0)}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-1 text-[11px] text-warning">
                  <AlertCircleIcon className="h-3 w-3" />
                  <span>Analyst review queue</span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardDescription className="text-xs">Benign Queries</CardDescription>
                <CardTitle className="text-2xl font-bold font-mono text-success">
                  {loading ? "..." : formatNumber(data?.metrics.benign_queries ?? 0)}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
                  <span>Verified benign volume</span>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Timeline Table */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Temporal Query Distribution</CardTitle>
              <CardDescription>
                Telemetry event rollups grouped by bucket for window: {data?.window.start ? formatDnsnetraTimestamp(data.window.start) : ""} to {data?.window.end ? formatDnsnetraTimestamp(data.window.end) : ""}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border overflow-x-auto">
                <table className="w-full text-xs font-mono">
                  <thead>
                    <tr className="border-b bg-muted/40 text-muted-foreground text-left">
                      <th className="p-2.5 font-medium">Bucket Timestamp</th>
                      <th className="p-2.5 font-medium text-right">Total Queries</th>
                      <th className="p-2.5 font-medium text-right text-success">Benign</th>
                      <th className="p-2.5 font-medium text-right text-destructive">Malicious</th>
                      <th className="p-2.5 font-medium text-right text-warning">Review Needed</th>
                      <th className="p-2.5 font-medium text-right text-muted-foreground">Unknown</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {loading ? (
                      <tr>
                        <td colSpan={6} className="p-4 text-center text-muted-foreground">
                          Loading temporal analytics...
                        </td>
                      </tr>
                    ) : !data?.timeline?.length ? (
                      <tr>
                        <td colSpan={6} className="p-4 text-center text-muted-foreground">
                          No events recorded in this time range.
                        </td>
                      </tr>
                    ) : (
                      data.timeline.slice(-15).map((bucket, idx) => (
                        <tr key={idx} className="hover:bg-muted/30 transition-colors">
                          <td className="p-2.5">{formatDnsnetraTimestamp(bucket.timestamp)}</td>
                          <td className="p-2.5 text-right font-semibold">{formatNumber(bucket.queries)}</td>
                          <td className="p-2.5 text-right text-success">{formatNumber(bucket.benign_queries)}</td>
                          <td className="p-2.5 text-right text-destructive">{formatNumber(bucket.malicious_queries)}</td>
                          <td className="p-2.5 text-right text-warning">{formatNumber(bucket.review_needed_queries)}</td>
                          <td className="p-2.5 text-right text-muted-foreground">{formatNumber(bucket.unknown_queries)}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}
