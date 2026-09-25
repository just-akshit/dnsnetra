"use client"

import * as React from "react"
import Link from "next/link"
import { useParams, useRouter } from "next/navigation"
import {
  ArrowLeftIcon,
  ActivityIcon,
  GlobeIcon,
  ShieldCheckIcon,
  ShieldAlertIcon,
  ClockIcon,
  DatabaseIcon,
  AlertCircleIcon,
  RefreshCwIcon,
  ExternalLinkIcon,
  LaptopIcon,
} from "lucide-react"
import { dnsnetraApi, type ClientDetail } from "@/lib/data-table/api-client"
import { formatDnsnetraTimestamp, formatNumber } from "@/lib/data-table/formatters"
import { DataTableStatus } from "@/components/data-table/data-table-status"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

export default function ClientProfilePage() {
  const params = useParams()
  const router = useRouter()
  const rawIp = params?.client_ip as string | undefined
  const clientIp = rawIp ? decodeURIComponent(rawIp) : ""

  const [detail, setDetail] = React.useState<ClientDetail | null>(null)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  const loadData = React.useCallback(async () => {
    if (!clientIp) return
    setLoading(true)
    setError(null)
    try {
      // Strictly do not send temporal params to investigation endpoints
      const res = await dnsnetraApi.getClientInvestigation(clientIp)
      setDetail(res)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load client profile."
      setError(msg)
    } finally {
      setLoading(false)
    }
  }, [clientIp])

  React.useEffect(() => {
    loadData()
  }, [loadData])

  if (loading) {
    return (
      <div className="flex flex-col gap-6 p-4 lg:p-6 animate-pulse">
        <div className="flex items-center gap-3">
          <Skeleton className="h-9 w-24 rounded-md" />
          <Skeleton className="h-9 w-64 rounded-md" />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Skeleton className="h-24 rounded-md" />
          <Skeleton className="h-24 rounded-md" />
          <Skeleton className="h-24 rounded-md" />
          <Skeleton className="h-24 rounded-md" />
        </div>
        <Skeleton className="h-64 rounded-md" />
        <Skeleton className="h-64 rounded-md" />
      </div>
    )
  }

  if (error || !detail) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center gap-4 min-h-[400px]">
        <div className="flex size-12 items-center justify-center rounded-full bg-destructive/10 text-destructive">
          <AlertCircleIcon className="size-6" />
        </div>
        <div className="flex flex-col gap-1">
          <h2 className="text-lg font-semibold text-foreground">
            Client Investigation Profile Unavailable
          </h2>
          <p className="text-xs text-muted-foreground max-w-md font-mono">
            {error ?? `Client "${clientIp}" was not found in authoritative DNSNetra telemetry.`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => router.push("/clients")}>
            <ArrowLeftIcon className="mr-1.5 size-3.5" />
            Back to Clients
          </Button>
          <Button variant="default" size="sm" onClick={loadData}>
            <RefreshCwIcon className="mr-1.5 size-3.5" />
            Retry
          </Button>
        </div>
      </div>
    )
  }

  const profile = detail.profile
  const totalQueries = profile.total_queries ?? 0
  const uniqueDomains = profile.unique_domains ?? 0

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* 1. Header Navigation & Entity Title */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-border/80 pb-4">
        <div className="flex flex-col gap-1.5">
          <div className="flex items-center gap-2">
            <Link
              href="/clients"
              className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              <ArrowLeftIcon className="size-3.5" />
              <span>Clients</span>
            </Link>
            <span className="text-xs text-muted-foreground">/</span>
            <span className="text-xs font-mono text-muted-foreground">Endpoint Profile</span>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <LaptopIcon className="size-5 text-muted-foreground" />
              <h1 className="text-2xl font-bold font-mono tracking-tight text-foreground select-text">
                {detail.client_ip}
              </h1>
            </div>
            <Badge variant="outline" className="font-mono text-xs">
              Monitored Endpoint
            </Badge>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={loadData}
            className="h-8 gap-1.5 text-xs font-normal"
          >
            <RefreshCwIcon className="size-3.5" />
            <span>Refresh Profile</span>
          </Button>
        </div>
      </div>

      {/* 2. Top Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <Card className="p-3 bg-card border-border/80">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <ActivityIcon className="size-3.5" />
            <span>Total Queries</span>
          </div>
          <div className="text-xl font-mono font-semibold text-foreground">
            {formatNumber(totalQueries)}
          </div>
        </Card>

        <Card className="p-3 bg-card border-border/80">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <GlobeIcon className="size-3.5" />
            <span>Unique Domains</span>
          </div>
          <div className="text-xl font-mono font-semibold text-foreground">
            {formatNumber(uniqueDomains)}
          </div>
        </Card>

        <Card className="p-3 bg-card border-border/80">
          <div className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400 mb-1">
            <ShieldCheckIcon className="size-3.5" />
            <span>Benign</span>
          </div>
          <div className="text-xl font-mono font-semibold text-emerald-700 dark:text-emerald-400">
            {formatNumber(profile.benign_queries ?? 0)}
          </div>
        </Card>

        <Card className="p-3 bg-card border-border/80">
          <div className="flex items-center gap-1.5 text-xs text-rose-600 dark:text-rose-400 mb-1">
            <ShieldAlertIcon className="size-3.5" />
            <span>Malicious</span>
          </div>
          <div className="text-xl font-mono font-semibold text-rose-700 dark:text-rose-400">
            {formatNumber(profile.malicious_queries ?? 0)}
          </div>
        </Card>

        <Card className="p-3 bg-card border-border/80">
          <div className="flex items-center gap-1.5 text-xs text-amber-600 dark:text-amber-400 mb-1">
            <ClockIcon className="size-3.5" />
            <span>Review Needed</span>
          </div>
          <div className="text-xl font-mono font-semibold text-amber-700 dark:text-amber-400">
            {formatNumber(profile.review_needed_queries ?? 0)}
          </div>
        </Card>

        <Card className="p-3 bg-card border-border/80">
          <div className="flex items-center gap-1.5 text-xs text-slate-500 mb-1">
            <DatabaseIcon className="size-3.5" />
            <span>Unknown</span>
          </div>
          <div className="text-xl font-mono font-semibold text-foreground">
            {formatNumber(profile.unknown_queries ?? 0)}
          </div>
        </Card>
      </div>

      {/* 3. Client Overview Details */}
      <Card>
        <CardHeader className="pb-3 border-b border-border/60">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <LaptopIcon className="size-4 text-primary" />
            <span>Client Overview</span>
          </CardTitle>
          <CardDescription className="text-xs">
            Authoritative lifetime endpoint profile from monitored DNS resolvers.
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="flex flex-col gap-2.5">
            <div className="flex items-center justify-between py-1 border-b border-border/40">
              <span className="text-muted-foreground">Client IP Address</span>
              <span className="font-mono font-medium text-foreground select-text">{detail.client_ip}</span>
            </div>
            <div className="flex items-center justify-between py-1 border-b border-border/40">
              <span className="text-muted-foreground">First Seen (UTC)</span>
              <span className="font-mono text-foreground">{formatDnsnetraTimestamp(profile.first_seen)}</span>
            </div>
            <div className="flex items-center justify-between py-1 border-b border-border/40">
              <span className="text-muted-foreground">Last Seen (UTC)</span>
              <span className="font-mono text-foreground">{formatDnsnetraTimestamp(profile.last_seen)}</span>
            </div>
          </div>
          <div className="flex flex-col gap-2.5">
            <div className="flex items-center justify-between py-1 border-b border-border/40">
              <span className="text-muted-foreground">Last Queried Domain</span>
              {profile.last_domain ? (
                <Link
                  href={`/domains/${encodeURIComponent(profile.last_domain)}`}
                  className="font-mono text-primary hover:underline inline-flex items-center gap-1"
                >
                  {profile.last_domain}
                  <ExternalLinkIcon className="size-3" />
                </Link>
              ) : (
                <span className="text-muted-foreground">—</span>
              )}
            </div>
            <div className="flex items-center justify-between py-1 border-b border-border/40">
              <span className="text-muted-foreground">Last Query Type</span>
              <span className="font-mono text-foreground">{profile.last_query_type || "A"}</span>
            </div>
            <div className="flex items-center justify-between py-1 border-b border-border/40">
              <span className="text-muted-foreground">Malicious Query Ratio</span>
              <span className="font-mono font-medium text-rose-600 dark:text-rose-400">
                {totalQueries > 0
                  ? `${((profile.malicious_queries / totalQueries) * 100).toFixed(1)}%`
                  : "0%"}
              </span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 4. Top Queried Domains Table */}
      <Card>
        <CardHeader className="pb-3 border-b border-border/60">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <GlobeIcon className="size-4 text-primary" />
            <span>Top Queried Domains ({detail.top_domains.length})</span>
          </CardTitle>
          <CardDescription className="text-xs">
            Most frequently resolved domains by {detail.client_ip}.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {detail.top_domains.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs">Domain</TableHead>
                  <TableHead className="text-xs text-right">Total Queries</TableHead>
                  <TableHead className="text-xs text-right">Benign</TableHead>
                  <TableHead className="text-xs text-right">Malicious</TableHead>
                  <TableHead className="text-xs text-right">Review</TableHead>
                  <TableHead className="text-xs">First Seen</TableHead>
                  <TableHead className="text-xs">Last Seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {detail.top_domains.map((item) => (
                  <TableRow key={item.domain}>
                    <TableCell className="font-mono text-xs font-medium">
                      <Link
                        href={`/domains/${encodeURIComponent(item.domain)}`}
                        className="text-primary hover:underline inline-flex items-center gap-1"
                      >
                        {item.domain}
                        <ExternalLinkIcon className="size-3 opacity-60" />
                      </Link>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-right font-medium">
                      {formatNumber(item.visit_count)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-right text-emerald-600 dark:text-emerald-400">
                      {formatNumber(item.benign_visits)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-right text-rose-600 dark:text-rose-400">
                      {formatNumber(item.malicious_visits)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-right text-amber-600 dark:text-amber-400">
                      {formatNumber(item.review_needed_visits)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {formatDnsnetraTimestamp(item.first_seen)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {formatDnsnetraTimestamp(item.last_seen)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="p-8 text-center text-xs text-muted-foreground font-mono">
              No top domains recorded for this client.
            </div>
          )}
        </CardContent>
      </Card>

      {/* 5. Threat Activity (if any suspect destinations) */}
      {detail.threat_activity && detail.threat_activity.length > 0 && (
        <Card className="border-rose-500/20 bg-rose-500/5">
          <CardHeader className="pb-3 border-b border-rose-500/20">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-rose-700 dark:text-rose-400">
              <ShieldAlertIcon className="size-4" />
              <span>Suspect Threat Activity ({detail.threat_activity.length})</span>
            </CardTitle>
            <CardDescription className="text-xs">
              Domains flagged as Malicious or Review Needed queried by this client.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs">Flagged Domain</TableHead>
                  <TableHead className="text-xs">Category</TableHead>
                  <TableHead className="text-xs text-right">Queries</TableHead>
                  <TableHead className="text-xs">Last Observed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {detail.threat_activity.map((item) => (
                  <TableRow key={item.domain}>
                    <TableCell className="font-mono text-xs font-medium">
                      <Link
                        href={`/domains/${encodeURIComponent(item.domain)}`}
                        className="text-rose-700 dark:text-rose-400 hover:underline"
                      >
                        {item.domain}
                      </Link>
                    </TableCell>
                    <TableCell className="text-xs">
                      <Badge variant="destructive" className="font-mono text-[10px]">
                        {item.activity_category}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-right font-medium">
                      {formatNumber(item.visit_count)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {formatDnsnetraTimestamp(item.last_seen)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* 6. Recent Queries */}
      <Card>
        <CardHeader className="pb-3 border-b border-border/60">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <ActivityIcon className="size-4 text-primary" />
                <span>Recent Query History ({detail.recent_queries.length})</span>
              </CardTitle>
              <CardDescription className="text-xs">
                Last recorded DNS queries originating from {detail.client_ip}.
              </CardDescription>
            </div>
            <Link
              href={`/queries?search=${encodeURIComponent(detail.client_ip)}`}
              className="text-xs text-primary hover:underline"
            >
              View in Query Log →
            </Link>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {detail.recent_queries.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs">Timestamp (UTC)</TableHead>
                  <TableHead className="text-xs">Domain</TableHead>
                  <TableHead className="text-xs">Query Type</TableHead>
                  <TableHead className="text-xs">Response Code</TableHead>
                  <TableHead className="text-xs">Verdict</TableHead>
                  <TableHead className="text-xs">TI Source</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {detail.recent_queries.map((q) => (
                  <TableRow key={q.id}>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {formatDnsnetraTimestamp(q.timestamp)}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      <Link
                        href={`/domains/${encodeURIComponent(q.domain)}`}
                        className="text-primary hover:underline"
                      >
                        {q.domain}
                      </Link>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      <Badge variant="outline" className="px-1.5 py-0 text-[10px]">
                        {q.query_type}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {q.response_code || "NOERROR"}
                    </TableCell>
                    <TableCell className="text-xs">
                      <DataTableStatus status={q.final_label} />
                    </TableCell>
                    <TableCell className="font-mono text-[11px] text-muted-foreground">
                      {q.ti_source || "rule_engine"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="p-8 text-center text-xs text-muted-foreground font-mono">
              No recent queries found for this client.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
