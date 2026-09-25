"use client"

import * as React from "react"
import Link from "next/link"
import { useParams, useRouter } from "next/navigation"
import {
  ArrowLeftIcon,
  ShieldCheckIcon,
  ShieldAlertIcon,
  ClockIcon,
  ActivityIcon,
  UsersIcon,
  AlertCircleIcon,
  RefreshCwIcon,
  ExternalLinkIcon,
  DatabaseIcon,
  GlobeIcon,
  ServerIcon,
  NetworkIcon,
  FileTextIcon,
} from "lucide-react"
import { dnsnetraApi, type DomainDetail } from "@/lib/data-table/api-client"
import { formatDnsnetraTimestamp, formatNumber } from "@/lib/data-table/formatters"
import { DataTableStatus } from "@/components/data-table/data-table-status"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

export default function DomainProfilePage() {
  const params = useParams()
  const router = useRouter()
  const rawDomain = params?.domain as string | undefined
  const domain = rawDomain ? decodeURIComponent(rawDomain) : ""

  const [detail, setDetail] = React.useState<DomainDetail | null>(null)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  const loadData = React.useCallback(async () => {
    if (!domain) return
    setLoading(true)
    setError(null)
    try {
      // Strictly do not send temporal params to investigation endpoints
      const res = await dnsnetraApi.getDomainInvestigation(domain)
      setDetail(res)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load domain profile."
      setError(msg)
    } finally {
      setLoading(false)
    }
  }, [domain])

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
            Domain Investigation Profile Unavailable
          </h2>
          <p className="text-xs text-muted-foreground max-w-md font-mono">
            {error ?? `Domain "${domain}" was not found in authoritative DNSNetra telemetry.`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => router.push("/domains")}>
            <ArrowLeftIcon className="mr-1.5 size-3.5" />
            Back to Domains
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
  const ti = detail.threat_intel
  const queryDist: Record<string, number> = profile.query_type_distribution ?? {}
  const totalQueries = profile.total_queries ?? 0
  const uniqueClients = profile.unique_clients ?? 0

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      {/* 1. Header Navigation & Entity Title */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-border/80 pb-4">
        <div className="flex flex-col gap-1.5">
          <div className="flex items-center gap-2">
            <Link
              href="/domains"
              className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              <ArrowLeftIcon className="size-3.5" />
              <span>Domains</span>
            </Link>
            <span className="text-xs text-muted-foreground">/</span>
            <span className="text-xs font-mono text-muted-foreground">Forensic Profile</span>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-2xl font-bold font-mono tracking-tight text-foreground select-text">
              {detail.domain}
            </h1>
            <DataTableStatus status={profile.last_label ?? "clean"} />
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

      {/* 2. Top Forensic KPI Summary Cards */}
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
            <UsersIcon className="size-3.5" />
            <span>Unique Clients</span>
          </div>
          <div className="text-xl font-mono font-semibold text-foreground">
            {formatNumber(uniqueClients)}
          </div>
        </Card>

        <Card className="p-3 bg-card border-border/80">
          <div className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400 mb-1">
            <ShieldCheckIcon className="size-3.5" />
            <span>Benign Queries</span>
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

      {/* 3. Domain Overview & Threat Intelligence Evidence */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Overview */}
        <Card>
          <CardHeader className="pb-3 border-b border-border/60">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <GlobeIcon className="size-4 text-primary" />
              <span>Domain Overview</span>
            </CardTitle>
            <CardDescription className="text-xs">
              Authoritative lifetime telemetry profile from monitored DNS resolvers.
            </CardDescription>
          </CardHeader>
          <CardContent className="pt-4 flex flex-col gap-3 text-xs">
            <div className="flex items-center justify-between py-1 border-b border-border/40">
              <span className="text-muted-foreground">Domain Entity</span>
              <span className="font-mono font-medium text-foreground select-text">{detail.domain}</span>
            </div>
            <div className="flex items-center justify-between py-1 border-b border-border/40">
              <span className="text-muted-foreground">First Seen (UTC)</span>
              <span className="font-mono text-foreground">{formatDnsnetraTimestamp(profile.first_seen)}</span>
            </div>
            <div className="flex items-center justify-between py-1 border-b border-border/40">
              <span className="text-muted-foreground">Last Seen (UTC)</span>
              <span className="font-mono text-foreground">{formatDnsnetraTimestamp(profile.last_seen)}</span>
            </div>
            <div className="flex items-center justify-between py-1 border-b border-border/40">
              <span className="text-muted-foreground">Last Observed Client</span>
              {profile.last_client_ip ? (
                <Link
                  href={`/clients/${encodeURIComponent(profile.last_client_ip)}`}
                  className="font-mono text-primary hover:underline inline-flex items-center gap-1"
                >
                  {profile.last_client_ip}
                  <ExternalLinkIcon className="size-3" />
                </Link>
              ) : (
                <span className="text-muted-foreground">—</span>
              )}
            </div>
            <div className="flex items-center justify-between py-1 border-b border-border/40">
              <span className="text-muted-foreground">Last Classification Source</span>
              <span className="font-mono text-foreground">{profile.last_ti_source || "Rule Engine / Model"}</span>
            </div>
            <div className="flex flex-col gap-1.5 pt-1">
              <span className="text-muted-foreground">Observed DNS Query Types</span>
              <div className="flex flex-wrap gap-1.5">
                {Object.keys(queryDist).length > 0 ? (
                  Object.entries(queryDist).map(([qType, count]) => (
                    <Badge key={qType} variant="secondary" className="font-mono text-[11px] gap-1">
                      <span>{qType}</span>
                      <span className="text-muted-foreground">({String(count)})</span>
                    </Badge>
                  ))
                ) : (
                  <span className="text-muted-foreground italic">Standard A/AAAA records</span>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Threat Intelligence */}
        <Card>
          <CardHeader className="pb-3 border-b border-border/60">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ShieldAlertIcon className="size-4 text-rose-500" />
              <span>Threat Intelligence Evidence</span>
            </CardTitle>
            <CardDescription className="text-xs">
              Matches against local threat intelligence databases and historical verdict reviews.
            </CardDescription>
          </CardHeader>
          <CardContent className="pt-4 flex flex-col gap-4 text-xs">
            {ti.reputation ? (
              <div className="rounded-md border border-rose-500/20 bg-rose-500/5 p-3.5 flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-rose-700 dark:text-rose-400 flex items-center gap-1.5">
                    <ShieldAlertIcon className="size-4" />
                    Reputation DB Match ({ti.reputation.status})
                  </span>
                  {ti.reputation.confidence !== undefined && ti.reputation.confidence !== null && (
                    <Badge variant="destructive" className="text-[10px] font-mono">
                      {Math.round(ti.reputation.confidence * 100)}% Confidence
                    </Badge>
                  )}
                </div>
                <div className="grid grid-cols-2 gap-2 text-[11px] text-muted-foreground">
                  <div>
                    <span className="block font-medium text-foreground">Source</span>
                    <span>{ti.reputation.source}</span>
                  </div>
                  <div>
                    <span className="block font-medium text-foreground">Times Seen</span>
                    <span className="font-mono">{ti.reputation.times_seen} occurrences</span>
                  </div>
                  <div>
                    <span className="block font-medium text-foreground">First Recorded</span>
                    <span className="font-mono">{formatDnsnetraTimestamp(ti.reputation.first_seen)}</span>
                  </div>
                  <div>
                    <span className="block font-medium text-foreground">Last Verified</span>
                    <span className="font-mono">{formatDnsnetraTimestamp(ti.reputation.last_seen)}</span>
                  </div>
                </div>
              </div>
            ) : null}

            {ti.daily_review ? (
              <div className="rounded-md border border-amber-500/20 bg-amber-500/5 p-3.5 flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-amber-700 dark:text-amber-400 flex items-center gap-1.5">
                    <ClockIcon className="size-4" />
                    Daily Review Queue ({ti.daily_review.status})
                  </span>
                  <Badge variant="outline" className="text-[10px] font-mono border-amber-500/30">
                    Review Count: {ti.daily_review.review_count}
                  </Badge>
                </div>
                <p className="text-[11px] text-muted-foreground">
                  Reason: {ti.daily_review.review_reason ?? "Flagged for periodic re-evaluation"}
                </p>
                <div className="flex items-center justify-between text-[11px] text-muted-foreground pt-1 border-t border-amber-500/10 font-mono">
                  <span>Next Check: {formatDnsnetraTimestamp(ti.daily_review.next_check_at)}</span>
                  <Link href={`/daily-review?search=${encodeURIComponent(detail.domain)}`} className="text-primary hover:underline">
                    Manage in Queue →
                  </Link>
                </div>
              </div>
            ) : null}

            {ti.reviewed_clean ? (
              <div className="rounded-md border border-emerald-500/20 bg-emerald-500/5 p-3.5 flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-emerald-700 dark:text-emerald-400 flex items-center gap-1.5">
                    <ShieldCheckIcon className="size-4" />
                    Analyst Reviewed Clean
                  </span>
                  <Badge variant="outline" className="text-[10px] font-mono border-emerald-500/30 text-emerald-600">
                    Verified
                  </Badge>
                </div>
                <div className="text-[11px] text-muted-foreground flex justify-between">
                  <span>Verified by: {ti.reviewed_clean.verification_source}</span>
                  <span className="font-mono">{formatDnsnetraTimestamp(ti.reviewed_clean.verified_at)}</span>
                </div>
              </div>
            ) : null}

            {!ti.reputation && !ti.daily_review && !ti.reviewed_clean && (
              <div className="flex flex-col items-center justify-center p-6 text-center text-muted-foreground rounded-md border border-dashed border-border gap-2">
                <ShieldCheckIcon className="size-8 text-emerald-500/60" />
                <span className="font-medium text-foreground">No Local Threat Intelligence Matches</span>
                <span className="text-[11px] max-w-xs">
                  This domain has not been flagged by reputation feeds or escalated to analyst review queues.
                </span>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* 4. WHOIS, RDAP, ASN & Network Data (Clearly Documented Unavailable Telemetry) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* WHOIS */}
        <Card className="bg-muted/15 border-border/70">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-xs font-semibold uppercase tracking-wider flex items-center gap-1.5 text-muted-foreground">
                <FileTextIcon className="size-3.5" />
                <span>WHOIS Information</span>
              </CardTitle>
              <Badge variant="outline" className="text-[10px] font-mono text-muted-foreground bg-muted/50">
                Unavailable
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="pt-2 text-xs flex flex-col gap-2 text-muted-foreground">
            <p className="text-[11px] leading-relaxed">
              Authoritative WHOIS registrar records are not provided in the current telemetry feed. Backend registrar integration is pending.
            </p>
            <div className="grid grid-cols-2 gap-1 text-[11px] pt-1 border-t border-border/40 font-mono">
              <span className="text-muted-foreground/70">Registrar:</span>
              <span>Unavailable</span>
              <span className="text-muted-foreground/70">Created:</span>
              <span>Unavailable</span>
              <span className="text-muted-foreground/70">Expires:</span>
              <span>Unavailable</span>
            </div>
          </CardContent>
        </Card>

        {/* RDAP */}
        <Card className="bg-muted/15 border-border/70">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-xs font-semibold uppercase tracking-wider flex items-center gap-1.5 text-muted-foreground">
                <ServerIcon className="size-3.5" />
                <span>RDAP Registration</span>
              </CardTitle>
              <Badge variant="outline" className="text-[10px] font-mono text-muted-foreground bg-muted/50">
                Unavailable
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="pt-2 text-xs flex flex-col gap-2 text-muted-foreground">
            <p className="text-[11px] leading-relaxed">
              RDAP entity events and registry JSON records are not exposed by the current backend schema.
            </p>
            <div className="grid grid-cols-2 gap-1 text-[11px] pt-1 border-t border-border/40 font-mono">
              <span className="text-muted-foreground/70">Entities:</span>
              <span>Unavailable</span>
              <span className="text-muted-foreground/70">Status:</span>
              <span>Unavailable</span>
              <span className="text-muted-foreground/70">Conformance:</span>
              <span>Unavailable</span>
            </div>
          </CardContent>
        </Card>

        {/* ASN / Network */}
        <Card className="bg-muted/15 border-border/70">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-xs font-semibold uppercase tracking-wider flex items-center gap-1.5 text-muted-foreground">
                <NetworkIcon className="size-3.5" />
                <span>ASN / Network</span>
              </CardTitle>
              <Badge variant="outline" className="text-[10px] font-mono text-muted-foreground bg-muted/50">
                Unavailable
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="pt-2 text-xs flex flex-col gap-2 text-muted-foreground">
            <p className="text-[11px] leading-relaxed">
              BGP Autonomous System Numbers and IP geolocations are not included in the telemetry pipeline.
            </p>
            <div className="grid grid-cols-2 gap-1 text-[11px] pt-1 border-t border-border/40 font-mono">
              <span className="text-muted-foreground/70">ASN Number:</span>
              <span>Unavailable</span>
              <span className="text-muted-foreground/70">Organization:</span>
              <span>Unavailable</span>
              <span className="text-muted-foreground/70">Country:</span>
              <span>Unavailable</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* 5. Top Querying Clients Table */}
      <Card>
        <CardHeader className="pb-3 border-b border-border/60">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <UsersIcon className="size-4 text-primary" />
                <span>Observed Querying Clients ({detail.top_querying_clients.length})</span>
              </CardTitle>
              <CardDescription className="text-xs">
                Internal endpoints that have issued DNS resolutions for {detail.domain}.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {detail.top_querying_clients.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs">Client Endpoint</TableHead>
                  <TableHead className="text-xs text-right">Total Queries</TableHead>
                  <TableHead className="text-xs text-right">Benign</TableHead>
                  <TableHead className="text-xs text-right">Malicious</TableHead>
                  <TableHead className="text-xs text-right">Review</TableHead>
                  <TableHead className="text-xs">First Observed</TableHead>
                  <TableHead className="text-xs">Last Observed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {detail.top_querying_clients.map((client) => (
                  <TableRow key={client.client_ip}>
                    <TableCell className="font-mono text-xs font-medium">
                      <Link
                        href={`/clients/${encodeURIComponent(client.client_ip)}`}
                        className="text-primary hover:underline inline-flex items-center gap-1"
                      >
                        {client.client_ip}
                        <ExternalLinkIcon className="size-3 opacity-60" />
                      </Link>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-right font-medium">
                      {formatNumber(client.visit_count)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-right text-emerald-600 dark:text-emerald-400">
                      {formatNumber(client.benign_visits)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-right text-rose-600 dark:text-rose-400">
                      {formatNumber(client.malicious_visits)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-right text-amber-600 dark:text-amber-400">
                      {formatNumber(client.review_needed_visits)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {formatDnsnetraTimestamp(client.first_seen)}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {formatDnsnetraTimestamp(client.last_seen)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="p-8 text-center text-xs text-muted-foreground font-mono">
              No querying client relationships recorded in database.
            </div>
          )}
        </CardContent>
      </Card>

      {/* 6. Recent DNS Query Events */}
      <Card>
        <CardHeader className="pb-3 border-b border-border/60">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <ActivityIcon className="size-4 text-primary" />
                <span>Recent Query History ({detail.recent_queries.length})</span>
              </CardTitle>
              <CardDescription className="text-xs">
                Last recorded DNS resolution events for {detail.domain}.
              </CardDescription>
            </div>
            <Link
              href={`/queries?search=${encodeURIComponent(detail.domain)}`}
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
                  <TableHead className="text-xs">Client Endpoint</TableHead>
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
                        href={`/clients/${encodeURIComponent(q.client_ip)}`}
                        className="text-primary hover:underline"
                      >
                        {q.client_ip}
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
              No recent query history events found for this domain.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
