"use client"

import * as React from "react"
import {
  dnsnetraApi,
  type DomainDetail,
} from "@/lib/data-table/api-client"
import {
  formatDnsnetraTimestamp,
  formatNumber,
} from "@/lib/data-table/formatters"
import { DataTableStatus } from "@/components/data-table/data-table-status"
import { Skeleton } from "@/components/ui/skeleton"
import { Badge } from "@/components/ui/badge"
import {
  ShieldCheckIcon,
  ShieldAlertIcon,
  ClockIcon,
  UsersIcon,
  ActivityIcon,
  AlertCircleIcon,
} from "lucide-react"

export interface DomainDetailsProps {
  domain: string
  onClose?: () => void
}

export function DomainDetails({ domain }: DomainDetailsProps) {
  const [detail, setDetail] = React.useState<DomainDetail | null>(null)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  React.useEffect(() => {
    let cancelled = false

    async function fetchDetail() {
      try {
        const data = await dnsnetraApi.getDomainDetail(domain)
        if (!cancelled) {
          setDetail(data)
          setError(null)
          setLoading(false)
        }
      } catch (err: unknown) {
        if (!cancelled) {
          const msg =
            err instanceof Error ? err.message : "Failed to load domain details."
          setError(msg)
          setLoading(false)
        }
      }
    }

    fetchDetail()

    return () => {
      cancelled = true
    }
  }, [domain])

  if (loading) {
    return (
      <div className="flex flex-col gap-4 py-2 animate-pulse">
        <div className="grid grid-cols-2 gap-3">
          <Skeleton className="h-16 rounded-md bg-muted/60" />
          <Skeleton className="h-16 rounded-md bg-muted/60" />
        </div>
        <Skeleton className="h-32 rounded-md bg-muted/60" />
        <Skeleton className="h-40 rounded-md bg-muted/60" />
      </div>
    )
  }

  if (error && !detail) {
    return (
      <div className="flex flex-col items-center justify-center p-6 text-center text-xs text-muted-foreground gap-2">
        <AlertCircleIcon className="size-5 text-amber-500" />
        <span>{error}</span>
      </div>
    )
  }

  const profile = detail?.profile
  const ti = detail?.threat_intel

  return (
    <div className="flex flex-col gap-6 py-2">
      {/* 1. Metric KPI Cards */}
      <div className="grid grid-cols-2 gap-3">
        <div className="rounded-md border border-border/80 bg-background p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <ActivityIcon className="size-3.5" />
            <span>Total Queries</span>
          </div>
          <div className="text-xl font-mono font-semibold text-foreground">
            {formatNumber(profile?.total_queries ?? 0)}
          </div>
        </div>

        <div className="rounded-md border border-border/80 bg-background p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <UsersIcon className="size-3.5" />
            <span>Unique Clients</span>
          </div>
          <div className="text-xl font-mono font-semibold text-foreground">
            {formatNumber(profile?.unique_clients ?? 0)}
          </div>
        </div>
      </div>

      {/* 2. Verdict & Telemetry Temporal Scope */}
      <div className="rounded-md border border-border/80 bg-background p-4 flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
            Current Classification
          </span>
          <DataTableStatus status={profile?.last_label ?? "clean"} />
        </div>

        <div className="grid grid-cols-2 gap-2 pt-2 border-t border-border/60 text-xs">
          <div>
            <span className="text-muted-foreground block text-[11px]">First Seen</span>
            <span className="font-mono text-foreground">
              {formatDnsnetraTimestamp(profile?.first_seen)}
            </span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px]">Last Seen</span>
            <span className="font-mono text-foreground">
              {formatDnsnetraTimestamp(profile?.last_seen)}
            </span>
          </div>
        </div>
      </div>

      {/* 3. Threat Intelligence Evidence */}
      <div className="rounded-md border border-border/80 bg-background p-4 flex flex-col gap-2.5">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Threat Intelligence Evidence
        </h4>

        {ti?.reputation ? (
          <div className="flex items-start gap-2.5 rounded-sm bg-rose-500/10 p-2.5 border border-rose-500/20 text-xs">
            <ShieldAlertIcon className="size-4 text-rose-600 mt-0.5 shrink-0" />
            <div className="flex flex-col gap-0.5">
              <span className="font-semibold text-rose-700 dark:text-rose-400">
                Malicious Reputation Match
              </span>
              <span className="text-muted-foreground">
                Source: {ti.reputation.source} (Seen {ti.reputation.times_seen}x)
              </span>
            </div>
          </div>
        ) : ti?.daily_review ? (
          <div className="flex items-start gap-2.5 rounded-sm bg-amber-500/10 p-2.5 border border-amber-500/20 text-xs">
            <ClockIcon className="size-4 text-amber-600 mt-0.5 shrink-0" />
            <div className="flex flex-col gap-0.5">
              <span className="font-semibold text-amber-700 dark:text-amber-400">
                Daily Review Queue ({ti.daily_review.status})
              </span>
              <span className="text-muted-foreground">
                {ti.daily_review.review_reason ?? "Flagged for periodic re-evaluation"}
              </span>
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-2 rounded-sm bg-emerald-500/10 p-2.5 border border-emerald-500/20 text-xs">
            <ShieldCheckIcon className="size-4 text-emerald-600 shrink-0" />
            <span className="text-emerald-700 dark:text-emerald-400 font-medium">
              No active threat intelligence alerts on record.
            </span>
          </div>
        )}
      </div>

      {/* 4. Top Querying Clients */}
      {detail?.top_querying_clients && detail.top_querying_clients.length > 0 && (
        <div className="flex flex-col gap-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Top Querying Clients ({detail.top_querying_clients.length})
          </h4>
          <div className="rounded-md border border-border/80 divide-y divide-border/60 bg-background text-xs font-mono">
            {detail.top_querying_clients.slice(0, 5).map((c) => (
              <div
                key={c.client_ip}
                className="flex items-center justify-between p-2.5 hover:bg-muted/30"
              >
                <span className="text-foreground">{c.client_ip}</span>
                <span className="text-muted-foreground tabular-nums">
                  {formatNumber(c.visit_count)} visits
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 5. Recent Queries Preview */}
      {detail?.recent_queries && detail.recent_queries.length > 0 && (
        <div className="flex flex-col gap-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Recent Telemetry Events
          </h4>
          <div className="rounded-md border border-border/80 divide-y divide-border/60 bg-background text-xs font-mono">
            {detail.recent_queries.slice(0, 5).map((q) => (
              <div
                key={q.id}
                className="flex items-center justify-between p-2.5 hover:bg-muted/30"
              >
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="px-1 py-0 text-[10px]">
                    {q.query_type}
                  </Badge>
                  <span className="text-muted-foreground text-[11px]">
                    {formatDnsnetraTimestamp(q.timestamp)}
                  </span>
                </div>
                <DataTableStatus status={q.final_label} />
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
