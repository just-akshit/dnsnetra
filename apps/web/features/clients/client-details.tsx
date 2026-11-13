"use client"

import * as React from "react"
import {
  dnsnetraApi,
  type ClientDetail,
} from "@/lib/data-table/api-client"
import {
  formatDnsnetraTimestamp,
  formatNumber,
} from "@/lib/data-table/formatters"
import { DataTableStatus } from "@/components/data-table/data-table-status"
import { Skeleton } from "@/components/ui/skeleton"
import { Badge } from "@/components/ui/badge"
import {
  GlobeIcon,
  ActivityIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  AlertCircleIcon,
} from "lucide-react"

export interface ClientDetailsProps {
  clientIp: string
  onClose?: () => void
}

export function ClientDetails({ clientIp }: ClientDetailsProps) {
  const [detail, setDetail] = React.useState<ClientDetail | null>(null)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  React.useEffect(() => {
    let cancelled = false

    async function fetchDetail() {
      try {
        const data = await dnsnetraApi.getClientDetail(clientIp)
        if (!cancelled) {
          setDetail(data)
          setError(null)
          setLoading(false)
        }
      } catch (err: unknown) {
        if (!cancelled) {
          const msg =
            err instanceof Error ? err.message : "Failed to load client details."
          setError(msg)
          setLoading(false)
        }
      }
    }

    fetchDetail()

    return () => {
      cancelled = true
    }
  }, [clientIp])

  if (loading) {
    return (
      <div className="flex flex-col gap-4 py-2 animate-pulse">
        <div className="grid grid-cols-3 gap-2">
          <Skeleton className="h-16 rounded-md bg-muted/60" />
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

  return (
    <div className="flex flex-col gap-6 py-2">
      {/* 1. Metric KPI Cards */}
      <div className="grid grid-cols-3 gap-2.5">
        <div className="rounded-md border border-border/80 bg-background p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <ActivityIcon className="size-3.5" />
            <span>Queries</span>
          </div>
          <div className="text-lg font-mono font-semibold text-foreground">
            {formatNumber(profile?.total_queries ?? 0)}
          </div>
        </div>

        <div className="rounded-md border border-border/80 bg-background p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <GlobeIcon className="size-3.5" />
            <span>Domains</span>
          </div>
          <div className="text-lg font-mono font-semibold text-foreground">
            {formatNumber(profile?.unique_domains ?? 0)}
          </div>
        </div>

        <div className="rounded-md border border-border/80 bg-background p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <ShieldAlertIcon className="size-3.5 text-rose-500" />
            <span>Threats</span>
          </div>
          <div className="text-lg font-mono font-semibold text-rose-600 dark:text-rose-400">
            {formatNumber(profile?.malicious_queries ?? 0)}
          </div>
        </div>
      </div>

      {/* 2. Temporal Profile Scope */}
      <div className="rounded-md border border-border/80 bg-background p-4 flex flex-col gap-3">
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div>
            <span className="text-muted-foreground block text-[11px]">First Observed</span>
            <span className="font-mono text-foreground">
              {formatDnsnetraTimestamp(profile?.first_seen)}
            </span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px]">Last Observed</span>
            <span className="font-mono text-foreground">
              {formatDnsnetraTimestamp(profile?.last_seen)}
            </span>
          </div>
        </div>
      </div>

      {/* 3. Threat Activity Breakdown */}
      {detail?.threat_activity && detail.threat_activity.length > 0 ? (
        <div className="flex flex-col gap-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-rose-600 dark:text-rose-400">
            Identified Threat Queries ({detail.threat_activity.length})
          </h4>
          <div className="rounded-md border border-rose-500/30 divide-y divide-rose-500/20 bg-rose-500/5 text-xs font-mono">
            {detail.threat_activity.slice(0, 5).map((t) => (
              <div
                key={t.domain}
                className="flex items-center justify-between p-2.5"
              >
                <span className="text-foreground">{t.domain}</span>
                <span className="text-rose-600 dark:text-rose-400 font-semibold tabular-nums">
                  {formatNumber(t.visit_count)} hits ({t.activity_category})
                </span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="flex items-center gap-2 rounded-md bg-emerald-500/10 p-3 border border-emerald-500/20 text-xs">
          <ShieldCheckIcon className="size-4 text-emerald-600 shrink-0" />
          <span className="text-emerald-700 dark:text-emerald-400 font-medium">
            Zero malicious queries attributed to this client endpoint.
          </span>
        </div>
      )}

      {/* 4. Top Queried Domains */}
      {detail?.top_domains && detail.top_domains.length > 0 && (
        <div className="flex flex-col gap-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Top Visited Domains ({detail.top_domains.length})
          </h4>
          <div className="rounded-md border border-border/80 divide-y divide-border/60 bg-background text-xs font-mono">
            {detail.top_domains.slice(0, 5).map((d) => (
              <div
                key={d.domain}
                className="flex items-center justify-between p-2.5 hover:bg-muted/30"
              >
                <span className="text-foreground truncate max-w-[240px]">
                  {d.domain}
                </span>
                <span className="text-muted-foreground tabular-nums">
                  {formatNumber(d.visit_count)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 5. Recent Telemetry Events */}
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
                  <span className="text-foreground text-[11px] truncate max-w-[180px]">
                    {q.domain}
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
