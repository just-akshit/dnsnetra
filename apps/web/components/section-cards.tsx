"use client"

import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardAction,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { TrendingUpIcon, ActivityIcon, AlertTriangleIcon } from "lucide-react"

import type { DashboardKPIs } from "@/lib/data-table/api-client"
import { formatNumber } from "@/lib/data-table/formatters"

export function SectionCards({ kpis }: { kpis?: DashboardKPIs }) {
  const totalQueries = kpis ? formatNumber(kpis.total_queries) : "0"
  const maliciousDomains = kpis ? formatNumber(kpis.malicious_domains) : "0"
  const totalClients = kpis ? formatNumber(kpis.total_clients) : "0"
  const uniqueDomains = kpis ? formatNumber(kpis.unique_domains) : "0"
  const malPct = kpis ? `${kpis.malicious_query_percentage.toFixed(1)}%` : "0.0%"

  return (
    <div className="grid grid-cols-1 gap-4 px-4 *:data-[slot=card]:bg-linear-to-t *:data-[slot=card]:from-primary/5 *:data-[slot=card]:to-card *:data-[slot=card]:shadow-xs lg:px-6 @xl/main:grid-cols-2 @5xl/main:grid-cols-4 dark:*:data-[slot=card]:bg-card">
      <Card className="@container/card">
        <CardHeader>
          <CardDescription>Total Queries</CardDescription>
          <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
            {totalQueries}
          </CardTitle>
          <CardAction>
            <Badge variant="outline">
              <ActivityIcon />
              Active
            </Badge>
          </CardAction>
        </CardHeader>
        <CardFooter className="flex-col items-start gap-1.5 text-sm">
          <div className="line-clamp-1 flex gap-2 font-medium">
            Resolver Query Volume
          </div>
          <div className="text-muted-foreground">
            Authoritative DNS telemetry log events
          </div>
        </CardFooter>
      </Card>
      <Card className="@container/card">
        <CardHeader>
          <CardDescription>Malicious Domains</CardDescription>
          <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl text-destructive">
            {maliciousDomains}
          </CardTitle>
          <CardAction>
            <Badge variant="outline" className="text-destructive border-destructive/30">
              <AlertTriangleIcon />
              {malPct}
            </Badge>
          </CardAction>
        </CardHeader>
        <CardFooter className="flex-col items-start gap-1.5 text-sm">
          <div className="line-clamp-1 flex gap-2 font-medium text-destructive">
            Confirmed Threat Intel Match
          </div>
          <div className="text-muted-foreground">
            Enriched via Reputation DB & TI feeds
          </div>
        </CardFooter>
      </Card>
      <Card className="@container/card">
        <CardHeader>
          <CardDescription>Client Endpoints</CardDescription>
          <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
            {totalClients}
          </CardTitle>
          <CardAction>
            <Badge variant="outline">
              <TrendingUpIcon />
              {kpis?.unique_clients ?? 0} Active
            </Badge>
          </CardAction>
        </CardHeader>
        <CardFooter className="flex-col items-start gap-1.5 text-sm">
          <div className="line-clamp-1 flex gap-2 font-medium">
            Fleet Endpoints Tracked
          </div>
          <div className="text-muted-foreground">
            Lifetime enrolled client profiles
          </div>
        </CardFooter>
      </Card>
      <Card className="@container/card">
        <CardHeader>
          <CardDescription>Unique Domains</CardDescription>
          <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
            {uniqueDomains}
          </CardTitle>
          <CardAction>
            <Badge variant="outline" className="text-muted-foreground">
              {kpis?.unknown_domains ?? 0} Triage
            </Badge>
          </CardAction>
        </CardHeader>
        <CardFooter className="flex-col items-start gap-1.5 text-sm">
          <div className="line-clamp-1 flex gap-2 font-medium">
            Distinct Observed FQDNs
          </div>
          <div className="text-muted-foreground">
            Cataloged across monitored resolvers
          </div>
        </CardFooter>
      </Card>
    </div>
  )
}
