"use client"

import * as React from "react"
import { Area, AreaChart, CartesianGrid, XAxis } from "recharts"

import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"
import type { TimeseriesResponse } from "@/lib/data-table/api-client"

export const description = "DNS query volume over time"

const chartConfig = {
  queries: {
    label: "DNS Queries",
  },
  total: {
    label: "Total Queries",
    color: "var(--primary)",
  },
  suspicious: {
    label: "Suspicious",
    color: "oklch(0.65 0.2 25)",
  },
} satisfies ChartConfig

import { Badge } from "@/components/ui/badge"
import { ActivityIcon } from "lucide-react"

interface ChartAreaInteractiveProps {
  timeseries?: TimeseriesResponse | null
  timeRange?: string
  onTimeRangeChange?: (range: string) => void
  loading?: boolean
}

export function ChartAreaInteractive({
  timeseries,
  loading = false,
}: ChartAreaInteractiveProps) {
  const chartData = React.useMemo(() => {
    if (!timeseries?.buckets?.length) return []
    return timeseries.buckets.map((b) => {
      const d = b.timestamp
      const label = d.length > 10 ? `${d.slice(5, 10)} ${d.slice(11, 16)}` : d.slice(5, 10)
      return {
        date: label,
        total: b.total_queries,
        suspicious: b.malicious_queries + b.review_needed_queries,
      }
    })
  }, [timeseries])

  const isEmpty = !chartData.length || chartData.every((d) => d.total === 0)

  return (
    <Card className="@container/card">
      <CardHeader>
        <CardTitle>DNS Query Volume</CardTitle>
        <CardDescription>
          <span className="hidden @[540px]/card:block">
            Chronological query timeseries with canonical verdict distribution
          </span>
          <span className="@[540px]/card:hidden">Query volume</span>
        </CardDescription>
        <CardAction>
          {timeseries?.bucket_size && (
            <Badge variant="outline" className="font-mono text-[11px] text-muted-foreground">
              Bucket: {timeseries.bucket_size}
            </Badge>
          )}
        </CardAction>
      </CardHeader>
      <CardContent className="px-2 pt-4 sm:px-6 sm:pt-6">
        {loading ? (
          <div className="flex h-[250px] w-full items-center justify-center text-xs text-muted-foreground">
            <span className="animate-pulse">Loading telemetry timeseries...</span>
          </div>
        ) : isEmpty ? (
          <div className="flex h-[250px] w-full flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border/70 p-6 text-center text-xs text-muted-foreground">
            <ActivityIcon className="h-6 w-6 text-muted-foreground/50" />
            <span className="font-medium text-foreground">No telemetry recorded for selected window</span>
            <span>No DNS queries were observed in this time range. Select another preset or custom range.</span>
          </div>
        ) : (
          <ChartContainer
            config={chartConfig}
            className="aspect-auto h-[250px] w-full"
          >
            <AreaChart data={chartData}>
            <defs>
              <linearGradient id="fillTotal" x1="0" y1="0" x2="0" y2="1">
                <stop
                  offset="5%"
                  stopColor="var(--color-total)"
                  stopOpacity={0.6}
                />
                <stop
                  offset="95%"
                  stopColor="var(--color-total)"
                  stopOpacity={0.05}
                />
              </linearGradient>
              <linearGradient id="fillSuspicious" x1="0" y1="0" x2="0" y2="1">
                <stop
                  offset="5%"
                  stopColor="var(--color-suspicious)"
                  stopOpacity={0.8}
                />
                <stop
                  offset="95%"
                  stopColor="var(--color-suspicious)"
                  stopOpacity={0.1}
                />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} />
            <XAxis
              dataKey="date"
              tickLine={false}
              axisLine={false}
              tickMargin={8}
              minTickGap={32}
              tickFormatter={(value) => {
                const date = new Date(value)
                return date.toLocaleDateString("en-US", {
                  month: "short",
                  day: "numeric",
                })
              }}
            />
            <ChartTooltip
              cursor={false}
              content={
                <ChartTooltipContent
                  labelFormatter={(value) => {
                    return new Date(value).toLocaleDateString("en-US", {
                      month: "short",
                      day: "numeric",
                    })
                  }}
                  indicator="dot"
                />
              }
            />
            <Area
              dataKey="suspicious"
              type="natural"
              fill="url(#fillSuspicious)"
              stroke="var(--color-suspicious)"
            />
            <Area
              dataKey="total"
              type="natural"
              fill="url(#fillTotal)"
              stroke="var(--color-total)"
            />
          </AreaChart>
        </ChartContainer>
        )}
      </CardContent>
    </Card>
  )
}
