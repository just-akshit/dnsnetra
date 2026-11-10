"use client"

import * as React from "react"
import Link from "next/link"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { dnsnetraApi } from "@/lib/data-table/api-client"
import type { CaseSummary } from "@/lib/reporting/types"

function errorMessage(err: unknown): string {
  return err instanceof Error && err.message ? err.message : "Failed to load cases."
}

export default function CasesPage() {
  const [items, setItems] = React.useState<CaseSummary[]>([])
  const [total, setTotal] = React.useState(0)
  const [hasMore, setHasMore] = React.useState(false)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  const fetchCases = React.useCallback(() => {
    return dnsnetraApi.listCases({ limit: 50 })
      .then((res) => {
        setItems(res.items)
        setTotal(res.total)
        setHasMore(res.has_more)
      })
      .catch((err: unknown) => {
        const message = errorMessage(err)
        setError(message)
        toast.error(message)
      })
      .finally(() => setLoading(false))
  }, [])

  React.useEffect(() => {
    void fetchCases()
  }, [fetchCases])

  const handleRetry = () => {
    setLoading(true)
    setError(null)
    void fetchCases()
  }

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Cases</h2>
        <p className="text-sm text-muted-foreground">Investigations, assignments, and resolutions.</p>
      </div>
      <Card>
        <CardHeader><CardTitle className="text-sm">Queue</CardTitle></CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <p className="p-4 text-sm text-muted-foreground">Loading cases…</p>
          ) : error ? (
            <div className="flex flex-col items-start gap-2 p-4">
              <p role="alert" className="text-sm text-destructive">{error}</p>
              <Button variant="outline" size="sm" onClick={handleRetry}>
                Retry
              </Button>
            </div>
          ) : items.length === 0 ? (
            <p className="p-4 text-sm text-muted-foreground">No cases yet.</p>
          ) : (
            <>
              <div className="divide-y divide-border/60">
                {items.map((item) => (
                  <Link key={item.public_id} href={`/cases/${encodeURIComponent(item.public_id)}`}
                        className="flex items-center justify-between gap-3 p-3 hover:bg-muted/50">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium">{item.title}</p>
                      <p className="font-mono text-[11px] text-muted-foreground">
                        {item.public_id} · {item.entity_value ?? "no entity"}
                      </p>
                    </div>
                    <div className="flex shrink-0 gap-2">
                      <Badge variant="outline">{item.priority}</Badge>
                      <Badge variant="outline">{item.status}</Badge>
                    </div>
                  </Link>
                ))}
              </div>
              {hasMore && (
                <p className="border-t border-border/60 p-3 text-xs text-muted-foreground">
                  Showing {items.length} of {total} cases.
                </p>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
