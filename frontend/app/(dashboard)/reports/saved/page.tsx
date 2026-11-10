"use client"

import * as React from "react"
import Link from "next/link"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { dnsnetraApi } from "@/lib/data-table/api-client"
import type { SavedReportSummary } from "@/lib/reporting/types"

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : "Failed to load saved reports."
}

export default function SavedReportsPage() {
  const [items, setItems] = React.useState<SavedReportSummary[]>([])
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  const fetchReports = React.useCallback(
    () => dnsnetraApi.listSavedReports({ limit: 50 }),
    []
  )

  React.useEffect(() => {
    fetchReports()
      .then((res) => {
        setItems(res.items)
        setError(null)
      })
      .catch((err: unknown) => setError(errorMessage(err)))
      .finally(() => setLoading(false))
  }, [fetchReports])

  const handleRetry = () => {
    setLoading(true)
    setError(null)
    fetchReports()
      .then((res) => setItems(res.items))
      .catch((err: unknown) => setError(errorMessage(err)))
      .finally(() => setLoading(false))
  }

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold tracking-tight">Saved Reports</h2>
          <p className="text-sm text-muted-foreground">
            Immutable snapshots created from dossiers and query sets.
          </p>
        </div>
        <Button variant="outline" size="sm" render={<Link href="/reports" />}>
          Back to telemetry
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Library</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <p className="p-4 text-sm text-muted-foreground">Loading reports…</p>
          ) : error ? (
            <div className="flex flex-col items-start gap-2 p-4">
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
              <Button variant="outline" size="sm" onClick={handleRetry}>
                Retry
              </Button>
            </div>
          ) : items.length === 0 ? (
            <p className="p-4 text-sm text-muted-foreground">No saved reports yet.</p>
          ) : (
            <div className="divide-y divide-border/60">
              {items.map((report) => (
                <Link
                  key={report.public_id}
                  href={`/reports/saved/${encodeURIComponent(report.public_id)}`}
                  className="flex items-center justify-between gap-3 p-3 transition-colors hover:bg-muted/50"
                >
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{report.title}</p>
                    <p className="font-mono text-[11px] text-muted-foreground">
                      <span>{report.public_id}</span> · {report.entity_value ?? report.kind}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {report.case_public_id && (
                      <Badge variant="outline" className="font-mono text-[10px]">
                        {report.case_public_id}
                      </Badge>
                    )}
                    <Badge variant="outline">{report.status}</Badge>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
