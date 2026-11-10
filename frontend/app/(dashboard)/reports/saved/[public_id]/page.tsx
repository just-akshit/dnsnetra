"use client"

import * as React from "react"
import { useParams } from "next/navigation"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { dnsnetraApi } from "@/lib/data-table/api-client"
import type { SavedReportDetail } from "@/lib/reporting/types"

type ReportSnapshot = {
  observed_in_network?: boolean
  dossier?: {
    domain?: string
    profile?: { total_queries?: number; unique_clients?: number }
    recent_queries?: unknown[]
    live_intel?: { verdict?: { state?: string }; checked_at?: string }
  }
}

export default function ReportDetailPage() {
  const params = useParams<{ public_id: string }>()
  const publicId = decodeURIComponent(params.public_id)
  const [report, setReport] = React.useState<SavedReportDetail | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [conclusion, setConclusion] = React.useState("")
  const [saving, setSaving] = React.useState(false)
  const [exporting, setExporting] = React.useState<"csv" | "xlsx" | null>(null)

  const loadReport = React.useCallback(
    () =>
      dnsnetraApi
        .getSavedReport(publicId)
        .then((data) => {
          setReport(data)
          setConclusion(data.conclusion ?? "")
          setError(null)
        })
        .catch(() => {
          setError("Failed to load report.")
          toast.error("Failed to load report.")
        }),
    [publicId]
  )

  React.useEffect(() => {
    loadReport()
  }, [loadReport])

  async function markReviewed() {
    if (!report) return
    setSaving(true)
    try {
      const updated = await dnsnetraApi.reviewSavedReport(publicId, {
        status: "reviewed",
        conclusion,
        verdict: report.verdict ?? undefined,
      })
      setReport(updated)
      toast.success("Report marked reviewed.")
    } catch {
      toast.error("Review failed.")
    } finally {
      setSaving(false)
    }
  }

  async function exportReport(format: "csv" | "xlsx") {
    setExporting(format)
    try {
      await dnsnetraApi.downloadSavedReport(publicId, format)
      toast.success("Export started.")
    } catch {
      toast.error("Export failed.")
    } finally {
      setExporting(null)
    }
  }

  if (error) {
    return (
      <div className="flex flex-col items-start gap-2 p-6">
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
        <Button variant="outline" size="sm" onClick={loadReport}>
          Retry
        </Button>
      </div>
    )
  }

  if (!report) {
    return <p className="p-6 text-sm text-muted-foreground">Loading report…</p>
  }

  const snapshot = report.snapshot as ReportSnapshot
  const dossier = snapshot.dossier ?? {}
  const profile = dossier.profile ?? {}
  const live = dossier.live_intel ?? {}

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{report.title}</h1>
          <p className="font-mono text-[11px] text-muted-foreground">
            {report.public_id} · {report.kind} · {report.created_at}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => exportReport("csv")}
            disabled={exporting !== null}
          >
            Export CSV
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => exportReport("xlsx")}
            disabled={exporting !== null}
          >
            Export XLSX
          </Button>
          <Badge variant="outline">{report.status}</Badge>
          {report.reviewed_at && (
            <span className="font-mono text-[10px] text-muted-foreground">
              {report.reviewed_at}
              {report.reviewed_by != null ? ` · by ${report.reviewed_by}` : ""}
            </span>
          )}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader><CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">Total queries</CardTitle></CardHeader>
          <CardContent><p className="font-mono text-2xl font-semibold">{profile.total_queries ?? "—"}</p></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">Unique clients</CardTitle></CardHeader>
          <CardContent><p className="font-mono text-2xl font-semibold">{profile.unique_clients ?? "—"}</p></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">Live verdict</CardTitle></CardHeader>
          <CardContent><p className="font-mono text-2xl font-semibold">{live.verdict?.state ?? "n/a"}</p></CardContent>
        </Card>
      </div>

      {snapshot.observed_in_network === false && (
        <p className="text-sm text-muted-foreground">No local telemetry for this window.</p>
      )}

      <Card>
        <CardHeader><CardTitle className="text-sm">Analyst assessment</CardTitle></CardHeader>
        <CardContent className="flex flex-col gap-3">
          <label htmlFor="conclusion" className="text-sm font-medium">Conclusion</label>
          <Input
            id="conclusion"
            value={conclusion}
            onChange={(event) => setConclusion(event.target.value)}
            placeholder="What did you conclude?"
          />
          <div>
            <Button
              size="sm"
              onClick={markReviewed}
              disabled={saving || !conclusion.trim()}
              aria-busy={saving}
            >
              {saving ? "Saving…" : "Mark reviewed"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
