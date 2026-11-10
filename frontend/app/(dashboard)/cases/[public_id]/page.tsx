"use client"

import * as React from "react"
import Link from "next/link"
import { useParams } from "next/navigation"
import { toast } from "sonner"

import { useAuthUser } from "@/components/auth/AuthGuard"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { dnsnetraApi } from "@/lib/data-table/api-client"
import type { CaseDetail, CaseEvent } from "@/lib/reporting/types"

interface Transition {
  label: string
  status: string
  /** Mirrors the backend's cases:manage requirement. */
  manageOnly?: boolean
}

const NEXT: Record<string, Transition[]> = {
  open: [{ label: "Start triage", status: "triaged" }],
  triaged: [{ label: "Start investigation", status: "investigating" }],
  investigating: [{ label: "Resolve", status: "resolved" }],
  awaiting_info: [{ label: "Resume", status: "investigating" }],
  resolved: [
    { label: "Reopen", status: "investigating", manageOnly: true },
    { label: "Close", status: "closed", manageOnly: true },
  ],
  closed: [{ label: "Reopen", status: "investigating", manageOnly: true }],
}

const RESOLUTIONS = [
  { value: "true_positive", label: "True positive" },
  { value: "false_positive", label: "False positive" },
  { value: "benign", label: "Benign" },
  { value: "duplicate", label: "Duplicate" },
  { value: "no_action", label: "No action" },
]

function actionsFor(status: string, role: string | undefined): Transition[] {
  const actions = NEXT[status] ?? []
  if (role === "ADMIN" || role === "SUPER_ADMIN") return actions
  if (role === "ANALYST") return actions.filter((action) => !action.manageOnly)
  return []
}

function errorMessage(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback
}

function eventLabel(event: CaseEvent): string {
  if (event.kind === "status_changed") {
    const from = typeof event.metadata?.from === "string" ? event.metadata.from : null
    const to = typeof event.metadata?.to === "string" ? event.metadata.to : null
    if (from && to) return `${from} → ${to}`
  }
  return event.kind
}

export default function CaseDetailPage() {
  const params = useParams<{ public_id: string }>()
  const publicId = decodeURIComponent(params.public_id)
  const me = useAuthUser()
  const [item, setItem] = React.useState<CaseDetail | null>(null)
  const [comment, setComment] = React.useState("")
  const [resolution, setResolution] = React.useState("true_positive")
  const [pending, setPending] = React.useState<string | null>(null)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  const fetchCase = React.useCallback(() => {
    return dnsnetraApi.getCase(publicId)
      .then(setItem)
      .catch((err: unknown) => {
        const message = errorMessage(err, "Failed to load case.")
        setError(message)
        toast.error(message)
      })
      .finally(() => setLoading(false))
  }, [publicId])

  React.useEffect(() => {
    void fetchCase()
  }, [fetchCase])

  const handleRetry = () => {
    setLoading(true)
    setError(null)
    void fetchCase()
  }

  async function move(status: string) {
    if (pending) return
    setPending(status)
    try {
      const payload = status === "resolved"
        ? { status, resolution }
        : { status }
      const updated = await dnsnetraApi.updateCase(publicId, payload)
      setItem(updated)
      toast.success(`Case moved to ${status}.`)
    } catch (err) {
      toast.error(errorMessage(err, "Case update failed."))
    } finally {
      setPending(null)
    }
  }

  async function addComment() {
    if (!comment.trim() || pending) return
    setPending("comment")
    try {
      setItem(await dnsnetraApi.commentCase(publicId, comment))
      setComment("")
    } catch (err) {
      toast.error(errorMessage(err, "Comment failed."))
    } finally {
      setPending(null)
    }
  }

  if (!item) {
    if (loading) {
      return <p className="p-6 text-sm text-muted-foreground">Loading case…</p>
    }
    return (
      <div className="flex flex-col items-start gap-2 p-6">
        <p role="alert" className="text-sm text-destructive">
          {error ?? "Failed to load case."}
        </p>
        <Button variant="outline" size="sm" onClick={handleRetry}>
          Retry
        </Button>
      </div>
    )
  }

  const actions = actionsFor(item.status, me?.role)
  const canResolve = actions.some((action) => action.status === "resolved")

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{item.title}</h1>
          <p className="font-mono text-[11px] text-muted-foreground">
            {item.public_id} · {item.entity_value ?? "no entity"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline">{item.priority}</Badge>
          <Badge variant="outline">{item.status}</Badge>
        </div>
      </div>

      {actions.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          {actions.map((action) => (
            <Button key={action.status} size="sm" onClick={() => void move(action.status)}
                    disabled={pending !== null}>
              {pending === action.status ? "Working…" : action.label}
            </Button>
          ))}
          {canResolve && (
            <select
              aria-label="Resolution"
              value={resolution}
              onChange={(e) => setResolution(e.target.value)}
              disabled={pending !== null}
              className="h-8 rounded-lg border border-input bg-transparent px-2.5 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-input/30"
            >
              {RESOLUTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          )}
        </div>
      )}

      <Card>
        <CardHeader><CardTitle className="text-sm">Timeline</CardTitle></CardHeader>
        <CardContent className="flex flex-col gap-3">
          {item.events.length === 0 ? (
            <p className="text-sm text-muted-foreground">No events yet.</p>
          ) : (
            <ol className="flex flex-col gap-2">
              {item.events.map((event) => (
                <li key={event.id} className="text-sm">
                  <span className="font-mono text-[11px] text-muted-foreground">{event.created_at}</span>
                  <span className="ml-2">{eventLabel(event)}</span>
                  {event.body && <span className="ml-2 text-muted-foreground">{event.body}</span>}
                </li>
              ))}
            </ol>
          )}
          <div className="flex gap-2">
            <Input value={comment} onChange={(e) => setComment(e.target.value)}
                   placeholder="Add a comment" aria-label="Comment" disabled={pending !== null} />
            <Button size="sm" onClick={() => void addComment()} disabled={pending !== null}>
              {pending === "comment" ? "Working…" : "Comment"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm">Linked reports</CardTitle></CardHeader>
        <CardContent>
          {item.reports.length === 0 ? (
            <p className="text-sm text-muted-foreground">No linked reports.</p>
          ) : (
            <ul className="flex flex-col gap-1">
              {item.reports.map((report) => (
                <li key={report}>
                  <Link href={`/reports/saved/${encodeURIComponent(report)}`}
                        className="font-mono text-xs underline-offset-4 hover:underline">
                    {report}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
