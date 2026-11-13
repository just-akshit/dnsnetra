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
  /** Backend gates this on cases:manage (closing, or reopening a closed case). */
  manageOnly?: boolean
}

const NEXT: Record<string, Transition[]> = {
  open: [
    { label: "Start triage", status: "triaged" },
    { label: "Close", status: "closed", manageOnly: true },
  ],
  triaged: [
    { label: "Start investigation", status: "investigating" },
    { label: "Request info", status: "awaiting_info" },
    { label: "Resolve", status: "resolved" },
    { label: "Close", status: "closed", manageOnly: true },
  ],
  investigating: [
    { label: "Request info", status: "awaiting_info" },
    { label: "Resolve", status: "resolved" },
    { label: "Close", status: "closed", manageOnly: true },
  ],
  awaiting_info: [
    { label: "Resume", status: "investigating" },
    { label: "Resolve", status: "resolved" },
    { label: "Close", status: "closed", manageOnly: true },
  ],
  resolved: [
    { label: "Reopen", status: "investigating" },
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

function actionsFor(
  status: string,
  role: string | undefined,
  userId: number | string | undefined,
  assignedTo: number | null | undefined
): Transition[] {
  const actions = NEXT[status] ?? []
  if (role === "ADMIN" || role === "SUPER_ADMIN") return actions
  if (role !== "ANALYST" || userId == null) return []
  // The PATCH route only lets an analyst update a case they own.
  if (assignedTo != null && String(assignedTo) !== String(userId)) return []
  return actions.filter((action) => !action.manageOnly)
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
  const [reportId, setReportId] = React.useState("")
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

  async function selfAssign() {
    if (pending || me?.id == null) return
    setPending("assign")
    try {
      setItem(await dnsnetraApi.updateCase(publicId, { assigned_to: me.id }))
      toast.success("Case assigned to you.")
    } catch (err) {
      toast.error(errorMessage(err, "Assignment failed."))
    } finally {
      setPending(null)
    }
  }

  async function linkReport() {
    if (!reportId.trim() || pending) return
    setPending("report")
    try {
      setItem(await dnsnetraApi.linkCaseReport(publicId, reportId.trim()))
      setReportId("")
      toast.success("Report linked.")
    } catch (err) {
      toast.error(errorMessage(err, "Could not link report."))
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

  const actions = actionsFor(item.status, me?.role, me?.id, item.assigned_to)
  const canResolve = actions.some((action) => action.status === "resolved")
  const canComment =
    me?.role === "ADMIN" || me?.role === "SUPER_ADMIN" || me?.role === "ANALYST"
  const canWrite = canComment
  const canManage = me?.role === "ADMIN" || me?.role === "SUPER_ADMIN"
  const isMine =
    me?.id != null && item.assigned_to != null && String(item.assigned_to) === String(me.id)
  const canSelfAssign =
    canWrite && me?.id != null && !isMine && (item.assigned_to == null || canManage)
  const assignee = isMine
    ? "Assigned to you"
    : item.assigned_to != null
      ? `Assigned to user #${item.assigned_to}`
      : "Unassigned"

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
          <span className="text-xs text-muted-foreground">{assignee}</span>
          <Badge variant="outline">{item.priority}</Badge>
          <Badge variant="outline">{item.status}</Badge>
        </div>
      </div>

      {(actions.length > 0 || canSelfAssign) && (
        <div className="flex flex-wrap items-center gap-2">
          {canSelfAssign && (
            <Button size="sm" variant="outline" onClick={() => void selfAssign()}
                    disabled={pending !== null}>
              {pending === "assign" ? "Working…" : "Assign to me"}
            </Button>
          )}
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
          {canComment && (
            <div className="flex gap-2">
              <Input value={comment} onChange={(e) => setComment(e.target.value)}
                     placeholder="Add a comment" aria-label="Comment" disabled={pending !== null} />
              <Button size="sm" onClick={() => void addComment()} disabled={pending !== null}>
                {pending === "comment" ? "Working…" : "Comment"}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm">Linked reports</CardTitle></CardHeader>
        <CardContent className="flex flex-col gap-3">
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
          {canWrite && (
            <div className="flex gap-2">
              <Input value={reportId} onChange={(e) => setReportId(e.target.value)}
                     placeholder="RPT-2026-000001" aria-label="Report ID" disabled={pending !== null} />
              <Button size="sm" onClick={() => void linkReport()}
                      disabled={pending !== null || !reportId.trim()}>
                {pending === "report" ? "Working…" : "Link report"}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
