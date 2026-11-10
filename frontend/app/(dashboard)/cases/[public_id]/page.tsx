"use client"

import * as React from "react"
import { useParams } from "next/navigation"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { dnsnetraApi } from "@/lib/data-table/api-client"
import type { CaseDetail } from "@/lib/reporting/types"

const NEXT: Record<string, { label: string; status: string }[]> = {
  open: [{ label: "Start triage", status: "triaged" }],
  triaged: [{ label: "Start investigation", status: "investigating" }],
  investigating: [{ label: "Resolve", status: "resolved" }],
  awaiting_info: [{ label: "Resume", status: "investigating" }],
  resolved: [{ label: "Close", status: "closed" }],
  closed: [],
}

export default function CaseDetailPage() {
  const params = useParams<{ public_id: string }>()
  const publicId = decodeURIComponent(params.public_id)
  const [item, setItem] = React.useState<CaseDetail | null>(null)
  const [comment, setComment] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)

  React.useEffect(() => {
    dnsnetraApi.getCase(publicId)
      .then(setItem)
      .catch(() => {
        setError("Failed to load case.")
        toast.error("Failed to load case.")
      })
  }, [publicId])

  async function move(status: string) {
    try {
      const payload = status === "resolved"
        ? { status, resolution: "true_positive" }
        : { status }
      const updated = await dnsnetraApi.updateCase(publicId, payload)
      setItem(updated)
      toast.success(`Case moved to ${status}.`)
    } catch {
      toast.error("Case update failed.")
    }
  }

  async function addComment() {
    if (!comment.trim()) return
    try {
      setItem(await dnsnetraApi.commentCase(publicId, comment))
      setComment("")
    } catch {
      toast.error("Comment failed.")
    }
  }

  if (!item) {
    return (
      <p role={error ? "alert" : undefined} className={`p-6 text-sm ${error ? "text-destructive" : "text-muted-foreground"}`}>
        {error ?? "Loading case…"}
      </p>
    )
  }

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

      <div className="flex flex-wrap gap-2">
        {(NEXT[item.status] ?? []).map((action) => (
          <Button key={action.status} size="sm" onClick={() => move(action.status)}>
            {action.label}
          </Button>
        ))}
      </div>

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
                  <span className="ml-2">{event.kind}</span>
                  {event.body && <span className="ml-2 text-muted-foreground">{event.body}</span>}
                </li>
              ))}
            </ol>
          )}
          <div className="flex gap-2">
            <Input value={comment} onChange={(e) => setComment(e.target.value)}
                   placeholder="Add a comment" aria-label="Comment" />
            <Button size="sm" onClick={addComment}>Comment</Button>
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
                <li key={report} className="font-mono text-xs">{report}</li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
