"use client"

import * as React from "react"
import Link from "next/link"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { dnsnetraApi } from "@/lib/data-table/api-client"
import type { CaseSummary } from "@/lib/reporting/types"

type CaseTab = "my_open" | "unassigned" | "all"

const TABS: Array<{ id: CaseTab; label: string }> = [
  { id: "my_open", label: "My open" },
  { id: "unassigned", label: "Unassigned" },
  { id: "all", label: "All" },
]

const STATUSES = [
  "open",
  "triaged",
  "investigating",
  "awaiting_info",
  "resolved",
  "closed",
]

const PRIORITIES = ["low", "medium", "high", "critical"]

function errorMessage(err: unknown): string {
  return err instanceof Error && err.message ? err.message : "Failed to load cases."
}

export default function CasesPage() {
  const [items, setItems] = React.useState<CaseSummary[]>([])
  const [total, setTotal] = React.useState(0)
  const [hasMore, setHasMore] = React.useState(false)
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)
  const [tab, setTab] = React.useState<CaseTab>("my_open")
  const [status, setStatus] = React.useState("all")
  const [priority, setPriority] = React.useState("all")
  const [showCreate, setShowCreate] = React.useState(false)
  const [creating, setCreating] = React.useState(false)
  const [form, setForm] = React.useState({
    title: "",
    entityType: "",
    entityValue: "",
    priority: "medium",
  })

  const fetchCases = React.useCallback(() => {
    const params: {
      limit: number
      status?: string
      priority?: string
      unassigned?: boolean
      assigned_to_me?: boolean
    } = { limit: 50 }
    if (tab === "my_open") params.assigned_to_me = true
    if (tab === "unassigned") params.unassigned = true
    if (status !== "all") params.status = status
    if (priority !== "all") params.priority = priority

    return dnsnetraApi.listCases(params)
      .then((res) => {
        setItems(res.items)
        setTotal(res.total)
        setHasMore(res.has_more)
        setError(null)
      })
      .catch((err: unknown) => {
        const message = errorMessage(err)
        setError(message)
        toast.error(message)
      })
      .finally(() => setLoading(false))
  }, [tab, status, priority])

  React.useEffect(() => {
    setLoading(true)
    void fetchCases()
  }, [fetchCases])

  const handleRetry = () => {
    setLoading(true)
    setError(null)
    void fetchCases()
  }

  async function createCase(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (creating || !form.title.trim()) return
    setCreating(true)
    try {
      const created = await dnsnetraApi.createCase({
        title: form.title.trim(),
        priority: form.priority,
        entity_type: form.entityType || undefined,
        entity_value: form.entityValue.trim() || undefined,
      })
      toast.success(`Case ${created.public_id} created.`)
      setShowCreate(false)
      setForm({ title: "", entityType: "", entityValue: "", priority: "medium" })
      setLoading(true)
      await fetchCases()
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setCreating(false)
    }
  }

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold tracking-tight">Cases</h2>
          <p className="text-sm text-muted-foreground">Investigations, assignments, and resolutions.</p>
        </div>
        <Button
          size="sm"
          onClick={() => setShowCreate((value) => !value)}
          aria-expanded={showCreate}
        >
          {showCreate ? "Cancel" : "Create case"}
        </Button>
      </div>

      {showCreate && (
        <Card>
          <CardHeader><CardTitle className="text-sm">New case</CardTitle></CardHeader>
          <CardContent>
            <form className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4" onSubmit={createCase}>
              <div className="flex flex-col gap-1">
                <label htmlFor="case-title" className="text-xs font-medium">Title</label>
                <Input
                  id="case-title"
                  value={form.title}
                  onChange={(event) => setForm({ ...form, title: event.target.value })}
                  placeholder="Investigate example.com"
                  required
                />
              </div>
              <div className="flex flex-col gap-1">
                <label htmlFor="case-entity-type" className="text-xs font-medium">Entity type</label>
                <select
                  id="case-entity-type"
                  value={form.entityType}
                  onChange={(event) => setForm({ ...form, entityType: event.target.value })}
                  className="h-8 rounded-lg border border-input bg-transparent px-2.5 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
                >
                  <option value="">None</option>
                  <option value="domain">Domain</option>
                  <option value="client">Client</option>
                  <option value="query">Query</option>
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label htmlFor="case-entity-value" className="text-xs font-medium">Entity value</label>
                <Input
                  id="case-entity-value"
                  value={form.entityValue}
                  onChange={(event) => setForm({ ...form, entityValue: event.target.value })}
                  placeholder="example.com"
                />
              </div>
              <div className="flex flex-col gap-1">
                <label htmlFor="case-priority" className="text-xs font-medium">Priority</label>
                <select
                  id="case-priority"
                  value={form.priority}
                  onChange={(event) => setForm({ ...form, priority: event.target.value })}
                  className="h-8 rounded-lg border border-input bg-transparent px-2.5 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
                >
                  {PRIORITIES.map((option) => (
                    <option key={option} value={option}>{option}</option>
                  ))}
                </select>
              </div>
              <div className="flex items-end gap-2 sm:col-span-2 lg:col-span-4">
                <Button type="submit" size="sm" disabled={creating || !form.title.trim()}>
                  {creating ? "Creating…" : "Create"}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div role="tablist" aria-label="Case queue" className="inline-flex items-center rounded-lg bg-muted p-[3px]">
          {TABS.map((item) => (
            <button
              key={item.id}
              role="tab"
              type="button"
              aria-selected={tab === item.id}
              onClick={() => setTab(item.id)}
              className="rounded-md px-2.5 py-1 text-sm font-medium text-foreground/60 transition-colors hover:text-foreground aria-selected:bg-background aria-selected:text-foreground"
            >
              {item.label}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select
            aria-label="Status filter"
            value={status}
            onChange={(event) => setStatus(event.target.value)}
            className="h-8 rounded-lg border border-input bg-transparent px-2.5 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
          >
            <option value="all">All statuses</option>
            {STATUSES.map((option) => (
              <option key={option} value={option}>{option}</option>
            ))}
          </select>
          <select
            aria-label="Priority filter"
            value={priority}
            onChange={(event) => setPriority(event.target.value)}
            className="h-8 rounded-lg border border-input bg-transparent px-2.5 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
          >
            <option value="all">All priorities</option>
            {PRIORITIES.map((option) => (
              <option key={option} value={option}>{option}</option>
            ))}
          </select>
        </div>
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
