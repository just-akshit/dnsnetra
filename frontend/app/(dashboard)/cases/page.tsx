"use client"

import * as React from "react"
import Link from "next/link"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { dnsnetraApi } from "@/lib/data-table/api-client"
import type { CaseSummary } from "@/lib/reporting/types"

export default function CasesPage() {
  const [items, setItems] = React.useState<CaseSummary[]>([])
  const [loading, setLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)

  React.useEffect(() => {
    dnsnetraApi.listCases({ limit: 50 })
      .then((res) => setItems(res.items))
      .catch(() => {
        setError("Failed to load cases.")
        toast.error("Failed to load cases.")
      })
      .finally(() => setLoading(false))
  }, [])

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
            <p role="alert" className="p-4 text-sm text-destructive">{error}</p>
          ) : items.length === 0 ? (
            <p className="p-4 text-sm text-muted-foreground">No cases yet.</p>
          ) : (
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
          )}
        </CardContent>
      </Card>
    </div>
  )
}
