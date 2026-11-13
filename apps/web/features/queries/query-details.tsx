"use client"

import * as React from "react"
import type { QueryItem } from "@/lib/data-table/api-client"
import { formatDnsnetraTimestamp } from "@/lib/data-table/formatters"
import { DataTableStatus } from "@/components/data-table/data-table-status"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  CalendarIcon,
  GlobeIcon,
  UsersIcon,
  ArrowRightIcon,
} from "lucide-react"
import type { EntityIdentifier } from "@/lib/data-table/types"

export interface QueryDetailsProps {
  query?: QueryItem | null
  queryId: string
  onInspectEntity?: (entity: EntityIdentifier) => void
  onClose?: () => void
}

export function QueryDetails({
  query,
  queryId,
  onInspectEntity,
}: QueryDetailsProps) {
  if (!query) {
    return (
      <div className="flex flex-col items-center justify-center p-8 text-center text-xs text-muted-foreground font-mono">
        Query record #{queryId} forensic event payload loaded from historical telemetry logs.
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-6 py-2">
      {/* 1. Classification & Time Scope */}
      <div className="rounded-md border border-border/80 bg-background p-4 flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Query Evaluation Verdict
          </span>
          <DataTableStatus status={query.final_label} />
        </div>

        <div className="flex items-center gap-2 pt-2 border-t border-border/60 text-xs">
          <CalendarIcon className="size-3.5 text-muted-foreground" />
          <span className="text-muted-foreground">Captured At:</span>
          <span className="font-mono text-foreground font-medium">
            {formatDnsnetraTimestamp(query.timestamp)}
          </span>
        </div>
      </div>

      {/* 2. Primary Associated Entities */}
      <div className="flex flex-col gap-3">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Associated Telemetry Entities
        </h4>

        {/* Domain Card */}
        <div className="flex items-center justify-between rounded-md border border-border/80 bg-background p-3.5">
          <div className="flex items-center gap-2.5">
            <div className="flex size-8 items-center justify-center rounded-md bg-muted text-muted-foreground">
              <GlobeIcon className="size-4" />
            </div>
            <div className="flex flex-col">
              <span className="text-[11px] text-muted-foreground">Queried Domain</span>
              <span className="font-mono text-xs font-medium text-foreground">
                {query.domain}
              </span>
            </div>
          </div>
          {onInspectEntity && (
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                onInspectEntity({
                  type: "domain",
                  id: query.domain,
                  label: query.domain,
                })
              }
              className="h-7 text-xs gap-1"
            >
              <span>Inspect</span>
              <ArrowRightIcon className="size-3" />
            </Button>
          )}
        </div>

        {/* Client Card */}
        <div className="flex items-center justify-between rounded-md border border-border/80 bg-background p-3.5">
          <div className="flex items-center gap-2.5">
            <div className="flex size-8 items-center justify-center rounded-md bg-muted text-muted-foreground">
              <UsersIcon className="size-4" />
            </div>
            <div className="flex flex-col">
              <span className="text-[11px] text-muted-foreground">Client Endpoint</span>
              <span className="font-mono text-xs font-medium text-foreground">
                {query.client_ip}
              </span>
            </div>
          </div>
          {onInspectEntity && (
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                onInspectEntity({
                  type: "client",
                  id: query.client_ip,
                  label: query.client_ip,
                })
              }
              className="h-7 text-xs gap-1"
            >
              <span>Inspect</span>
              <ArrowRightIcon className="size-3" />
            </Button>
          )}
        </div>
      </div>

      {/* 3. DNS Protocol & Resolution Metadata */}
      <div className="rounded-md border border-border/80 bg-background p-4 flex flex-col gap-3">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          DNS Resolver Protocol Attributes
        </h4>

        <div className="grid grid-cols-2 gap-3 text-xs font-mono">
          <div>
            <span className="text-muted-foreground block text-[11px] font-sans">
              Record Type
            </span>
            <Badge variant="outline" className="mt-1 px-1.5 py-0 uppercase">
              {query.query_type}
            </Badge>
          </div>

          <div>
            <span className="text-muted-foreground block text-[11px] font-sans">
              Response Code
            </span>
            <span className="text-foreground mt-1 inline-block">
              {query.response_code || "NOERROR"}
            </span>
          </div>

          <div>
            <span className="text-muted-foreground block text-[11px] font-sans">
              Intelligence Source
            </span>
            <span className="text-foreground mt-1 inline-block">
              {query.ti_source || "Local Pipeline / Classifier"}
            </span>
          </div>

          <div>
            <span className="text-muted-foreground block text-[11px] font-sans">
              Event Log Sequence
            </span>
            <span className="text-foreground mt-1 inline-block">
              #{query.id}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}
