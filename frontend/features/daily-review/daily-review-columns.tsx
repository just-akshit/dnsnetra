"use client"

import * as React from "react"
import { Checkbox } from "@/components/ui/checkbox"
import { Badge } from "@/components/ui/badge"
import { createDnsnetraColumnHelper } from "@/lib/data-table/features"
import {
  formatDnsnetraTimestamp,
  formatNumber,
} from "@/lib/data-table/formatters"
import type { DailyReviewItem } from "@/lib/data-table/api-client"
import { DataTableEntity } from "@/components/data-table/data-table-entity"
import { DataTableStatus } from "@/components/data-table/data-table-status"
import { DataTableRowActions } from "@/components/data-table/data-table-row-actions"
import { toast } from "sonner"
import type { EntityIdentifier, DnsnetraTableMeta } from "@/lib/data-table/types"

const columnHelper = createDnsnetraColumnHelper<DailyReviewItem>()

export interface DailyReviewColumnOptions {
  onEntityClick?: (entity: EntityIdentifier) => void
  onPromoteClean?: (domain: string) => void
  onPromoteMalicious?: (domain: string) => void
}

export function createDailyReviewColumns(options: DailyReviewColumnOptions = {}) {
  return [
    // 1. Select
    columnHelper.display({
      id: "select",
      header: ({ table }) => (
        <div className="flex items-center justify-center">
          <Checkbox
            checked={table.getIsAllPageRowsSelected()}
            onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
            aria-label="Select all review items on page"
          />
        </div>
      ),
      cell: ({ row }) => (
        <div className="flex items-center justify-center">
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(value) => row.toggleSelected(!!value)}
            aria-label={`Select domain ${row.original.domain}`}
          />
        </div>
      ),
      enableSorting: false,
      enableHiding: false,
    }),

    // 2. Domain (Clickable entity)
    columnHelper.accessor("domain", {
      id: "domain",
      header: "Domain",
      cell: ({ row, table }) => {
        const domain = row.original.domain
        const meta = table.options.meta as DnsnetraTableMeta | undefined
        const handleEntityClick = options.onEntityClick ?? meta?.onEntityClick

        return (
          <DataTableEntity
            type="domain"
            id={domain}
            label={domain}
            onClick={handleEntityClick}
          />
        )
      },
      enableHiding: false,
    }),

    // 3. Status
    columnHelper.accessor("status", {
      id: "status",
      header: "Review Status",
      cell: ({ row }) => (
        <DataTableStatus status={row.original.status} />
      ),
    }),

    // 4. Review Count
    columnHelper.accessor("review_count", {
      id: "review_count",
      header: () => <div className="text-right">Checks</div>,
      cell: ({ row }) => (
        <div className="text-right font-mono tabular-nums text-foreground">
          {formatNumber(row.original.review_count)}
        </div>
      ),
      meta: { align: "right" },
    }),

    // 5. Reason
    columnHelper.accessor("reason", {
      id: "reason",
      header: "Reason / Trigger",
      cell: ({ row }) => (
        <span className="text-muted-foreground text-xs truncate max-w-[200px] block">
          {row.original.reason || "Periodic heuristic check"}
        </span>
      ),
    }),

    // 6. Last Checked At (Strict timestamp)
    columnHelper.accessor("last_seen_at", {
      id: "last_seen_at",
      header: "Last Seen",
      cell: ({ row }) => (
        <span className="font-mono text-muted-foreground text-xs">
          {formatDnsnetraTimestamp(row.original.last_seen_at)}
        </span>
      ),
    }),

    // 7. Next Check At / Due Status
    columnHelper.accessor("next_check_at", {
      id: "next_check_at",
      header: "Next Check",
      cell: ({ row }) => (
        <div className="flex items-center gap-1.5">
          <span className="font-mono text-muted-foreground text-xs">
            {formatDnsnetraTimestamp(row.original.next_check_at)}
          </span>
          {row.original.is_due && (
            <Badge
              variant="outline"
              className="text-[9px] px-1 py-0 border-amber-500/40 bg-amber-500/10 text-amber-600 font-mono"
            >
              DUE
            </Badge>
          )}
        </div>
      ),
    }),

    // 8. Actions
    columnHelper.display({
      id: "actions",
      header: () => null,
      cell: ({ row, table }) => {
        const item = row.original
        const meta = table.options.meta as DnsnetraTableMeta | undefined
        const handleEntityClick = options.onEntityClick ?? meta?.onEntityClick

        return (
          <DataTableRowActions
            actions={[
              {
                id: "inspect-domain",
                label: "Inspect Domain",
                onClick: () =>
                  handleEntityClick?.({
                    type: "domain",
                    id: item.domain,
                    label: item.domain,
                  }),
              },
              {
                id: "mark-clean",
                label: "Promote to Clean",
                onClick: () => {
                  options.onPromoteClean?.(item.domain)
                  toast.success(`Promoted ${item.domain} to Clean`)
                },
              },
              {
                id: "mark-malicious",
                label: "Flag as Malicious",
                destructive: true,
                onClick: () => {
                  options.onPromoteMalicious?.(item.domain)
                  toast.error(`Flagged ${item.domain} as Malicious`)
                },
              },
              {
                id: "copy",
                label: "Copy Domain",
                onClick: () => {
                  navigator.clipboard.writeText(item.domain)
                  toast.success(`Copied ${item.domain}`)
                },
              },
            ]}
          />
        )
      },
      enableSorting: false,
      enableHiding: false,
    }),
  ]
}
