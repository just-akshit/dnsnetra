"use client"

import * as React from "react"
import { Checkbox } from "@/components/ui/checkbox"
import { createDnsnetraColumnHelper } from "@/lib/data-table/features"
import {
  formatDnsnetraTimestamp,
  formatNumber,
} from "@/lib/data-table/formatters"
import type { DomainItem } from "@/lib/data-table/api-client"
import { DataTableEntity } from "@/components/data-table/data-table-entity"
import { DataTableStatus } from "@/components/data-table/data-table-status"
import { DataTableRowActions } from "@/components/data-table/data-table-row-actions"
import { toast } from "sonner"
import type { EntityIdentifier, DnsnetraTableMeta } from "@/lib/data-table/types"

const columnHelper = createDnsnetraColumnHelper<DomainItem>()

export interface DomainColumnOptions {
  onEntityClick?: (entity: EntityIdentifier) => void
}

export function createDomainColumns(options: DomainColumnOptions = {}) {
  return [
    // 1. Row selection checkbox
    columnHelper.display({
      id: "select",
      header: ({ table }) => (
        <div className="flex items-center justify-center">
          <Checkbox
            checked={table.getIsAllPageRowsSelected()}
            onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
            aria-label="Select all domains on page"
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

    // 2. Primary Entity: Domain (Clickable)
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

    // 3. Verdict
    columnHelper.accessor("latest_verdict", {
      id: "verdict",
      header: "Verdict",
      cell: ({ row }) => (
        <DataTableStatus status={row.original.latest_verdict ?? "clean"} />
      ),
    }),

    // 4. Query Count (Right-aligned numeric)
    columnHelper.accessor("total_queries", {
      id: "total_queries",
      header: () => <div className="text-right">Queries</div>,
      cell: ({ row }) => (
        <div className="text-right font-mono tabular-nums text-foreground">
          {formatNumber(row.original.total_queries)}
        </div>
      ),
      meta: { align: "right" },
    }),

    // 5. Unique Clients (Right-aligned numeric)
    columnHelper.accessor("unique_clients", {
      id: "unique_clients",
      header: () => <div className="text-right">Clients</div>,
      cell: ({ row }) => (
        <div className="text-right font-mono tabular-nums text-foreground">
          {formatNumber(row.original.unique_clients)}
        </div>
      ),
      meta: { align: "right" },
    }),

    // 6. First Seen (Strict YYYY-MM-DD HH:mm:ss)
    columnHelper.accessor("first_seen", {
      id: "first_seen",
      header: "First Seen",
      cell: ({ row }) => (
        <span className="font-mono text-muted-foreground text-xs">
          {formatDnsnetraTimestamp(row.original.first_seen)}
        </span>
      ),
    }),

    // 7. Last Seen (Strict YYYY-MM-DD HH:mm:ss)
    columnHelper.accessor("last_seen", {
      id: "last_seen",
      header: "Last Seen",
      cell: ({ row }) => (
        <span className="font-mono text-muted-foreground text-xs">
          {formatDnsnetraTimestamp(row.original.last_seen)}
        </span>
      ),
    }),

    // 8. Row Actions
    columnHelper.display({
      id: "actions",
      header: () => null,
      cell: ({ row, table }) => {
        const domain = row.original.domain
        const meta = table.options.meta as DnsnetraTableMeta | undefined
        const handleEntityClick = options.onEntityClick ?? meta?.onEntityClick

        return (
          <DataTableRowActions
            actions={[
              {
                id: "inspect",
                label: "Preview Forensic Overview",
                onClick: () =>
                  handleEntityClick?.({
                    type: "domain",
                    id: domain,
                    label: domain,
                  }),
              },
              {
                id: "full-profile",
                label: "View Full Profile",
                onClick: () => {
                  window.location.href = `/domains/${encodeURIComponent(domain)}`
                },
              },
              {
                id: "copy",
                label: "Copy Domain",
                onClick: () => {
                  navigator.clipboard.writeText(domain)
                  toast.success(`Copied ${domain} to clipboard`)
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
