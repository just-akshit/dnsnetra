"use client"

import * as React from "react"
import { Checkbox } from "@/components/ui/checkbox"
import { createDnsnetraColumnHelper } from "@/lib/data-table/features"
import {
  formatDnsnetraTimestamp,
  formatNumber,
} from "@/lib/data-table/formatters"
import type { ClientItem } from "@/lib/data-table/api-client"
import { DataTableEntity } from "@/components/data-table/data-table-entity"
import { DataTableRowActions } from "@/components/data-table/data-table-row-actions"
import { toast } from "sonner"
import type { EntityIdentifier, DnsnetraTableMeta } from "@/lib/data-table/types"
import { cn } from "cn"

const columnHelper = createDnsnetraColumnHelper<ClientItem>()

export interface ClientColumnOptions {
  onEntityClick?: (entity: EntityIdentifier) => void
}

export function createClientColumns(options: ClientColumnOptions = {}) {
  return [
    // 1. Selection checkbox
    columnHelper.display({
      id: "select",
      header: ({ table }) => (
        <div className="flex items-center justify-center">
          <Checkbox
            checked={table.getIsAllPageRowsSelected()}
            onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
            aria-label="Select all clients on page"
          />
        </div>
      ),
      cell: ({ row }) => (
        <div className="flex items-center justify-center">
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(value) => row.toggleSelected(!!value)}
            aria-label={`Select client ${row.original.client_ip}`}
          />
        </div>
      ),
      enableSorting: false,
      enableHiding: false,
    }),

    // 2. Primary Entity: Client IP
    columnHelper.accessor("client_ip", {
      id: "client_ip",
      header: "Client IP",
      cell: ({ row, table }) => {
        const ip = row.original.client_ip
        const meta = table.options.meta as DnsnetraTableMeta | undefined
        const handleEntityClick = options.onEntityClick ?? meta?.onEntityClick

        return (
          <DataTableEntity
            type="client"
            id={ip}
            label={ip}
            onClick={handleEntityClick}
          />
        )
      },
      enableHiding: false,
    }),

    // 3. Total Queries (Right-aligned numeric)
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

    // 4. Unique Domains (Right-aligned numeric)
    columnHelper.accessor("unique_domains", {
      id: "unique_domains",
      header: () => <div className="text-right">Domains</div>,
      cell: ({ row }) => (
        <div className="text-right font-mono tabular-nums text-foreground">
          {formatNumber(row.original.unique_domains)}
        </div>
      ),
      meta: { align: "right" },
    }),

    // 5. Malicious / Non-Benign Queries (Right-aligned numeric, highlighted in amber/red if >0)
    columnHelper.accessor("malicious_queries", {
      id: "malicious_queries",
      header: () => <div className="text-right">Threats</div>,
      cell: ({ row }) => {
        const count = row.original.malicious_queries
        return (
          <div
            className={cn(
              "text-right font-mono tabular-nums",
              count > 0
                ? "text-rose-600 dark:text-rose-400 font-semibold"
                : "text-muted-foreground"
            )}
          >
            {count > 0 ? formatNumber(count) : "—"}
          </div>
        )
      },
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
        const ip = row.original.client_ip
        const meta = table.options.meta as DnsnetraTableMeta | undefined
        const handleEntityClick = options.onEntityClick ?? meta?.onEntityClick

        return (
          <DataTableRowActions
            actions={[
              {
                id: "inspect",
                label: "Preview Endpoint Overview",
                onClick: () =>
                  handleEntityClick?.({
                    type: "client",
                    id: ip,
                    label: ip,
                  }),
              },
              {
                id: "full-profile",
                label: "View Full Profile",
                onClick: () => {
                  window.location.href = `/clients/${encodeURIComponent(ip)}`
                },
              },
              {
                id: "copy",
                label: "Copy IP",
                onClick: () => {
                  navigator.clipboard.writeText(ip)
                  toast.success(`Copied ${ip} to clipboard`)
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
