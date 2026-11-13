"use client"

import * as React from "react"
import { Checkbox } from "@/components/ui/checkbox"
import { Badge } from "@/components/ui/badge"
import { createDnsnetraColumnHelper } from "@/lib/data-table/features"
import { formatDnsnetraTimestamp } from "@/lib/data-table/formatters"
import type { QueryItem } from "@/lib/data-table/api-client"
import { DataTableEntity } from "@/components/data-table/data-table-entity"
import { DataTableStatus } from "@/components/data-table/data-table-status"
import { DataTableRowActions } from "@/components/data-table/data-table-row-actions"
import { toast } from "sonner"
import type { EntityIdentifier, DnsnetraTableMeta } from "@/lib/data-table/types"

const columnHelper = createDnsnetraColumnHelper<QueryItem>()

export interface QueryColumnOptions {
  onEntityClick?: (entity: EntityIdentifier) => void
}

export function createQueryColumns(options: QueryColumnOptions = {}) {
  return [
    // 1. Checkbox
    columnHelper.display({
      id: "select",
      header: ({ table }) => (
        <div className="flex items-center justify-center">
          <Checkbox
            checked={table.getIsAllPageRowsSelected()}
            onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
            aria-label="Select all queries on page"
          />
        </div>
      ),
      cell: ({ row }) => (
        <div className="flex items-center justify-center">
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(value) => row.toggleSelected(!!value)}
            aria-label={`Select query ${row.original.id}`}
          />
        </div>
      ),
      enableSorting: false,
      enableHiding: false,
    }),

    // 2. Timestamp (Strict YYYY-MM-DD HH:mm:ss, Clickable to open Query Event Detail)
    columnHelper.accessor("timestamp", {
      id: "timestamp",
      header: "Timestamp",
      cell: ({ row, table }) => {
        const query = row.original
        const meta = table.options.meta as DnsnetraTableMeta | undefined
        const handleEntityClick = options.onEntityClick ?? meta?.onEntityClick

        return (
          <DataTableEntity
            type="query"
            id={String(query.id)}
            label={formatDnsnetraTimestamp(query.timestamp)}
            onClick={() =>
              handleEntityClick?.({
                type: "query",
                id: String(query.id),
                label: `Query #${query.id} (${query.domain})`,
                data: query,
              })
            }
          />
        )
      },
      enableHiding: false,
    }),

    // 3. Client IP (Interactive entity)
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
    }),

    // 4. Domain Name (Interactive entity)
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
    }),

    // 5. Query Record Type (Badge)
    columnHelper.accessor("query_type", {
      id: "query_type",
      header: "Type",
      cell: ({ row }) => (
        <Badge
          variant="outline"
          className="font-mono text-[10px] px-1.5 py-0 uppercase bg-muted/40 text-muted-foreground"
        >
          {row.original.query_type}
        </Badge>
      ),
    }),

    // 6. Final Verdict / Label
    columnHelper.accessor("final_label", {
      id: "verdict",
      header: "Verdict",
      cell: ({ row }) => (
        <DataTableStatus status={row.original.final_label} />
      ),
    }),

    // 7. Intelligence Source
    columnHelper.accessor("ti_source", {
      id: "source",
      header: "Source",
      cell: ({ row }) => (
        <span className="font-mono text-xs text-muted-foreground">
          {row.original.ti_source || "—"}
        </span>
      ),
    }),

    // 8. Row Actions
    columnHelper.display({
      id: "actions",
      header: () => null,
      cell: ({ row, table }) => {
        const query = row.original
        const meta = table.options.meta as DnsnetraTableMeta | undefined
        const handleEntityClick = options.onEntityClick ?? meta?.onEntityClick

        return (
          <DataTableRowActions
            actions={[
              {
                id: "inspect-query",
                label: "Inspect Query Event",
                onClick: () =>
                  handleEntityClick?.({
                    type: "query",
                    id: String(query.id),
                    label: `Query #${query.id}`,
                    data: query,
                  }),
              },
              {
                id: "inspect-domain",
                label: `Inspect ${query.domain}`,
                onClick: () =>
                  handleEntityClick?.({
                    type: "domain",
                    id: query.domain,
                    label: query.domain,
                  }),
              },
              {
                id: "inspect-client",
                label: `Inspect ${query.client_ip}`,
                onClick: () =>
                  handleEntityClick?.({
                    type: "client",
                    id: query.client_ip,
                    label: query.client_ip,
                  }),
              },
              {
                id: "copy-domain",
                label: "Copy Domain",
                onClick: () => {
                  navigator.clipboard.writeText(query.domain)
                  toast.success(`Copied ${query.domain}`)
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
