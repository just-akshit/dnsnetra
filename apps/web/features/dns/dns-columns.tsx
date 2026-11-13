"use client"

import * as React from "react"
import { Badge } from "@/components/ui/badge"
import { createDnsnetraColumnHelper } from "@/lib/data-table/features"
import { formatDnsnetraTimestamp } from "@/lib/data-table/formatters"
import type { DnsDomainItem } from "@/lib/data-table/api-client"
import { DataTableEntity } from "@/components/data-table/data-table-entity"
import type { EntityIdentifier } from "@/lib/data-table/types"

const columnHelper = createDnsnetraColumnHelper<DnsDomainItem>()

export interface DnsColumnOptions {
  onEntityClick?: (entity: EntityIdentifier) => void
}

export function createDnsColumns(options: DnsColumnOptions = {}) {
  return [
    columnHelper.accessor("registered_domain", {
      id: "registered_domain",
      header: "Domain",
      cell: ({ row, table }) => {
        const meta = table.options.meta as { onEntityClick?: (entity: EntityIdentifier) => void } | undefined
        return (
          <DataTableEntity
            type="domain"
            id={row.original.registered_domain}
            label={row.original.registered_domain}
            onClick={options.onEntityClick ?? meta?.onEntityClick}
          />
        )
      },
    }),

    columnHelper.accessor("domain", {
      id: "domain",
      header: "Query",
      cell: ({ row, table }) => {
        const meta = table.options.meta as { onEntityClick?: (entity: EntityIdentifier) => void } | undefined
        return (
          <DataTableEntity
            type="domain"
            id={row.original.domain}
            label={row.original.domain}
            onClick={options.onEntityClick ?? meta?.onEntityClick}
          />
        )
      },
    }),

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

    columnHelper.accessor("first_seen", {
      id: "first_seen",
      header: "First seen",
      cell: ({ row }) => (
        <span className="font-mono text-xs text-muted-foreground">
          {formatDnsnetraTimestamp(row.original.first_seen)}
        </span>
      ),
    }),

    columnHelper.accessor("last_seen", {
      id: "last_seen",
      header: "Last seen",
      cell: ({ row }) => (
        <span className="font-mono text-xs text-muted-foreground">
          {formatDnsnetraTimestamp(row.original.last_seen)}
        </span>
      ),
    }),

    columnHelper.accessor("client_ip", {
      id: "client_ip",
      header: "Client IP",
      cell: ({ row, table }) => {
        const ip = row.original.client_ip
        if (!ip) return <span className="text-xs text-muted-foreground">—</span>
        const meta = table.options.meta as { onEntityClick?: (entity: EntityIdentifier) => void } | undefined
        return (
          <DataTableEntity
            type="client"
            id={ip}
            label={ip}
            onClick={options.onEntityClick ?? meta?.onEntityClick}
          />
        )
      },
    }),
  ]
}
