"use client"

import * as React from "react"
import { z } from "zod"
import { DataTable as UnifiedDataTable } from "./data-table/data-table"
import { dnsnetraTableFeatures } from "@/lib/data-table/features"
import { createColumnHelper } from "@tanstack/react-table"
import { Checkbox } from "@/components/ui/checkbox"
import { Badge } from "@/components/ui/badge"
import { DataTableStatus } from "./data-table/data-table-status"
import { DataTableEntity } from "./data-table/data-table-entity"
import type { DataTableProps } from "@/lib/data-table/types"

export * from "./data-table/index"

export const schema = z.object({
  id: z.number(),
  header: z.string(),
  type: z.string(),
  status: z.string(),
  target: z.string(),
  limit: z.string(),
  reviewer: z.string(),
})

type LegacyItem = z.infer<typeof schema>
const columnHelper = createColumnHelper<typeof dnsnetraTableFeatures, LegacyItem>()

const defaultLegacyColumns = [
  columnHelper.display({
    id: "select",
    header: ({ table }) => (
      <div className="flex items-center justify-center">
        <Checkbox
          checked={table.getIsAllPageRowsSelected()}
          onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
          aria-label="Select all rows"
        />
      </div>
    ),
    cell: ({ row }) => (
      <div className="flex items-center justify-center">
        <Checkbox
          checked={row.getIsSelected()}
          onCheckedChange={(value) => row.toggleSelected(!!value)}
          aria-label="Select row"
        />
      </div>
    ),
    enableSorting: false,
    enableHiding: false,
  }),
  columnHelper.accessor("header", {
    id: "header",
    header: "Domain / Query",
    cell: ({ row }) => (
      <DataTableEntity
        type="domain"
        id={row.original.header}
        label={row.original.header}
      />
    ),
    enableHiding: false,
  }),
  columnHelper.accessor("type", {
    id: "type",
    header: "Record Type",
    cell: ({ row }) => (
      <Badge
        variant="outline"
        className="px-1.5 py-0 text-muted-foreground font-mono text-[10px] uppercase"
      >
        {row.original.type}
      </Badge>
    ),
  }),
  columnHelper.accessor("status", {
    id: "status",
    header: "Status",
    cell: ({ row }) => (
      <DataTableStatus status={row.original.status} />
    ),
  }),
  columnHelper.accessor("target", {
    id: "target",
    header: () => <div className="w-full text-right">Count</div>,
    cell: ({ row }) => (
      <div className="text-right font-mono tabular-nums text-foreground">
        {row.original.target}
      </div>
    ),
    meta: { align: "right" },
  }),
  columnHelper.accessor("limit", {
    id: "limit",
    header: () => <div className="w-full text-right">Score</div>,
    cell: ({ row }) => (
      <div className="text-right font-mono tabular-nums text-foreground">
        {row.original.limit}
      </div>
    ),
    meta: { align: "right" },
  }),
  columnHelper.accessor("reviewer", {
    id: "reviewer",
    header: "Source",
    cell: ({ row }) => (
      <span className="text-muted-foreground font-mono text-xs">
        {row.original.reviewer}
      </span>
    ),
  }),
]

export function DataTable<TData extends object>(
  props:
    | DataTableProps<TData>
    | { data: LegacyItem[]; [key: string]: unknown }
) {
  if ("columns" in props && props.columns) {
    return <UnifiedDataTable {...(props as DataTableProps<TData>)} />
  }

  // Legacy fallback for dashboard page demo data, migrated seamlessly to the unified DataTable system
  return (
    <UnifiedDataTable<LegacyItem>
      tableId="dashboard-telemetry"
      data={(props as { data: LegacyItem[] }).data ?? []}
      columns={defaultLegacyColumns}
      searchPlaceholder="Search telemetry events..."
      showSearch={true}
      tabs={[
        { id: "recent", label: "Recent Queries" },
        { id: "suspicious", label: "Suspicious", count: 23 },
        { id: "blocked", label: "Blocked" },
      ]}
    />
  )
}
