"use client"

import * as React from "react"
import { FlexRender, type RowModel } from "@tanstack/react-table"
import { TableBody, TableCell, TableRow } from "@/components/ui/table"
import { DataTableSkeleton } from "./data-table-skeleton"
import { DataTableEmpty } from "./data-table-empty"
import { DataTableError } from "./data-table-error"
import type { DnsnetraTableFeatures } from "@/lib/data-table/features"
import type { DnsnetraTableMeta } from "@/lib/data-table/types"
import { cn } from "cn"

export interface DataTableBodyProps<TData extends object> {
  rowModel: RowModel<DnsnetraTableFeatures, TData>
  columnCount: number
  loading?: boolean
  error?: string | Error | null
  onRetry?: () => void
  isFiltered?: boolean
  emptyTitle?: string
  emptyDescription?: string
  onClearFilters?: () => void
}

export function DataTableBody<TData extends object>({
  rowModel,
  columnCount,
  loading = false,
  error = null,
  onRetry,
  isFiltered = false,
  emptyTitle,
  emptyDescription,
  onClearFilters,
}: DataTableBodyProps<TData>) {
  if (loading) {
    return (
      <TableBody>
        <DataTableSkeleton columnCount={columnCount} rowCount={10} />
      </TableBody>
    )
  }

  if (error) {
    return (
      <TableBody>
        <TableRow className="hover:bg-transparent">
          <TableCell colSpan={columnCount} className="p-0">
            <DataTableError error={error} onRetry={onRetry} />
          </TableCell>
        </TableRow>
      </TableBody>
    )
  }

  if (rowModel.rows.length === 0) {
    return (
      <TableBody>
        <TableRow className="hover:bg-transparent">
          <TableCell colSpan={columnCount} className="p-0">
            <DataTableEmpty
              title={emptyTitle}
              description={emptyDescription}
              isFiltered={isFiltered}
              onClearFilters={onClearFilters}
            />
          </TableCell>
        </TableRow>
      </TableBody>
    )
  }

  return (
    <TableBody>
      {rowModel.rows.map((row) => {
        const isSelected = row.getIsSelected()
        return (
          <TableRow
            key={row.id}
            data-state={isSelected ? "selected" : undefined}
            className={cn(
              "border-b border-border/60 transition-colors",
              "hover:bg-muted/40",
              isSelected && "bg-muted/60 hover:bg-muted/75 font-normal"
            )}
          >
            {row.getVisibleCells().map((cell) => {
              const meta = cell.column.columnDef.meta as DnsnetraTableMeta | undefined
              const isRightAlign = meta?.align === "right"

              return (
                <TableCell
                  key={cell.id}
                  className={cn(
                    "px-3 py-2 text-xs text-foreground align-middle whitespace-nowrap",
                    isRightAlign && "text-right tabular-nums"
                  )}
                >
                  <FlexRender cell={cell} />
                </TableCell>
              )
            })}
          </TableRow>
        )
      })}
    </TableBody>
  )
}
