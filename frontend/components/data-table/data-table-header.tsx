"use client"

import * as React from "react"
import { FlexRender, type HeaderGroup } from "@tanstack/react-table"
import { ArrowUpIcon, ArrowDownIcon, ChevronsUpDownIcon } from "lucide-react"
import { cn } from "cn"
import { TableHead, TableHeader, TableRow } from "@/components/ui/table"
import type { DnsnetraTableFeatures } from "@/lib/data-table/features"
import type { DnsnetraTableMeta } from "@/lib/data-table/types"

export interface DataTableHeaderProps<TData extends object> {
  headerGroups: HeaderGroup<DnsnetraTableFeatures, TData>[]
  stickyHeader?: boolean
}

export function DataTableHeader<TData extends object>({
  headerGroups,
  stickyHeader = false,
}: DataTableHeaderProps<TData>) {
  return (
    <TableHeader
      className={cn(
        "bg-muted/75 border-b border-border/80 transition-colors select-none",
        stickyHeader && "sticky top-0 z-10 backdrop-blur-xs"
      )}
    >
      {headerGroups.map((headerGroup) => (
        <TableRow
          key={headerGroup.id}
          className="border-b border-border/80 hover:bg-transparent"
        >
          {headerGroup.headers.map((header) => {
            const canSort = header.column.getCanSort()
            const isSorted = header.column.getIsSorted()

            // 3-way sort cycle: asc -> desc -> none
            const handleSortClick = (e: React.MouseEvent) => {
              if (!canSort) return
              e.preventDefault()

              if (isSorted === "asc") {
                header.column.toggleSorting(true) // next: desc
              } else if (isSorted === "desc") {
                header.column.clearSorting() // next: clear
              } else {
                header.column.toggleSorting(false) // next: asc
              }
            }

            const ariaSort =
              isSorted === "asc"
                ? "ascending"
                : isSorted === "desc"
                ? "descending"
                : "none"

            return (
              <TableHead
                key={header.id}
                colSpan={header.colSpan}
                aria-sort={canSort ? ariaSort : undefined}
                className={cn(
                  "h-9 px-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground whitespace-nowrap",
                  canSort && "cursor-pointer transition-colors hover:text-foreground"
                )}
                onClick={canSort ? handleSortClick : undefined}
              >
                {header.isPlaceholder ? null : (
                  <div
                    className={cn(
                      "flex items-center gap-1.5",
                      (header.column.columnDef.meta as DnsnetraTableMeta | undefined)?.align === "right" &&
                        "justify-end"
                    )}
                  >
                    <FlexRender header={header} />
                    {canSort && (
                      <span className="inline-flex size-3.5 shrink-0 items-center justify-center">
                        {isSorted === "asc" ? (
                          <ArrowUpIcon className="size-3 text-primary" />
                        ) : isSorted === "desc" ? (
                          <ArrowDownIcon className="size-3 text-primary" />
                        ) : (
                          <ChevronsUpDownIcon className="size-3 text-muted-foreground/40 opacity-0 group-hover:opacity-100 transition-opacity hover:text-muted-foreground" />
                        )}
                      </span>
                    )}
                  </div>
                )}
              </TableHead>
            )
          })}
        </TableRow>
      ))}
    </TableHeader>
  )
}
