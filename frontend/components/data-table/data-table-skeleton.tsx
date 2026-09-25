"use client"

import * as React from "react"
import { Skeleton } from "@/components/ui/skeleton"
import { TableCell, TableRow } from "@/components/ui/table"

export interface DataTableSkeletonProps {
  columnCount: number
  rowCount?: number
}

export function DataTableSkeleton({
  columnCount,
  rowCount = 10,
}: DataTableSkeletonProps) {
  return (
    <>
      {Array.from({ length: rowCount }).map((_, rowIndex) => (
        <TableRow
          key={`skeleton-row-${rowIndex}`}
          className="border-b border-border/60 hover:bg-transparent"
        >
          {Array.from({ length: columnCount }).map((_, colIndex) => (
            <TableCell key={`skeleton-cell-${rowIndex}-${colIndex}`} className="px-3 py-2.5">
              <Skeleton
                className="h-4 w-full max-w-[85%] rounded-xs bg-muted-foreground/15"
                style={{
                  width:
                    colIndex === 0
                      ? "18px" // checkbox column
                      : colIndex === 1
                      ? `${Math.floor(60 + (rowIndex * 7) % 35)}%` // primary column
                      : `${Math.floor(40 + (rowIndex * 11) % 40)}%`, // other columns
                }}
              />
            </TableCell>
          ))}
        </TableRow>
      ))}
    </>
  )
}
