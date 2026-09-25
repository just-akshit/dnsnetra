"use client"

import * as React from "react"
import {
  ChevronLeftIcon,
  ChevronRightIcon,
  ChevronsLeftIcon,
  ChevronsRightIcon,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import type { ReactTable } from "@tanstack/react-table"
import type { DnsnetraTableFeatures } from "@/lib/data-table/features"

export interface DataTablePaginationProps<TData extends object> {
  table: ReactTable<DnsnetraTableFeatures, TData>
  pageSizeOptions?: number[]
  totalRows?: number
  enableRowSelection?: boolean
}

export function DataTablePagination<TData extends object>({
  table,
  pageSizeOptions = [10, 25, 50, 100],
  totalRows,
  enableRowSelection = true,
}: DataTablePaginationProps<TData>) {
  const { pageIndex, pageSize } = table.state.pagination
  const pageCount = table.getPageCount()

  const selectedCount = table.getSelectedRowModel().rows.length
  const totalCount =
    totalRows !== undefined
      ? totalRows
      : table.getFilteredRowModel().rows.length

  return (
    <div className="flex flex-col-reverse items-center justify-between gap-4 px-2 py-3 sm:flex-row">
      {/* Left: Row Selection Count or Total Records */}
      <div className="flex-1 text-xs text-muted-foreground font-mono">
        {enableRowSelection ? (
          <>
            <span className="font-semibold text-foreground">{selectedCount}</span> of{" "}
            <span className="font-semibold text-foreground">{totalCount}</span> row(s) selected
          </>
        ) : (
          <>
            <span className="font-semibold text-foreground">{totalCount}</span> total rows
          </>
        )}
      </div>

      {/* Right: Page Size Selector, Page Indicator, and Navigation Buttons */}
      <div className="flex flex-wrap items-center gap-6 lg:gap-8">
        {/* Rows per page selector */}
        <div className="flex items-center gap-2">
          <Label htmlFor="data-table-rows-per-page" className="text-xs text-muted-foreground font-normal">
            Rows per page
          </Label>
          <Select
            value={String(pageSize)}
            onValueChange={(value) => table.setPageSize(Number(value))}
          >
            <SelectTrigger
              id="data-table-rows-per-page"
              size="sm"
              className="h-8 w-18 text-xs font-mono"
            >
              <SelectValue placeholder={String(pageSize)} />
            </SelectTrigger>
            <SelectContent side="top">
              <SelectGroup>
                {pageSizeOptions.map((size) => (
                  <SelectItem key={size} value={String(size)} className="text-xs font-mono">
                    {size}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        </div>

        {/* Page X of Y */}
        <div className="flex w-fit items-center justify-center text-xs font-medium text-foreground">
          Page {pageIndex + 1} of {Math.max(1, pageCount)}
        </div>

        {/* Navigation Buttons: First, Previous, Next, Last */}
        <div className="flex items-center gap-1">
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            onClick={() => table.setPageIndex(0)}
            disabled={!table.getCanPreviousPage()}
            aria-label="Go to first page"
          >
            <ChevronsLeftIcon className="size-3.5" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
            aria-label="Go to previous page"
          >
            <ChevronLeftIcon className="size-3.5" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
            aria-label="Go to next page"
          >
            <ChevronRightIcon className="size-3.5" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            onClick={() => table.setPageIndex(pageCount - 1)}
            disabled={!table.getCanNextPage()}
            aria-label="Go to last page"
          >
            <ChevronsRightIcon className="size-3.5" />
          </Button>
        </div>
      </div>
    </div>
  )
}
