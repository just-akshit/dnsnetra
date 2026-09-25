"use client"

import * as React from "react"
import { Columns3Icon, ChevronDownIcon, RotateCcwIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import type { ReactTable } from "@tanstack/react-table"
import type { DnsnetraTableFeatures } from "@/lib/data-table/features"

export interface DataTableColumnMenuProps<TData extends object> {
  table: ReactTable<DnsnetraTableFeatures, TData>
  onResetColumns?: () => void
}

export function DataTableColumnMenu<TData extends object>({
  table,
  onResetColumns,
}: DataTableColumnMenuProps<TData>) {
  const hideableColumns = table
    .getAllColumns()
    .filter((col) => col.getCanHide())

  if (hideableColumns.length === 0) return null

  const handleReset = () => {
    table.resetColumnVisibility()
    onResetColumns?.()
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={<Button variant="outline" size="sm" className="h-8 gap-1.5 text-xs font-normal" />}
      >
        <Columns3Icon className="size-3.5" data-icon="inline-start" />
        <span>Columns</span>
        <ChevronDownIcon className="size-3 opacity-60" data-icon="inline-end" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-52">
        <div className="flex items-center justify-between px-2 py-1.5">
          <DropdownMenuLabel className="text-xs font-medium text-muted-foreground p-0">
            Toggle Columns
          </DropdownMenuLabel>
          <button
            type="button"
            onClick={handleReset}
            className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground cursor-pointer"
          >
            <RotateCcwIcon className="size-2.5" />
            <span>Reset</span>
          </button>
        </div>
        <DropdownMenuSeparator />
        {hideableColumns.map((column) => {
          // Format column header name
          const header = column.columnDef.header
          let label = column.id
          if (typeof header === "string") {
            label = header
          }

          return (
            <DropdownMenuCheckboxItem
              key={column.id}
              className="text-xs capitalize"
              checked={column.getIsVisible()}
              onCheckedChange={(value) => column.toggleVisibility(!!value)}
            >
              {label}
            </DropdownMenuCheckboxItem>
          )
        })}
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onClick={handleReset}
          className="text-xs text-muted-foreground justify-center focus:text-foreground cursor-pointer"
        >
          <RotateCcwIcon className="mr-1.5 size-3" />
          Reset to default columns
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
