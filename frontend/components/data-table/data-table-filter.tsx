"use client"

import { FilterIcon, XCircleIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import type { TableFilterConfig } from "@/lib/data-table/types"

export interface DataTableFilterProps {
  config: TableFilterConfig
  value: string | string[] | undefined
  onChange: (value: string | string[] | undefined) => void
}

export function DataTableFilter({
  config,
  value,
  onChange,
}: DataTableFilterProps) {
  const selectedValues = new Set(
    Array.isArray(value) ? value : value ? [value] : []
  )

  const handleSelect = (optionValue: string) => {
    if (config.isMulti) {
      const next = new Set(selectedValues)
      if (next.has(optionValue)) {
        next.delete(optionValue)
      } else {
        next.add(optionValue)
      }
      const arr = Array.from(next)
      onChange(arr.length ? arr : undefined)
    } else {
      if (selectedValues.has(optionValue)) {
        onChange(undefined)
      } else {
        onChange(optionValue)
      }
    }
  }

  const handleClear = (e: React.MouseEvent) => {
    e.stopPropagation()
    onChange(undefined)
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            variant="outline"
            size="sm"
            className="h-8 border-dashed gap-1.5 text-xs font-normal"
          />
        }
      >
        <FilterIcon className="size-3 text-muted-foreground" />
        <span>{config.title}</span>
        {selectedValues.size > 0 && (
          <>
            <div className="mx-1 h-3.5 w-px bg-border" />
            <Badge
              variant="secondary"
              className="rounded-xs px-1 font-mono text-[10px] font-normal"
            >
              {selectedValues.size === 1
                ? config.options.find((o) => selectedValues.has(o.value))?.label ??
                  selectedValues.size
                : selectedValues.size}
            </Badge>
          </>
        )}
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-48">
        <DropdownMenuLabel className="text-xs font-medium text-muted-foreground px-2 py-1.5">
          {config.title}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {config.options.map((option) => {
          const isSelected = selectedValues.has(option.value)
          return (
            <DropdownMenuCheckboxItem
              key={option.value}
              checked={isSelected}
              onCheckedChange={() => handleSelect(option.value)}
              className="text-xs gap-2"
            >
              {option.icon && (
                <span className="size-3.5 shrink-0 text-muted-foreground">
                  {option.icon}
                </span>
              )}
              <span className="flex-1">{option.label}</span>
              {option.count !== undefined && (
                <span className="font-mono text-[10px] text-muted-foreground">
                  {option.count}
                </span>
              )}
            </DropdownMenuCheckboxItem>
          )
        })}
        {selectedValues.size > 0 && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={handleClear}
              className="text-xs text-muted-foreground justify-center focus:text-foreground cursor-pointer"
            >
              <XCircleIcon className="mr-1.5 size-3" />
              Clear Filter
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
