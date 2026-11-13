"use client"

import * as React from "react"
import { SearchXIcon, InboxIcon } from "lucide-react"
import { Button } from "@/components/ui/button"

export interface DataTableEmptyProps {
  title?: string
  description?: string
  isFiltered?: boolean
  onClearFilters?: () => void
}

export function DataTableEmpty({
  title,
  description,
  isFiltered = false,
  onClearFilters,
}: DataTableEmptyProps) {
  const defaultTitle = isFiltered
    ? "No matching records found"
    : "No records found"

  const defaultDescription = isFiltered
    ? "No records match the active search or filter criteria. Try adjusting your parameters."
    : "This collection currently has no recorded events or entities."

  return (
    <div className="flex min-h-[260px] flex-col items-center justify-center p-8 text-center animate-in fade-in-50 duration-200">
      <div className="flex size-10 items-center justify-center rounded-full bg-muted/60 text-muted-foreground ring-1 ring-border/50 mb-3">
        {isFiltered ? (
          <SearchXIcon className="size-5" />
        ) : (
          <InboxIcon className="size-5" />
        )}
      </div>
      <h3 className="text-sm font-semibold text-foreground tracking-tight">
        {title ?? defaultTitle}
      </h3>
      <p className="mt-1 max-w-sm text-xs text-muted-foreground leading-normal">
        {description ?? defaultDescription}
      </p>
      {isFiltered && onClearFilters && (
        <div className="mt-4">
          <Button
            variant="outline"
            size="sm"
            onClick={onClearFilters}
            className="h-8 text-xs font-normal"
          >
            Clear Filters
          </Button>
        </div>
      )}
    </div>
  )
}
