"use client"

import * as React from "react"
import { cn } from "cn"
import type { EntityType } from "@/lib/data-table/types"

export interface DataTableEntityProps {
  type: EntityType
  id: string
  label?: string
  className?: string
  onClick?: (entity: { type: EntityType; id: string; label?: string }) => void
  isClickable?: boolean
}

/**
 * Standard DNSNetra primary clickable entity component.
 * Renders domain, client IP, or query identifier as clean monospace/standard text.
 * On hover: subtle underline and slight brightness shift without distracting bright colors.
 * Accessible with keyboard navigation (Enter/Space).
 */
export function DataTableEntity({
  type,
  id,
  label,
  className,
  onClick,
  isClickable = true,
}: DataTableEntityProps) {
  const displayLabel = label ?? id

  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation() // Prevent row selection or other clicks
    if (onClick && isClickable) {
      onClick({ type, id, label: displayLabel })
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (isClickable && (e.key === "Enter" || e.key === " ")) {
      e.preventDefault()
      e.stopPropagation()
      onClick?.({ type, id, label: displayLabel })
    }
  }

  if (!isClickable || !onClick) {
    return (
      <span
        className={cn(
          "font-mono font-medium text-foreground tracking-tight select-text",
          className
        )}
      >
        {displayLabel}
      </span>
    )
  }

  return (
    <button
      type="button"
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      title={`Inspect ${type}: ${displayLabel}`}
      className={cn(
        "group inline-flex items-center text-left font-mono font-medium text-foreground tracking-tight",
        "cursor-pointer select-text rounded-xs outline-none transition-colors",
        "hover:text-primary hover:underline hover:underline-offset-3",
        "focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
        className
      )}
    >
      <span>{displayLabel}</span>
    </button>
  )
}
