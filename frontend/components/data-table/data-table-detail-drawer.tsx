"use client"

import * as React from "react"
import Link from "next/link"
import { ArrowUpRightIcon, AlertCircleIcon, RotateCcwIcon } from "lucide-react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog"
import { Button, buttonVariants } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "cn"
import type { EntityIdentifier } from "@/lib/data-table/types"

export interface DataTableDetailDrawerProps {
  entity: EntityIdentifier | null
  open: boolean
  onOpenChange: (open: boolean) => void
  loading?: boolean
  error?: string | Error | null
  onRetry?: () => void
  children?: React.ReactNode
}

/**
 * Maps entity type and ID to the canonical profile route in DNSNetra.
 */
function getProfileUrl(entity: EntityIdentifier | null): string | null {
  if (!entity) return null
  switch (entity.type) {
    case "domain":
      return `/domains/${encodeURIComponent(entity.id)}`
    case "client":
      return `/clients/${encodeURIComponent(entity.id)}`
    case "query":
      return `/queries?search=${encodeURIComponent(entity.id)}`
    case "daily_review":
      return `/daily-review?search=${encodeURIComponent(entity.id)}`
    default:
      return null
  }
}

export function DataTableDetailDrawer({
  entity,
  open,
  onOpenChange,
  loading = false,
  error = null,
  onRetry,
  children,
}: DataTableDetailDrawerProps) {
  const profileUrl = getProfileUrl(entity)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="w-[calc(100vw-2rem)] sm:max-w-xl max-h-[85vh] p-0 flex flex-col gap-0 border border-border bg-card shadow-2xl overflow-hidden">
        {/* Header */}
        <DialogHeader className="px-6 py-5 border-b border-border/70 bg-muted/30">
          <div className="flex items-center gap-2 mb-1.5">
            <Badge
              variant="outline"
              className="text-[10px] uppercase font-mono tracking-wider px-1.5 py-0 bg-background text-muted-foreground"
            >
              {entity?.type ?? "Entity"} Preview
            </Badge>
          </div>
          <DialogTitle className="text-lg font-mono font-semibold tracking-tight text-foreground truncate select-text">
            {entity?.label ?? entity?.id ?? "Entity Inspection"}
          </DialogTitle>
          <DialogDescription className="text-xs text-muted-foreground font-sans">
            Forensic metadata, telemetry metrics, and observed intelligence preview.
          </DialogDescription>
        </DialogHeader>

        {/* Content Body with Loading & Error States */}
        <div className="flex-1 overflow-y-auto px-6 py-5">
          {loading ? (
            <div className="flex flex-col gap-4 animate-pulse">
              <div className="grid grid-cols-2 gap-3">
                <Skeleton className="h-16 rounded-md bg-muted" />
                <Skeleton className="h-16 rounded-md bg-muted" />
              </div>
              <Skeleton className="h-28 rounded-md bg-muted" />
              <Skeleton className="h-44 rounded-md bg-muted" />
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center p-8 text-center min-h-[220px]">
              <div className="flex size-10 items-center justify-center rounded-full bg-destructive/10 text-destructive mb-3">
                <AlertCircleIcon className="size-5" />
              </div>
              <p className="text-xs text-muted-foreground font-mono mb-4">
                {typeof error === "string" ? error : error.message}
              </p>
              {onRetry && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={onRetry}
                  className="h-8 gap-1.5 text-xs font-normal"
                >
                  <RotateCcwIcon className="size-3" />
                  <span>Retry</span>
                </Button>
              )}
            </div>
          ) : (
            children
          )}
        </div>

        {/* Footer with "Full Profile" Action and Dismiss */}
        <DialogFooter className="border-t border-border/80 px-6 py-3.5 bg-muted/20 flex flex-row items-center justify-between sm:justify-between">
          <span className="text-xs text-muted-foreground hidden sm:inline">
            Deep forensic investigation
          </span>
          <div className="flex items-center gap-2 ml-auto">
            <DialogClose
              render={
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 text-xs font-normal"
                />
              }
            >
              Close
            </DialogClose>
            {profileUrl && (
              <Link
                href={profileUrl}
                onClick={() => onOpenChange(false)}
                className={cn(
                  buttonVariants({ variant: "default", size: "sm" }),
                  "h-8 gap-1.5 text-xs font-medium"
                )}
              >
                <span>Full Profile</span>
                <ArrowUpRightIcon className="size-3.5" />
              </Link>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
