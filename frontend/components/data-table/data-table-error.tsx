"use client"

import * as React from "react"
import { AlertCircleIcon, RotateCcwIcon } from "lucide-react"
import { Button } from "@/components/ui/button"

export interface DataTableErrorProps {
  error?: string | Error | null
  onRetry?: () => void
}

export function DataTableError({
  error,
  onRetry,
}: DataTableErrorProps) {
  const errorMessage =
    typeof error === "string"
      ? error
      : error?.message ?? "An unexpected error occurred while loading telemetry data."

  return (
    <div className="flex min-h-[260px] flex-col items-center justify-center p-8 text-center animate-in fade-in-50 duration-200">
      <div className="flex size-10 items-center justify-center rounded-full bg-destructive/10 text-destructive ring-1 ring-destructive/20 mb-3">
        <AlertCircleIcon className="size-5" />
      </div>
      <h3 className="text-sm font-semibold text-foreground tracking-tight">
        Unable to load data
      </h3>
      <p className="mt-1 max-w-md text-xs text-muted-foreground leading-normal font-mono break-all">
        {errorMessage}
      </p>
      {onRetry && (
        <div className="mt-4">
          <Button
            variant="outline"
            size="sm"
            onClick={onRetry}
            className="h-8 gap-1.5 text-xs font-normal"
          >
            <RotateCcwIcon className="size-3" />
            <span>Retry</span>
          </Button>
        </div>
      )}
    </div>
  )
}
