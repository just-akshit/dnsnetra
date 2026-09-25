"use client";

import { AlertCircle, RefreshCw } from "lucide-react";
import * as React from "react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface DataTableErrorProps {
  error: string | Error;
  onRetry?: () => void;
  className?: string;
}

export function DataTableError({
  error,
  onRetry,
  className,
}: DataTableErrorProps) {
  const errorMessage = typeof error === "string" ? error : error.message;

  return (
    <div
      className={cn(
        "flex min-h-[220px] flex-col items-center justify-center p-8 text-center",
        className,
      )}
    >
      <div className="flex size-11 items-center justify-center rounded-full bg-destructive/10 text-destructive mb-3">
        <AlertCircle className="size-5" />
      </div>
      <h3 className="text-sm font-semibold text-foreground">
        Failed to load table data
      </h3>
      <p className="mt-1 max-w-md text-xs text-muted-foreground font-mono">
        {errorMessage || "An unexpected error occurred while querying the server."}
      </p>

      {onRetry && (
        <Button
          variant="outline"
          size="sm"
          onClick={onRetry}
          className="mt-4 h-8 gap-1.5 text-xs cursor-pointer border-destructive/30 hover:bg-destructive/10 hover:text-destructive"
        >
          <RefreshCw className="size-3.5" />
          <span>Retry request</span>
        </Button>
      )}
    </div>
  );
}
