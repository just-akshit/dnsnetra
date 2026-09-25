"use client";

import { Database, FilterX, SearchX } from "lucide-react";
import * as React from "react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface DataTableEmptyProps {
  hasSearch?: boolean;
  hasFilters?: boolean;
  onClearSearch?: () => void;
  onClearFilters?: () => void;
  onResetAll?: () => void;
  title?: string;
  description?: string;
  className?: string;
}

export function DataTableEmpty({
  hasSearch = false,
  hasFilters = false,
  onClearSearch,
  onClearFilters,
  onResetAll,
  title,
  description,
  className,
}: DataTableEmptyProps) {
  let defaultTitle = "No records found";
  let defaultDescription = "There is currently no data available in this table.";
  let Icon = Database;

  if (hasSearch && hasFilters) {
    defaultTitle = "No matching records found";
    defaultDescription = "No results match your search query and active filter criteria.";
    Icon = SearchX;
  } else if (hasSearch) {
    defaultTitle = "No search results";
    defaultDescription = "Try adjusting or clearing your search term.";
    Icon = SearchX;
  } else if (hasFilters) {
    defaultTitle = "No filtered records";
    defaultDescription = "No records match the current filter configuration.";
    Icon = FilterX;
  }

  return (
    <div
      className={cn(
        "flex min-h-[220px] flex-col items-center justify-center p-8 text-center",
        className,
      )}
    >
      <div className="flex size-11 items-center justify-center rounded-full bg-muted/60 text-muted-foreground mb-3">
        <Icon className="size-5" />
      </div>
      <h3 className="text-sm font-semibold text-foreground">
        {title ?? defaultTitle}
      </h3>
      <p className="mt-1 max-w-sm text-xs text-muted-foreground">
        {description ?? defaultDescription}
      </p>

      {(hasSearch || hasFilters || onResetAll) && (
        <div className="mt-4 flex items-center gap-2">
          {onResetAll && (
            <Button
              variant="outline"
              size="sm"
              onClick={onResetAll}
              className="h-8 text-xs cursor-pointer"
            >
              Reset Everything
            </Button>
          )}
          {hasSearch && onClearSearch && (
            <Button
              variant="secondary"
              size="sm"
              onClick={onClearSearch}
              className="h-8 text-xs cursor-pointer"
            >
              Clear Search
            </Button>
          )}
          {hasFilters && onClearFilters && (
            <Button
              variant="secondary"
              size="sm"
              onClick={onClearFilters}
              className="h-8 text-xs cursor-pointer"
            >
              Clear Filters
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
