"use client";

import type { Column, Table } from "@tanstack/react-table";
import {
  Check,
  Columns3,
  Lock,
  Pin,
  Plus,
  RotateCcw,
  Search,
  SlidersHorizontal,
  X,
} from "lucide-react";
import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

interface DataTableViewOptionsProps<TData> {
  table: Table<TData>;
  title?: string;
  variant?: "button" | "add-column" | "icon";
  disabled?: boolean;
  align?: "start" | "center" | "end";
  className?: string;
}

export function DataTableViewOptions<TData>({
  table,
  title,
  variant = "add-column",
  disabled,
  align = "end",
  className,
}: DataTableViewOptionsProps<TData>) {
  const [open, setOpen] = React.useState(false);
  const [search, setSearch] = React.useState("");

  // All columns eligible for display in the column manager (excludes internal utility columns like select / expander)
  const allColumns = React.useMemo(() => {
    return table.getAllColumns().filter((column) => {
      // Exclude purely structural columns like selection checkbox and expander chevron from the picker
      if (column.id === "select" || column.id === "expander") return false;
      return true;
    });
  }, [table]);

  const visibleColumnsCount = React.useMemo(() => {
    return allColumns.filter((col) => col.getIsVisible()).length;
  }, [allColumns]);

  const filteredColumns = React.useMemo(() => {
    if (!search.trim()) return allColumns;
    const q = search.toLowerCase();
    return allColumns.filter((column) => {
      const label = column.columnDef.meta?.label ?? column.id;
      return (
        label.toLowerCase().includes(q) ||
        column.id.toLowerCase().includes(q)
      );
    });
  }, [allColumns, search]);

  const handleToggleColumn = (column: Column<TData, unknown>) => {
    const isRequired =
      !column.getCanHide() || column.columnDef.meta?.required === true;
    if (isRequired) return;

    column.toggleVisibility(!column.getIsVisible());
  };

  const handleShowAll = () => {
    allColumns.forEach((col) => {
      if (col.getCanHide()) col.toggleVisibility(true);
    });
  };

  const handleHideAllOptional = () => {
    allColumns.forEach((col) => {
      const isRequired =
        !col.getCanHide() || col.columnDef.meta?.required === true;
      if (!isRequired) col.toggleVisibility(false);
    });
  };

  const handleReset = () => {
    table.resetColumnVisibility();
  };

  const buttonLabel =
    title ??
    (variant === "add-column"
      ? "+ Add column"
      : `Columns (${visibleColumnsCount}/${allColumns.length})`);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          aria-label="Manage table columns"
          variant="outline"
          size="sm"
          className={cn(
            "h-8 gap-1.5 px-2.5 text-xs font-medium cursor-pointer transition-colors",
            variant === "add-column" && "border-dashed hover:border-primary hover:text-primary",
            className,
          )}
          disabled={disabled}
        >
          {variant === "add-column" ? (
            <Plus className="size-3.5 text-muted-foreground" />
          ) : (
            <Columns3 className="size-3.5 text-muted-foreground" />
          )}
          <span>{buttonLabel}</span>
          {variant !== "add-column" && (
            <Badge
              variant="secondary"
              className="ml-0.5 px-1.5 py-0 text-[10px] font-mono rounded"
            >
              {visibleColumnsCount}/{allColumns.length}
            </Badge>
          )}
        </Button>
      </PopoverTrigger>

      <PopoverContent
        align={align}
        className="w-72 p-0 shadow-lg border border-border/80 bg-popover"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border/60 px-3 py-2 bg-muted/20">
          <div className="flex items-center gap-1.5">
            <Columns3 className="size-3.5 text-primary" />
            <span className="text-xs font-semibold text-foreground">
              Manage Columns
            </span>
          </div>
          <span className="text-[11px] text-muted-foreground font-mono">
            {visibleColumnsCount} of {allColumns.length} visible
          </span>
        </div>

        {/* Search Input */}
        <div className="p-2 border-b border-border/40">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3 text-muted-foreground pointer-events-none" />
            <Input
              placeholder="Search columns..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-7 pl-7 pr-6 text-xs bg-background"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground cursor-pointer"
              >
                <X className="size-3" />
              </button>
            )}
          </div>
        </div>

        {/* Quick Batch Actions */}
        <div className="flex items-center justify-between px-3 py-1 text-[11px] text-muted-foreground bg-muted/10 border-b border-border/30">
          <button
            type="button"
            onClick={handleShowAll}
            className="hover:text-foreground hover:underline cursor-pointer"
          >
            Show all
          </button>
          <span className="opacity-40">•</span>
          <button
            type="button"
            onClick={handleHideAllOptional}
            className="hover:text-foreground hover:underline cursor-pointer"
          >
            Hide optional
          </button>
        </div>

        {/* Columns List */}
        <div
          role="menu"
          aria-label="Toggle column visibility"
          className="max-h-64 overflow-y-auto p-1 space-y-0.5"
        >
          {filteredColumns.length === 0 ? (
            <div className="py-6 text-center text-xs text-muted-foreground">
              No matching columns found.
            </div>
          ) : (
            filteredColumns.map((column) => {
              const label =
                column.columnDef.meta?.label ?? column.id.replace(/_/g, " ");
              const isVisible = column.getIsVisible();
              const isRequired =
                !column.getCanHide() ||
                column.columnDef.meta?.required === true;
              const isPinned = column.getIsPinned();

              return (
                <div
                  key={column.id}
                  role="menuitemcheckbox"
                  aria-checked={isVisible}
                  aria-disabled={isRequired}
                  onClick={() => handleToggleColumn(column)}
                  className={cn(
                    "flex items-center justify-between px-2 py-1.5 rounded-md text-xs transition-colors select-none",
                    isRequired
                      ? "opacity-80 cursor-default bg-muted/10"
                      : "cursor-pointer hover:bg-accent text-foreground",
                    isVisible && !isRequired && "font-medium text-foreground",
                  )}
                >
                  <div className="flex items-center gap-2 min-w-0 flex-1">
                    <Checkbox
                      checked={isVisible}
                      disabled={isRequired}
                      onCheckedChange={() => handleToggleColumn(column)}
                      aria-label={`Toggle ${label} column`}
                      className="size-3.5 pointer-events-none"
                    />
                    <span className="truncate capitalize">{label}</span>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0 ml-2">
                    {isPinned && (
                      <Badge
                        variant="outline"
                        className="h-4 px-1 text-[9px] font-mono text-primary border-primary/30 gap-0.5"
                      >
                        <Pin className="size-2.5 rotate-45" />
                        <span>{isPinned === "left" ? "Left" : "Right"}</span>
                      </Badge>
                    )}

                    {isRequired ? (
                      <Tooltip>
                        <TooltipTrigger className="flex items-center text-muted-foreground">
                          <Lock className="size-3 opacity-70" />
                        </TooltipTrigger>
                        <TooltipContent side="left" className="text-[11px]">
                          Required column
                        </TooltipContent>
                      </Tooltip>
                    ) : null}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer: Reset to defaults */}
        <div className="border-t border-border/60 p-1.5 bg-muted/20">
          <Button
            variant="ghost"
            size="sm"
            onClick={handleReset}
            className="w-full h-7 justify-center gap-1.5 text-xs text-muted-foreground hover:text-foreground hover:bg-background cursor-pointer"
          >
            <RotateCcw className="size-3" />
            <span>Reset columns to defaults</span>
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}

export const DataTableColumnManager = DataTableViewOptions;
