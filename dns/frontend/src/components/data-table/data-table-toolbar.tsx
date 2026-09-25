"use client";

import type { Column, Table } from "@tanstack/react-table";
import { RotateCcw, Search, X } from "lucide-react";
import * as React from "react";

import { DataTableDateFilter } from "@/components/data-table/data-table-date-filter";
import { DataTableDensity } from "@/components/data-table/data-table-density";
import { DataTableFacetedFilter } from "@/components/data-table/data-table-faceted-filter";
import { DataTablePresets } from "@/components/data-table/data-table-presets";
import { DataTableSliderFilter } from "@/components/data-table/data-table-slider-filter";
import { DataTableViewOptions } from "@/components/data-table/data-table-view-options";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import type { TableDensity, TablePreset } from "@/types/data-table";

interface DataTableToolbarProps<TData> extends React.HTMLAttributes<HTMLDivElement> {
  table: Table<TData>;
  search?: string;
  onSearchChange?: (value: string) => void;
  searchPlaceholder?: string;
  presets?: TablePreset<TData>[];
  activePresetId?: string | null;
  onSelectPreset?: (preset: TablePreset<TData>) => void;
  onResetAll?: () => void;
  enableDensity?: boolean;
  enableViewOptions?: boolean;
  viewOptionsVariant?: "button" | "add-column" | "icon";
  viewOptionsTitle?: string;
  density?: TableDensity;
  onDensityChange?: (density: TableDensity) => void;
}

export function DataTableToolbar<TData>({
  table,
  search,
  onSearchChange,
  searchPlaceholder = "Search...",
  presets,
  activePresetId,
  onSelectPreset,
  onResetAll,
  enableDensity = true,
  enableViewOptions = true,
  viewOptionsVariant = "add-column",
  viewOptionsTitle,
  density = "default",
  onDensityChange,
  children,
  className,
  ...props
}: DataTableToolbarProps<TData>) {
  const isFiltered =
    table.getState().columnFilters.length > 0 || (search && search.length > 0);

  const filterableColumns = React.useMemo(
    () => table.getAllColumns().filter((column) => column.getCanFilter()),
    [table],
  );

  const handleReset = React.useCallback(() => {
    if (onResetAll) {
      onResetAll();
    } else {
      table.resetColumnFilters();
      if (onSearchChange) onSearchChange("");
    }
  }, [onResetAll, table, onSearchChange]);

  return (
    <div
      role="toolbar"
      aria-orientation="horizontal"
      className={cn("flex w-full flex-col gap-2.5 p-1", className)}
      {...props}
    >
      {/* Top Bar: Search, Filters & Controls */}
      <div className="flex w-full flex-wrap items-center justify-between gap-2.5">
        {/* Left Side: Search + Column Filters */}
        <div className="flex flex-1 flex-wrap items-center gap-2">
          {/* Global / Primary Search */}
          {onSearchChange !== undefined && (
            <div className="relative min-w-[200px] max-w-xs">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground pointer-events-none" />
              <Input
                placeholder={searchPlaceholder}
                value={search ?? ""}
                onChange={(e) => onSearchChange(e.target.value)}
                className="h-8 pl-8 pr-7 text-xs bg-background"
              />
              {search ? (
                <button
                  type="button"
                  aria-label="Clear search"
                  onClick={() => onSearchChange("")}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground cursor-pointer"
                >
                  <X className="size-3.5" />
                </button>
              ) : null}
            </div>
          )}

          {/* Faceted & Custom Filters for Filterable Columns */}
          {filterableColumns.map((column) => (
            <DataTableToolbarFilter key={column.id} column={column} />
          ))}

          {/* Reset All / Reset Filters Button */}
          {isFiltered && (
            <Button
              aria-label="Reset everything"
              variant="outline"
              size="sm"
              onClick={handleReset}
              className="h-8 gap-1.5 px-2.5 text-xs text-muted-foreground hover:text-foreground border-dashed cursor-pointer"
            >
              <RotateCcw className="size-3.5" />
              <span>Reset</span>
            </Button>
          )}
        </div>

        {/* Right Side: View Options, Density, Custom Children */}
        <div className="flex items-center gap-2">
          {children}

          {enableDensity && onDensityChange && (
            <DataTableDensity
              density={density}
              onDensityChange={onDensityChange}
            />
          )}

          {enableViewOptions && (
            <DataTableViewOptions
              table={table}
              variant={viewOptionsVariant}
              title={viewOptionsTitle}
              align="end"
            />
          )}
        </div>
      </div>

      {/* Bottom Bar: Presets (if configured) */}
      {presets && presets.length > 0 && onSelectPreset && (
        <DataTablePresets
          presets={presets}
          activePresetId={activePresetId ?? null}
          onSelectPreset={onSelectPreset}
        />
      )}
    </div>
  );
}

interface DataTableToolbarFilterProps<TData> {
  column: Column<TData>;
}

function DataTableToolbarFilter<TData>({
  column,
}: DataTableToolbarFilterProps<TData>) {
  const columnMeta = column.columnDef.meta;
  if (!columnMeta?.variant) return null;

  const title = columnMeta.label ?? column.id;

  switch (columnMeta.variant) {
    case "text":
      return (
        <Input
          placeholder={columnMeta.placeholder ?? `Filter ${title.toLowerCase()}...`}
          value={(column.getFilterValue() as string) ?? ""}
          onChange={(event) => column.setFilterValue(event.target.value)}
          className="h-8 w-36 text-xs lg:w-48 bg-background"
        />
      );

    case "number":
      return (
        <div className="relative">
          <Input
            type="number"
            inputMode="numeric"
            placeholder={columnMeta.placeholder ?? title}
            value={(column.getFilterValue() as string) ?? ""}
            onChange={(event) => column.setFilterValue(event.target.value)}
            className={cn("h-8 w-28 text-xs bg-background", columnMeta.unit && "pr-7")}
          />
          {columnMeta.unit && (
            <span className="absolute top-0 right-0 bottom-0 flex items-center rounded-r-md bg-accent px-2 text-muted-foreground text-[10px]">
              {columnMeta.unit}
            </span>
          )}
        </div>
      );

    case "range":
      return (
        <DataTableSliderFilter
          column={column}
          title={title}
        />
      );

    case "date":
    case "dateRange":
      return (
        <DataTableDateFilter
          column={column}
          title={title}
          multiple={columnMeta.variant === "dateRange"}
        />
      );

    case "select":
    case "multiSelect":
      return (
        <DataTableFacetedFilter
          column={column}
          title={title}
          options={columnMeta.options ?? []}
          multiple={columnMeta.variant === "multiSelect"}
        />
      );

    default:
      return null;
  }
}
