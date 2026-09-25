"use client";

import {
  flexRender,
  type Row,
  type Table as TanstackTable,
} from "@tanstack/react-table";
import * as React from "react";

import { DataTableEmpty } from "@/components/data-table/data-table-empty";
import { DataTableError } from "@/components/data-table/data-table-error";
import { DataTablePagination } from "@/components/data-table/data-table-pagination";
import { DataTableSkeleton } from "@/components/data-table/data-table-skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { getColumnPinningStyle } from "@/lib/data-table";
import { cn } from "@/lib/utils";
import type { TableDensity } from "@/types/data-table";

interface DataTableProps<TData> extends React.HTMLAttributes<HTMLDivElement> {
  table: TanstackTable<TData>;
  actionBar?: React.ReactNode;
  loading?: boolean;
  error?: string | Error | null;
  onRetry?: () => void;
  emptyState?: React.ReactNode;
  hasSearch?: boolean;
  hasFilters?: boolean;
  onClearSearch?: () => void;
  onClearFilters?: () => void;
  onResetAll?: () => void;
  renderSubComponent?: (props: { row: Row<TData> }) => React.ReactNode;
  density?: TableDensity;
  withPagination?: boolean;
  totalRows?: number;
  pageSizeOptions?: number[];
  onRowClick?: (row: Row<TData>, event: React.MouseEvent) => void;
}

const DENSITY_STYLES: Record<TableDensity, { cell: string; head: string }> = {
  compact: {
    cell: "py-1 px-2.5 text-xs leading-tight",
    head: "h-8 px-2.5 text-xs",
  },
  default: {
    cell: "py-2 px-3 text-xs leading-normal",
    head: "h-9 px-3 text-xs",
  },
  comfortable: {
    cell: "py-3 px-3.5 text-sm leading-normal",
    head: "h-11 px-3.5 text-sm",
  },
};

export function DataTable<TData>({
  table,
  actionBar,
  loading = false,
  error = null,
  onRetry,
  emptyState,
  hasSearch,
  hasFilters,
  onClearSearch,
  onClearFilters,
  onResetAll,
  renderSubComponent,
  density: densityProp,
  withPagination = true,
  totalRows,
  pageSizeOptions,
  onRowClick,
  children,
  className,
  ...props
}: DataTableProps<TData>) {
  const currentDensity =
    densityProp ?? table.options.meta?.density ?? "default";
  const densityClass = DENSITY_STYLES[currentDensity] ?? DENSITY_STYLES.default;

  const rows = table.getRowModel().rows;
  const columnsCount = table.getAllColumns().length;
  const isFiltered =
    table.getState().columnFilters.length > 0 ||
    table.getState().globalFilter ||
    hasSearch;

  return (
    <div
      className={cn("flex w-full flex-col gap-2.5", className)}
      {...props}
    >
      {children}

      <div className="overflow-hidden rounded-md border border-border/80 bg-card shadow-2xs">
        <div className="overflow-x-auto">
          <Table className="border-collapse">
            <TableHeader className="bg-muted/40 border-b border-border/60">
              {table.getHeaderGroups().map((headerGroup) => (
                <TableRow key={headerGroup.id} className="hover:bg-transparent">
                  {headerGroup.headers.map((header) => {
                    const pinningStyles = getColumnPinningStyle({
                      column: header.column,
                      withBorder: true,
                    });

                    return (
                      <TableHead
                        key={header.id}
                        colSpan={header.colSpan}
                        style={pinningStyles}
                        className={cn(
                          densityClass.head,
                          "font-medium text-muted-foreground transition-colors",
                          header.column.getIsPinned() &&
                            "bg-muted/90 backdrop-blur-xs",
                        )}
                      >
                        {header.isPlaceholder
                          ? null
                          : flexRender(
                              header.column.columnDef.header,
                              header.getContext(),
                            )}
                      </TableHead>
                    );
                  })}
                </TableRow>
              ))}
            </TableHeader>

            <TableBody className="divide-y divide-border/40">
              {loading ? (
                <TableRow className="hover:bg-transparent">
                  <TableCell
                    colSpan={columnsCount}
                    className="p-0 text-center"
                  >
                    <DataTableSkeleton
                      columnCount={columnsCount}
                      rowCount={Math.min(table.getState().pagination.pageSize, 10)}
                      withPagination={false}
                      withViewOptions={false}
                    />
                  </TableCell>
                </TableRow>
              ) : error ? (
                <TableRow className="hover:bg-transparent">
                  <TableCell
                    colSpan={columnsCount}
                    className="h-48 text-center"
                  >
                    <DataTableError error={error} onRetry={onRetry} />
                  </TableCell>
                </TableRow>
              ) : rows?.length ? (
                rows.map((row) => {
                  const isSelected = row.getIsSelected();
                  const isExpanded = row.getIsExpanded();

                  return (
                    <React.Fragment key={row.id}>
                      <TableRow
                        data-state={isSelected ? "selected" : undefined}
                        onClick={(e) => onRowClick?.(row, e)}
                        className={cn(
                          "transition-colors",
                          onRowClick && "cursor-pointer",
                          isSelected && "bg-primary/5 dark:bg-primary/10",
                          "hover:bg-muted/40",
                        )}
                      >
                        {row.getVisibleCells().map((cell) => {
                          const pinningStyles = getColumnPinningStyle({
                            column: cell.column,
                            withBorder: true,
                          });

                          return (
                            <TableCell
                              key={cell.id}
                              style={pinningStyles}
                              className={cn(
                                densityClass.cell,
                                "align-middle",
                                cell.column.getIsPinned() &&
                                  "bg-card/95 backdrop-blur-xs",
                              )}
                            >
                              {flexRender(
                                cell.column.columnDef.cell,
                                cell.getContext(),
                              )}
                            </TableCell>
                          );
                        })}
                      </TableRow>

                      {/* Expandable Sub-Row */}
                      {isExpanded && renderSubComponent && (
                        <TableRow className="bg-muted/20 hover:bg-muted/20 border-b border-border/40">
                          <TableCell
                            colSpan={columnsCount}
                            className="p-4"
                          >
                            {renderSubComponent({ row })}
                          </TableCell>
                        </TableRow>
                      )}
                    </React.Fragment>
                  );
                })
              ) : (
                <TableRow className="hover:bg-transparent">
                  <TableCell
                    colSpan={columnsCount}
                    className="h-48 text-center p-0"
                  >
                    {emptyState ?? (
                      <DataTableEmpty
                        hasSearch={Boolean(hasSearch || table.getState().globalFilter)}
                        hasFilters={Boolean(hasFilters || isFiltered)}
                        onClearSearch={onClearSearch}
                        onClearFilters={onClearFilters}
                        onResetAll={onResetAll}
                      />
                    )}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </div>

      {/* Pagination Footer */}
      {withPagination && (
        <DataTablePagination
          table={table}
          totalRows={totalRows}
          pageSizeOptions={pageSizeOptions}
        />
      )}

      {/* Floating Action Bar */}
      {actionBar &&
        table.getFilteredSelectedRowModel().rows.length > 0 &&
        actionBar}
    </div>
  );
}
