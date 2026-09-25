import type { Table } from "@tanstack/react-table";
import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
} from "lucide-react";
import * as React from "react";

import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

interface DataTablePaginationProps<TData> extends React.HTMLAttributes<HTMLDivElement> {
  table: Table<TData>;
  pageSizeOptions?: number[];
  totalRows?: number;
}

export function DataTablePagination<TData>({
  table,
  pageSizeOptions = [10, 25, 50, 100],
  totalRows,
  className,
  ...props
}: DataTablePaginationProps<TData>) {
  const selectedRows = table.getFilteredSelectedRowModel().rows.length;
  const visibleRows = table.getFilteredRowModel().rows.length;
  const pageIndex = table.getState().pagination.pageIndex;
  const pageSize = table.getState().pagination.pageSize;
  const pageCount = Math.max(1, table.getPageCount());

  return (
    <div
      className={cn(
        "flex w-full flex-col-reverse items-center justify-between gap-3 overflow-auto px-1 py-1.5 sm:flex-row sm:gap-6",
        className,
      )}
      {...props}
    >
      <div className="flex-1 whitespace-nowrap text-xs text-muted-foreground">
        {selectedRows > 0 ? (
          <span>
            <strong className="font-semibold text-foreground">{selectedRows}</strong> of{" "}
            <strong className="font-semibold text-foreground">{visibleRows}</strong> row(s) selected
            {totalRows !== undefined && totalRows > visibleRows && (
              <span className="text-[11px] opacity-75"> ({totalRows.toLocaleString()} total in database)</span>
            )}
          </span>
        ) : (
          <span>
            Showing <strong className="font-medium text-foreground">{visibleRows}</strong>{" "}
            {totalRows !== undefined ? (
              <>of <strong className="font-medium text-foreground">{totalRows.toLocaleString()}</strong> records</>
            ) : (
              "records"
            )}
          </span>
        )}
      </div>

      <div className="flex flex-col-reverse items-center gap-3 sm:flex-row sm:gap-4 lg:gap-6">
        <div className="flex items-center gap-2">
          <p className="whitespace-nowrap text-xs font-medium text-muted-foreground">Rows per page</p>
          <Select
            value={`${pageSize}`}
            onValueChange={(value) => {
              table.setPageSize(Number(value));
            }}
          >
            <SelectTrigger className="h-7 w-[70px] text-xs">
              <SelectValue placeholder={pageSize} />
            </SelectTrigger>
            <SelectContent side="top">
              <SelectGroup>
                {pageSizeOptions.map((size) => (
                  <SelectItem key={size} value={`${size}`} className="text-xs">
                    {size}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        </div>

        <div className="flex items-center justify-center text-xs font-medium text-muted-foreground">
          Page <strong className="mx-1 text-foreground">{pageIndex + 1}</strong> of{" "}
          <strong className="mx-1 text-foreground">{pageCount}</strong>
        </div>

        <div className="flex items-center gap-1">
          <Button
            aria-label="Go to first page"
            variant="outline"
            size="icon"
            className="hidden size-7 lg:flex cursor-pointer disabled:opacity-40"
            onClick={() => table.setPageIndex(0)}
            disabled={!table.getCanPreviousPage()}
          >
            <ChevronsLeft className="size-3.5" />
          </Button>
          <Button
            aria-label="Go to previous page"
            variant="outline"
            size="icon"
            className="size-7 cursor-pointer disabled:opacity-40"
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
          >
            <ChevronLeft className="size-3.5" />
          </Button>
          <Button
            aria-label="Go to next page"
            variant="outline"
            size="icon"
            className="size-7 cursor-pointer disabled:opacity-40"
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
          >
            <ChevronRight className="size-3.5" />
          </Button>
          <Button
            aria-label="Go to last page"
            variant="outline"
            size="icon"
            className="hidden size-7 lg:flex cursor-pointer disabled:opacity-40"
            onClick={() => table.setPageIndex(pageCount - 1)}
            disabled={!table.getCanNextPage()}
          >
            <ChevronsRight className="size-3.5" />
          </Button>
        </div>
      </div>
    </div>
  );
}
