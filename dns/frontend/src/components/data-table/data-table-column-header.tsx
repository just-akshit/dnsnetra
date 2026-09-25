"use client";

import type { Column } from "@tanstack/react-table";
import {
  ArrowDown,
  ArrowUp,
  ChevronsUpDown,
  EyeOff,
  Pin,
  PinOff,
  X,
} from "lucide-react";
import * as React from "react";

import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";

interface DataTableColumnHeaderProps<TData, TValue>
  extends React.HTMLAttributes<HTMLDivElement> {
  column: Column<TData, TValue>;
  title?: string;
  children?: React.ReactNode;
}

export function DataTableColumnHeader<TData, TValue>({
  column,
  title,
  children,
  className,
  ...props
}: DataTableColumnHeaderProps<TData, TValue>) {
  const label = title ?? (typeof children === "string" ? children : "");

  if (!column.getCanSort() && !column.getCanHide() && !column.getCanPin()) {
    return (
      <div className={cn("text-xs font-medium text-muted-foreground", className)} {...props}>
        {children ?? title}
      </div>
    );
  }

  const isPinned = column.getIsPinned();

  return (
    <div className={cn("flex items-center gap-1.5", className)} {...props}>
      <DropdownMenu>
        <DropdownMenuTrigger
          className={cn(
            "-ml-1.5 flex h-7 items-center gap-1 rounded-md px-1.5 text-xs font-medium text-muted-foreground hover:bg-accent hover:text-foreground focus:outline-none focus:ring-1 focus:ring-ring data-[state=open]:bg-accent cursor-pointer transition-colors",
            isPinned && "text-primary font-semibold",
          )}
        >
          <span>{children ?? title}</span>
          {isPinned && <Pin className="size-3 text-primary rotate-45" />}
          {column.getCanSort() && (
            column.getIsSorted() === "desc" ? (
              <ArrowDown className="size-3.5 text-foreground" />
            ) : column.getIsSorted() === "asc" ? (
              <ArrowUp className="size-3.5 text-foreground" />
            ) : (
              <ChevronsUpDown className="size-3 opacity-60" />
            )
          )}
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-36 text-xs">
          {column.getCanSort() && (
            <>
              <DropdownMenuCheckboxItem
                className="cursor-pointer gap-2"
                checked={column.getIsSorted() === "asc"}
                onClick={() => column.toggleSorting(false)}
              >
                <ArrowUp className="size-3.5 text-muted-foreground" />
                Ascending
              </DropdownMenuCheckboxItem>
              <DropdownMenuCheckboxItem
                className="cursor-pointer gap-2"
                checked={column.getIsSorted() === "desc"}
                onClick={() => column.toggleSorting(true)}
              >
                <ArrowDown className="size-3.5 text-muted-foreground" />
                Descending
              </DropdownMenuCheckboxItem>
              {column.getIsSorted() && (
                <DropdownMenuItem
                  className="cursor-pointer gap-2"
                  onClick={() => column.clearSorting()}
                >
                  <X className="size-3.5 text-muted-foreground" />
                  Clear sort
                </DropdownMenuItem>
              )}
              {(column.getCanPin() || column.getCanHide()) && <DropdownMenuSeparator />}
            </>
          )}

          {column.getCanPin() && (
            <>
              <DropdownMenuCheckboxItem
                className="cursor-pointer gap-2"
                checked={isPinned === "left"}
                onClick={() => column.pin(isPinned === "left" ? false : "left")}
              >
                <Pin className="size-3.5 text-muted-foreground rotate-[-45deg]" />
                Pin to left
              </DropdownMenuCheckboxItem>
              <DropdownMenuCheckboxItem
                className="cursor-pointer gap-2"
                checked={isPinned === "right"}
                onClick={() => column.pin(isPinned === "right" ? false : "right")}
              >
                <Pin className="size-3.5 text-muted-foreground rotate-45" />
                Pin to right
              </DropdownMenuCheckboxItem>
              {isPinned && (
                <DropdownMenuItem
                  className="cursor-pointer gap-2"
                  onClick={() => column.pin(false)}
                >
                  <PinOff className="size-3.5 text-muted-foreground" />
                  Unpin column
                </DropdownMenuItem>
              )}
              {column.getCanHide() && <DropdownMenuSeparator />}
            </>
          )}

          {column.getCanHide() && (
            <DropdownMenuItem
              className="cursor-pointer gap-2 text-destructive focus:text-destructive"
              onClick={() => column.toggleVisibility(false)}
            >
              <EyeOff className="size-3.5" />
              Hide column
            </DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}
