"use client";

import type { ColumnDef, Row } from "@tanstack/react-table";
import {
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  ExternalLink,
  MoreHorizontal,
} from "lucide-react";
import Link from "next/link";
import * as React from "react";

import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { VerdictBadge } from "@/components/security/VerdictBadge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  formatDateTime,
  formatFullTimestamp,
  formatNumber,
  formatRelativeTime,
  formatTimestampParts,
} from "@/lib/format";
import { cn } from "@/lib/utils";

/**
 * Checkbox copy button with copied visual feedback
 */
export function CopyButton({
  value,
  label = "Copy",
  className,
}: {
  value: string;
  label?: string;
  className?: string;
}) {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <button
      type="button"
      aria-label={label}
      onClick={handleCopy}
      className={cn(
        "inline-flex items-center justify-center size-5 rounded hover:bg-accent text-muted-foreground hover:text-foreground opacity-60 hover:opacity-100 transition-opacity cursor-pointer",
        className,
      )}
    >
      {copied ? (
        <Check className="size-3 text-emerald-500" />
      ) : (
        <Copy className="size-3" />
      )}
    </button>
  );
}

/**
 * Row selection checkbox column
 */
export function createSelectColumn<TData>(): ColumnDef<TData> {
  return {
    id: "select",
    header: ({ table }) => {
      const isAllSelected = table.getIsAllPageRowsSelected();
      const isSomeSelected = table.getIsSomePageRowsSelected();

      return (
        <div className="flex items-center justify-center px-1">
          <Checkbox
            checked={isAllSelected}
            indeterminate={isSomeSelected && !isAllSelected}
            onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
            aria-label="Select all visible rows"
            className="size-3.5"
          />
        </div>
      );
    },
    cell: ({ row }) => (
      <div
        className="flex items-center justify-center px-1"
        onClick={(e) => e.stopPropagation()}
      >
        <Checkbox
          checked={row.getIsSelected()}
          onCheckedChange={(value) => row.toggleSelected(!!value)}
          aria-label="Select row"
          className="size-3.5"
        />
      </div>
    ),
    enableSorting: false,
    enableHiding: false,
    size: 40,
  };
}

/**
 * Expandable row trigger column
 */
export function createExpandColumn<TData>(): ColumnDef<TData> {
  return {
    id: "expander",
    header: () => null,
    cell: ({ row }) => (
      <div
        className="flex items-center justify-center px-1"
        onClick={(e) => e.stopPropagation()}
      >
        <Button
          variant="ghost"
          size="icon"
          onClick={() => row.toggleExpanded()}
          className="size-5 p-0 text-muted-foreground hover:text-foreground cursor-pointer"
        >
          {row.getIsExpanded() ? (
            <ChevronDown className="size-3.5" />
          ) : (
            <ChevronRight className="size-3.5" />
          )}
        </Button>
      </div>
    ),
    enableSorting: false,
    enableHiding: false,
    size: 32,
  };
}

/**
 * Domain name column with copy action and drill-down investigation link
 */
export function createDomainColumn<TData>({
  accessorKey = "domain" as keyof TData & string,
  id = "domain",
  title = "Domain",
  linkToInvestigation = true,
  enableFilter = true,
  required = false,
  defaultVisible = true,
  hideable = true,
}: {
  accessorKey?: keyof TData & string;
  id?: string;
  title?: string;
  linkToInvestigation?: boolean;
  enableFilter?: boolean;
  required?: boolean;
  defaultVisible?: boolean;
  hideable?: boolean;
} = {}): ColumnDef<TData> {
  return {
    id,
    accessorKey,
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={title} />
    ),
    cell: ({ row }) => {
      const domain = String(row.getValue(id) ?? "");
      if (!domain) return <span className="text-muted-foreground">-</span>;

      return (
        <div className="flex items-center gap-1.5 max-w-[280px]">
          {linkToInvestigation ? (
            <Link
              href={`/investigate/domains/${encodeURIComponent(domain)}`}
              className="truncate font-mono font-medium text-foreground hover:text-primary hover:underline transition-colors"
              onClick={(e) => e.stopPropagation()}
            >
              {domain}
            </Link>
          ) : (
            <span className="truncate font-mono font-medium text-foreground">
              {domain}
            </span>
          )}
          <CopyButton value={domain} label={`Copy ${domain}`} />
        </div>
      );
    },
    meta: {
      label: title,
      placeholder: "Search domain...",
      variant: "text",
      required,
      defaultVisible,
      hideable: !required && hideable,
    },
    enableHiding: !required && hideable,
    enableColumnFilter: enableFilter,
    enableSorting: true,
  };
}

/**
 * DNS Query string column with monospace formatting and copy
 */
export function createQueryColumn<TData>({
  accessorKey = "query" as keyof TData & string,
  id = "query",
  title = "Query",
  enableFilter = true,
  required = false,
  defaultVisible = true,
  hideable = true,
}: {
  accessorKey?: keyof TData & string;
  id?: string;
  title?: string;
  enableFilter?: boolean;
  required?: boolean;
  defaultVisible?: boolean;
  hideable?: boolean;
} = {}): ColumnDef<TData> {
  return {
    id,
    accessorKey,
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={title} />
    ),
    cell: ({ row }) => {
      const query = String(row.getValue(id) ?? "");
      if (!query) return <span className="text-muted-foreground">-</span>;

      return (
        <div className="flex items-center gap-1.5 max-w-[260px]">
          <span className="truncate font-mono text-xs text-foreground">
            {query}
          </span>
          <CopyButton value={query} label="Copy query string" />
        </div>
      );
    },
    meta: {
      label: title,
      placeholder: "Filter query...",
      variant: "text",
      required,
      defaultVisible,
      hideable: !required && hideable,
    },
    enableHiding: !required && hideable,
    enableColumnFilter: enableFilter,
    enableSorting: true,
  };
}

/**
 * IP address column with copy action and client investigation link
 */
export function createIpColumn<TData>({
  accessorKey = "client_ip" as keyof TData & string,
  id = "client_ip",
  title = "Client IP",
  linkToClient = true,
  enableFilter = true,
  required = false,
  defaultVisible = true,
  hideable = true,
}: {
  accessorKey?: keyof TData & string;
  id?: string;
  title?: string;
  linkToClient?: boolean;
  enableFilter?: boolean;
  required?: boolean;
  defaultVisible?: boolean;
  hideable?: boolean;
} = {}): ColumnDef<TData> {
  return {
    id,
    accessorKey,
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={title} />
    ),
    cell: ({ row }) => {
      const ip = String(row.getValue(id) ?? "");
      if (!ip) return <span className="text-muted-foreground">-</span>;

      return (
        <div className="flex items-center gap-1.5 max-w-[200px]">
          {linkToClient ? (
            <Link
              href={`/investigate/clients/${encodeURIComponent(ip)}`}
              className="truncate font-mono font-medium text-foreground hover:text-primary hover:underline transition-colors text-xs"
              onClick={(e) => e.stopPropagation()}
            >
              {ip}
            </Link>
          ) : (
            <span className="truncate font-mono text-xs text-foreground">
              {ip}
            </span>
          )}
          <CopyButton value={ip} label={`Copy IP ${ip}`} />
        </div>
      );
    },
    meta: {
      label: title,
      placeholder: "Filter IP...",
      variant: "text",
      required,
      defaultVisible,
      hideable: !required && hideable,
    },
    enableHiding: !required && hideable,
    enableColumnFilter: enableFilter,
    enableSorting: true,
  };
}

/**
 * Verdict / Label badge column
 */
export function createVerdictColumn<TData>({
  accessorKey = "label" as keyof TData & string,
  id = "label",
  title = "Verdict",
  align = "right",
  required = false,
  defaultVisible = true,
  hideable = true,
  enableColumnFilter = true,
}: {
  accessorKey?: keyof TData & string;
  id?: string;
  title?: string;
  align?: "left" | "right" | "center";
  required?: boolean;
  defaultVisible?: boolean;
  hideable?: boolean;
  enableColumnFilter?: boolean;
} = {}): ColumnDef<TData> {
  return {
    id,
    accessorKey,
    header: ({ column }) => (
      <div className={cn(align === "right" ? "text-right" : align === "center" ? "text-center" : "text-left")}>
        <DataTableColumnHeader column={column} title={title} />
      </div>
    ),
    cell: ({ row }) => {
      const verdict = String(row.getValue(id) ?? "unknown");
      return (
        <div className={cn("flex", align === "right" ? "justify-end" : align === "center" ? "justify-center" : "justify-start")}>
          <VerdictBadge verdict={verdict} />
        </div>
      );
    },
    meta: {
      label: title,
      variant: "select",
      options: [
        { label: "Malicious", value: "malicious" },
        { label: "Review Needed", value: "review_needed" },
        { label: "Benign", value: "benign" },
        { label: "Unknown", value: "unknown" },
      ],
      required,
      defaultVisible,
      hideable: !required && hideable,
    },
    enableHiding: !required && hideable,
    enableColumnFilter,
    enableSorting: true,
  };
}

/**
 * Numeric Count Column
 */
export function createCountColumn<TData>({
  accessorKey,
  id,
  title,
  align = "right",
  highlightThreats = false,
  required = false,
  defaultVisible = true,
  hideable = true,
  enableColumnFilter = true,
}: {
  accessorKey: keyof TData & string;
  id?: string;
  title: string;
  align?: "left" | "right" | "center";
  highlightThreats?: boolean;
  required?: boolean;
  defaultVisible?: boolean;
  hideable?: boolean;
  enableColumnFilter?: boolean;
}): ColumnDef<TData> {
  const colId = id ?? (accessorKey as string);

  return {
    id: colId,
    accessorKey,
    header: ({ column }) => (
      <div className={cn(align === "right" ? "text-right" : align === "center" ? "text-center" : "text-left")}>
        <DataTableColumnHeader column={column} title={title} />
      </div>
    ),
    cell: ({ row }) => {
      const val = row.getValue(colId) as number | null | undefined;
      const num = typeof val === "number" ? val : 0;

      if (highlightThreats && num > 0) {
        return (
          <div className={cn(align === "right" ? "text-right" : align === "center" ? "text-center" : "text-left")}>
            <span className="font-semibold text-destructive">{formatNumber(num)}</span>
          </div>
        );
      }

      return (
        <div className={cn("text-muted-foreground", align === "right" ? "text-right" : align === "center" ? "text-center" : "text-left")}>
          {formatNumber(num)}
        </div>
      );
    },
    meta: {
      label: title,
      variant: "number",
      required,
      defaultVisible,
      hideable: !required && hideable,
    },
    enableHiding: !required && hideable,
    enableColumnFilter,
    enableSorting: true,
  };
}

/**
 * Timestamp Column with full precision YYYY-MM-DD HH:mm:ss [TZ], accurate chronological sorting, and relative time tooltip
 */
export function createTimestampColumn<TData>({
  accessorKey = "timestamp" as keyof TData & string,
  id = "timestamp",
  title = "Timestamp",
  align = "left",
  fullPrecision = true,
  stacked = false,
  showRelativeTooltip = true,
  required = false,
  defaultVisible = true,
  hideable = true,
  enableColumnFilter = true,
}: {
  accessorKey?: keyof TData & string;
  id?: string;
  title?: string;
  align?: "left" | "right" | "center";
  fullPrecision?: boolean;
  stacked?: boolean;
  showRelativeTooltip?: boolean;
  required?: boolean;
  defaultVisible?: boolean;
  hideable?: boolean;
  enableColumnFilter?: boolean;
} = {}): ColumnDef<TData> {
  return {
    id,
    accessorKey,
    header: ({ column }) => (
      <div
        className={cn(
          align === "right"
            ? "text-right"
            : align === "center"
              ? "text-center"
              : "text-left",
        )}
      >
        <DataTableColumnHeader column={column} title={title} />
      </div>
    ),
    cell: ({ row }) => {
      const ts = row.getValue(id) as string | number | null | undefined;
      if (!ts) {
        return (
          <div
            className={cn(
              "text-muted-foreground text-xs font-mono",
              align === "right" ? "text-right" : align === "center" ? "text-center" : "text-left",
            )}
          >
            -
          </div>
        );
      }

      const { full } = formatTimestampParts(ts);

      return (
        <div
          className={cn(
            "text-xs font-mono text-foreground whitespace-nowrap select-all",
            align === "right" ? "text-right" : align === "center" ? "text-center" : "text-left",
          )}
        >
          {full}
        </div>
      );
    },
    sortingFn: (rowA, rowB, columnId) => {
      const a = rowA.getValue(columnId) as string | number | null | undefined;
      const b = rowB.getValue(columnId) as string | number | null | undefined;
      const timeA = a ? new Date(a).getTime() : 0;
      const timeB = b ? new Date(b).getTime() : 0;
      return timeA < timeB ? -1 : timeA > timeB ? 1 : 0;
    },
    meta: {
      label: title,
      variant: "dateRange",
      required,
      defaultVisible,
      hideable: !required && hideable,
    },
    enableHiding: !required && hideable,
    enableColumnFilter,
    enableSorting: true,
  };
}

/**
 * Configurable row actions dropdown menu
 */
export function createActionsColumn<TData>({
  actions,
}: {
  actions: (row: Row<TData>) => {
    label: string;
    icon?: React.ComponentType<{ className?: string }>;
    onClick: () => void;
    destructive?: boolean;
    separator?: boolean;
  }[];
}): ColumnDef<TData> {
  return {
    id: "actions",
    header: () => <div className="text-right px-1">Actions</div>,
    cell: ({ row }) => {
      const rowActions = actions(row);

      return (
        <div className="flex items-center justify-end px-1" onClick={(e) => e.stopPropagation()}>
          <DropdownMenu>
            <DropdownMenuTrigger
              className="inline-flex size-7 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground focus:outline-none focus:ring-1 focus:ring-ring cursor-pointer"
            >
              <MoreHorizontal className="size-4" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-40 text-xs">
              {rowActions.map((action, idx) => (
                <React.Fragment key={idx}>
                  {action.separator && <DropdownMenuSeparator />}
                  <DropdownMenuItem
                    onClick={action.onClick}
                    className={cn(
                      "cursor-pointer gap-2",
                      action.destructive && "text-destructive focus:text-destructive",
                    )}
                  >
                    {action.icon && <action.icon className="size-3.5" />}
                    <span>{action.label}</span>
                  </DropdownMenuItem>
                </React.Fragment>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      );
    },
    enableSorting: false,
    enableHiding: false,
    size: 60,
  };
}
