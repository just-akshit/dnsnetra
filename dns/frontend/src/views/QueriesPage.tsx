"use client";

import { ColumnDef, Row } from "@tanstack/react-table";
import {
  AlertTriangle,
  Copy,
  Globe,
  Radio,
  RotateCcw,
  ShieldAlert,
} from "lucide-react";
import { useRouter } from "next/navigation";
import * as React from "react";
import {
  ActionBar,
  ActionBarClose,
  ActionBarGroup,
  ActionBarItem,
  ActionBarSelection,
  ActionBarSeparator,
} from "@/components/ui/action-bar";
import { DataTable } from "@/components/data-table/data-table";
import {
  createActionsColumn,
  createDomainColumn,
  createExpandColumn,
  createIpColumn,
  createQueryColumn,
  createSelectColumn,
  createTimestampColumn,
  createVerdictColumn,
} from "@/components/data-table/data-table-column-helpers";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { DataTableEmpty } from "@/components/data-table/data-table-empty";
import { DataTableToolbar } from "@/components/data-table/data-table-toolbar";
import { GlobalTimeRangePicker } from "@/components/layout/GlobalTimeRangePicker";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useTimeRange } from "@/context/TimeRangeContext";
import { useDataTable } from "@/hooks/use-data-table";
import { apiClient } from "@/lib/api-client";
import { formatFullTimestamp } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { TablePreset } from "@/types/data-table";

export interface DnsQueryItem {
  id: string;
  timestamp: string;
  domain: string;
  query_type: string;
  response_code: string;
  client_ip: string;
  verdict: "benign" | "malicious" | "review_needed" | "unknown" | string;
  response_time_ms: number;
  ti_source?: string | null;
}

const RECORD_TYPE_OPTIONS = [
  { label: "A", value: "A" },
  { label: "AAAA", value: "AAAA" },
  { label: "CNAME", value: "CNAME" },
  { label: "TXT", value: "TXT" },
  { label: "MX", value: "MX" },
  { label: "NS", value: "NS" },
  { label: "PTR", value: "PTR" },
];

const RESPONSE_CODE_OPTIONS = [
  { label: "NOERROR", value: "NOERROR" },
  { label: "NXDOMAIN", value: "NXDOMAIN" },
  { label: "SERVFAIL", value: "SERVFAIL" },
  { label: "REFUSED", value: "REFUSED" },
];

const QUERY_PRESETS: TablePreset<DnsQueryItem>[] = [
  {
    id: "all",
    label: "All Queries",
    icon: Globe,
    search: "",
    filters: { verdict: [] },
  },
  {
    id: "threats",
    label: "Threat Queries",
    icon: ShieldAlert,
    filters: { verdict: ["malicious"] },
  },
  {
    id: "review_needed",
    label: "Review Needed",
    icon: AlertTriangle,
    filters: { verdict: ["review_needed"] },
  },
];

export const QueriesPage: React.FC = () => {
  const router = useRouter();
  const { timeRange, registerRefreshHandler } = useTimeRange();

  const [queries, setQueries] = React.useState<DnsQueryItem[]>([]);
  const [meta, setMeta] = React.useState({
    total: 0,
    page: 1,
    pageSize: 50,
    pages: 1,
  });
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  // Stale-request tracking to prevent out-of-order responses from overwriting data
  const requestSeq = React.useRef(0);
  const hasLoadedRef = React.useRef(false);

  // Column Definitions
  const columns = React.useMemo<ColumnDef<DnsQueryItem>[]>(() => [
    createSelectColumn<DnsQueryItem>(),
    createExpandColumn<DnsQueryItem>(),
    createTimestampColumn<DnsQueryItem>({
      accessorKey: "timestamp",
      id: "timestamp",
      title: "Timestamp",
      align: "left",
      fullPrecision: true,
      stacked: false,
      required: true,
      defaultVisible: true,
      enableColumnFilter: false,
    }),
    createDomainColumn<DnsQueryItem>({
      accessorKey: "domain",
      id: "domain",
      title: "Domain",
      linkToInvestigation: true,
      required: true,
      defaultVisible: true,
      enableFilter: false,
    }),
    createQueryColumn<DnsQueryItem>({
      accessorKey: "domain",
      id: "query",
      title: "Query",
      defaultVisible: false,
      hideable: true,
      enableFilter: false,
    }),
    {
      id: "query_type",
      accessorKey: "query_type",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Type" />
      ),
      cell: ({ row }) => {
        const type = String(row.getValue("query_type") ?? "-");
        return (
          <span className="font-mono text-xs px-1.5 py-0.5 rounded bg-muted/60 text-muted-foreground font-semibold">
            {type}
          </span>
        );
      },
      meta: {
        label: "Record Type",
        variant: "select",
        options: RECORD_TYPE_OPTIONS,
        defaultVisible: true,
      },
      enableColumnFilter: false,
      enableSorting: true,
    },
    {
      id: "response_code",
      accessorKey: "response_code",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="RCODE" />
      ),
      cell: ({ row }) => {
        const rcode = String(row.getValue("response_code") ?? "-");
        const isError = rcode !== "NOERROR" && rcode !== "";

        return (
          <span
            className={cn(
              "font-mono text-xs px-1.5 py-0.5 rounded font-semibold",
              isError
                ? "bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20"
                : "bg-muted/40 text-muted-foreground",
            )}
          >
            {rcode || "NOERROR"}
          </span>
        );
      },
      meta: {
        label: "Response Code",
        variant: "select",
        options: RESPONSE_CODE_OPTIONS,
        defaultVisible: true,
      },
      enableColumnFilter: false,
      enableSorting: true,
    },
    createVerdictColumn<DnsQueryItem>({
      accessorKey: "verdict",
      id: "verdict",
      title: "Verdict",
      align: "right",
      defaultVisible: true,
      enableColumnFilter: true,
    }),
    createIpColumn<DnsQueryItem>({
      accessorKey: "client_ip",
      id: "client_ip",
      title: "Client IP",
      linkToClient: true,
      defaultVisible: true,
      enableFilter: false,
    }),
    {
      id: "response_time_ms",
      accessorKey: "response_time_ms",
      header: ({ column }) => (
        <div className="text-right">
          <DataTableColumnHeader column={column} title="Latency" />
        </div>
      ),
      cell: ({ row }) => {
        const ms = row.getValue("response_time_ms") as number;
        return (
          <div className="text-right font-mono text-xs text-muted-foreground">
            {ms !== undefined && ms > 0 ? `${ms}ms` : "-"}
          </div>
        );
      },
      meta: {
        label: "Latency",
        variant: "range",
        defaultVisible: true,
      },
      enableColumnFilter: false,
      enableSorting: true,
    },
    {
      id: "ti_source",
      accessorKey: "ti_source",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Source" />
      ),
      cell: ({ row }) => {
        const src = row.getValue("ti_source") as string | null;
        if (!src) return <span className="text-muted-foreground text-xs">-</span>;
        return (
          <span className="font-mono text-xs px-1.5 py-0.5 rounded bg-muted/40 text-muted-foreground">
            {src}
          </span>
        );
      },
      meta: {
        label: "Source",
        defaultVisible: false,
      },
      enableColumnFilter: false,
      enableSorting: true,
    },
    {
      id: "id",
      accessorKey: "id",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Query ID" />
      ),
      cell: ({ row }) => {
        const qid = String(row.getValue("id") ?? "-");
        return (
          <div className="text-xs font-mono text-muted-foreground truncate max-w-[120px]">
            {qid}
          </div>
        );
      },
      meta: {
        label: "Query ID",
        variant: "text",
        defaultVisible: false,
        hideable: true,
      },
      enableColumnFilter: false,
      enableSorting: true,
    },
    createActionsColumn<DnsQueryItem>({
      actions: (row) => [
        {
          label: "Investigate Domain",
          onClick: () =>
            router.push(`/investigate/domains/${encodeURIComponent(row.original.domain)}`),
        },
        {
          label: "Investigate Client",
          onClick: () =>
            router.push(`/investigate/clients/${encodeURIComponent(row.original.client_ip)}`),
        },
        {
          label: "Copy Raw Event",
          onClick: () => {
            navigator.clipboard.writeText(JSON.stringify(row.original, null, 2));
          },
        },
      ],
    }),
  ], [router]);

  // Hook Integration
  const {
    table,
    search,
    setSearch,
    page,
    perPage,
    density,
    setDensity,
    activePresetId,
    applyPreset,
    resetAll,
    columnFilters,
  } = useDataTable({
    tableId: "dns-queries-table",
    data: queries,
    columns,
    pageCount: meta.pages,
    presets: QUERY_PRESETS,
    manualPagination: true,
    manualSorting: true,
    manualFiltering: true,
    initialState: {
      columnPinning: {
        left: ["select", "expander", "timestamp", "domain"],
        right: ["actions"],
      },
      columnVisibility: {
        query: false,
        ti_source: false,
        id: false,
      },
      pagination: {
        pageIndex: 0,
        pageSize: 50,
      },
    },
    getRowId: (row) => row.id,
  });

  // Extract verdict filter from columnFilters
  const labelFilter = React.useMemo(() => {
    const filter = columnFilters.find((f) => f.id === "verdict");
    if (!filter || !filter.value) return undefined;
    if (Array.isArray(filter.value)) {
      return filter.value[0] || undefined;
    }
    return String(filter.value) || undefined;
  }, [columnFilters]);

  // Fetch real queries from backend
  const fetchQueries = React.useCallback(
    async (isSilent = false) => {
      const seq = ++requestSeq.current;
      if (!isSilent && !hasLoadedRef.current) {
        setLoading(true);
      }
      setError(null);

      try {
        const startIso =
          timeRange.isCustom && timeRange.startDate
            ? timeRange.startDate.toISOString()
            : undefined;
        const endIso =
          timeRange.isCustom && timeRange.endDate
            ? timeRange.endDate.toISOString()
            : undefined;

        const res = await apiClient.getReportQueries({
          page,
          pageSize: perPage,
          search: search || undefined,
          label: labelFilter !== "all" ? labelFilter : undefined,
          window: timeRange.isCustom ? undefined : timeRange.preset,
          start_time: startIso,
          end_time: endIso,
        });

        // If a newer request was dispatched, discard this response
        if (seq !== requestSeq.current) return;

        const mapped: DnsQueryItem[] = (res.data || []).map((item: any) => ({
          id: String(item.id),
          timestamp: item.timestamp,
          domain: item.domain,
          query_type: item.query_type || "A",
          response_code: item.response_code || "NOERROR",
          client_ip: item.client_ip,
          verdict:
            (item.final_label || "unknown").toLowerCase() === "clean"
              ? "benign"
              : (item.final_label || "unknown").toLowerCase(),
          response_time_ms: 0,
          ti_source: item.ti_source || null,
        }));

        setQueries(mapped);
        hasLoadedRef.current = true;
        if (res.meta) {
          setMeta({
            total: res.meta.total,
            page: res.meta.page,
            pageSize: res.meta.page_size,
            pages: res.meta.pages,
          });
        }
      } catch (err: any) {
        if (seq !== requestSeq.current) return;
        console.error("Error fetching queries:", err);
        setError(
          err.response?.data?.detail ||
            err.message ||
            "Failed to load queries from backend",
        );
      } finally {
        if (seq === requestSeq.current) {
          setLoading(false);
        }
      }
    },
    [page, perPage, search, labelFilter, timeRange.isCustom, timeRange.preset, timeRange.startDate, timeRange.endDate],
  );

  React.useEffect(() => {
    fetchQueries();
  }, [fetchQueries]);

  React.useEffect(() => {
    const unregister = registerRefreshHandler(() => fetchQueries(true));
    return () => unregister();
  }, [registerRefreshHandler, fetchQueries]);

  // Floating Action Bar on Selection
  const selectedRows = table.getFilteredSelectedRowModel().rows;
  const handleCopySelected = React.useCallback(() => {
    const text = selectedRows
      .map(
        (r) =>
          `${r.original.timestamp}\t${r.original.domain}\t${r.original.query_type}\t${r.original.client_ip}\t${r.original.verdict}`,
      )
      .join("\n");
    navigator.clipboard.writeText(text);
  }, [selectedRows]);

  // Expandable Row Subcomponent
  const renderSubComponent = React.useCallback(
    ({ row }: { row: Row<DnsQueryItem> }) => {
      const item = row.original;
      return (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 p-2 bg-muted/10 rounded border border-border/50 text-xs">
          <div>
            <span className="text-muted-foreground block text-[11px] font-medium">Exact Timestamp</span>
            <span className="font-mono text-foreground">{formatFullTimestamp(item.timestamp)}</span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px] font-medium">Origin Client</span>
            <span className="font-mono text-foreground">{item.client_ip}</span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px] font-medium">DNS Record Type / Code</span>
            <span className="font-mono text-foreground">{item.query_type} / {item.response_code}</span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px] font-medium">Threat Intelligence</span>
            <span className="font-mono text-foreground">{item.ti_source || "Local telemetry"}</span>
          </div>
        </div>
      );
    },
    [],
  );

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-foreground">
            DNS Queries Telemetry Stream
          </h1>
          <p className="text-xs text-muted-foreground">
            Real-time DNS transaction stream, protocol inspections, and query log exploration.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-xs font-normal gap-1.5 text-muted-foreground">
            <Radio className="size-3 text-amber-500" />
            <span>Telemetry Pipeline</span>
          </Badge>
          <Badge variant="outline" className="text-xs font-normal">
            {meta.total.toLocaleString()} records
          </Badge>
        </div>
      </div>

      {/* Notice Banner */}
      <div className="p-3.5 rounded-md bg-blue-500/10 border border-blue-500/20 text-xs text-blue-700 dark:text-blue-300 flex items-center justify-between">
        <span>
          Live DNS telemetry streaming endpoint coming in a future backend phase. Raw historical telemetry is stored in PostgreSQL (<code>domain_query_history</code>).
        </span>
      </div>

      {/* Enterprise Data Table */}
      <DataTable
        table={table}
        loading={loading}
        error={error}
        onRetry={fetchQueries}
        density={density}
        totalRows={meta.total}
        renderSubComponent={renderSubComponent}
        onRowClick={(row) => {
          router.push(`/investigate/domains/${encodeURIComponent(row.original.domain)}`);
        }}
        onResetAll={resetAll}
        emptyState={
          <DataTableEmpty
            title="No DNS queries found"
            description="No queries match the current time range and filters."
            hasFilters={Boolean(search || labelFilter)}
            onClearFilters={() => {
              setSearch("");
              table.resetColumnFilters();
            }}
          />
        }
        actionBar={
          <ActionBar
            open={selectedRows.length > 0}
            onOpenChange={(open) => {
              if (!open) table.toggleAllRowsSelected(false);
            }}
          >
            <ActionBarSelection>
              <span>{selectedRows.length} query record(s) selected</span>
            </ActionBarSelection>

            <ActionBarGroup>
              <ActionBarItem onClick={handleCopySelected}>
                <Copy className="size-3.5 mr-1" />
                Copy Query Records
              </ActionBarItem>

              <ActionBarSeparator />

              <ActionBarClose aria-label="Clear selection" />
            </ActionBarGroup>
          </ActionBar>
        }
      >
        {/* Minimal Primary Toolbar */}
        <DataTableToolbar
          table={table}
          search={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search domain or query..."
          presets={QUERY_PRESETS}
          activePresetId={activePresetId}
          onSelectPreset={applyPreset}
          onResetAll={resetAll}
          density={density}
          onDensityChange={setDensity}
          enableDensity={true}
          enableViewOptions={true}
          viewOptionsVariant="add-column"
          viewOptionsTitle="+ Add column"
        >
          <GlobalTimeRangePicker />
          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchQueries()}
            disabled={loading}
            className="h-8 gap-1.5 text-xs cursor-pointer"
          >
            <RotateCcw className={cn("size-3.5", loading && "animate-spin")} />
            <span className="hidden sm:inline">Refresh</span>
          </Button>
        </DataTableToolbar>
      </DataTable>
    </div>
  );
};

export default QueriesPage;
