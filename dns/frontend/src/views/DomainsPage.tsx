"use client";

import { ColumnDef, Row } from "@tanstack/react-table";
import {
  AlertTriangle,
  Copy,
  ExternalLink,
  Globe,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
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
  createCountColumn,
  createDomainColumn,
  createExpandColumn,
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
import type { DomainItem } from "@/types/api";
import type { TablePreset } from "@/types/data-table";

const DOMAIN_PRESETS: TablePreset<DomainItem>[] = [
  {
    id: "all",
    label: "All Domains",
    icon: Globe,
    search: "",
    filters: { label: [] },
  },
  {
    id: "malicious",
    label: "Malicious",
    icon: ShieldAlert,
    filters: { label: ["malicious"] },
  },
  {
    id: "review_needed",
    label: "Review Needed",
    icon: AlertTriangle,
    filters: { label: ["review_needed"] },
  },
  {
    id: "benign",
    label: "Benign",
    icon: ShieldCheck,
    filters: { label: ["benign"] },
  },
];

export const DomainsPage: React.FC = () => {
  const router = useRouter();
  const { timeRange, registerRefreshHandler } = useTimeRange();

  const [domains, setDomains] = React.useState<DomainItem[]>([]);
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
  const columns = React.useMemo<ColumnDef<DomainItem>[]>(() => [
    createSelectColumn<DomainItem>(),
    createExpandColumn<DomainItem>(),
    createDomainColumn<DomainItem>({
      accessorKey: "domain",
      id: "domain",
      title: "Domain",
      linkToInvestigation: true,
      required: true,
      defaultVisible: true,
      enableFilter: false,
    }),
    createCountColumn<DomainItem>({
      accessorKey: "total_queries",
      id: "total_queries",
      title: "Queries",
      align: "right",
      defaultVisible: true,
      enableColumnFilter: false,
    }),
    createCountColumn<DomainItem>({
      accessorKey: "unique_clients",
      id: "unique_clients",
      title: "Clients",
      align: "right",
      defaultVisible: true,
      enableColumnFilter: false,
    }),
    createCountColumn<DomainItem>({
      accessorKey: "threat_count",
      id: "threat_count",
      title: "Threats",
      align: "right",
      highlightThreats: true,
      defaultVisible: true,
      enableColumnFilter: false,
    }),
    createVerdictColumn<DomainItem>({
      accessorKey: "label",
      id: "label",
      title: "Verdict",
      align: "right",
      defaultVisible: true,
      enableColumnFilter: true,
    }),
    {
      id: "last_ti_source",
      accessorKey: "last_ti_source",
      header: ({ column }) => (
        <div className="text-right">
          <DataTableColumnHeader column={column} title="Source" />
        </div>
      ),
      cell: ({ row }) => {
        const source = row.getValue("last_ti_source") as string | null;
        return (
          <div className="text-right font-mono text-xs text-muted-foreground truncate max-w-[120px]">
            {source || "-"}
          </div>
        );
      },
      meta: {
        label: "TI Source",
        variant: "text",
        defaultVisible: true,
      },
      enableColumnFilter: false,
      enableSorting: true,
    },
    createTimestampColumn<DomainItem>({
      accessorKey: "last_seen",
      id: "last_seen",
      title: "Last Seen",
      align: "right",
      fullPrecision: true,
      stacked: false,
      defaultVisible: true,
      enableColumnFilter: false,
    }),
    createTimestampColumn<DomainItem>({
      accessorKey: "first_seen",
      id: "first_seen",
      title: "First Seen",
      align: "right",
      fullPrecision: true,
      stacked: false,
      defaultVisible: false,
      enableColumnFilter: false,
    }),
    createCountColumn<DomainItem>({
      accessorKey: "clean_count",
      id: "clean_count",
      title: "Clean Count",
      align: "right",
      defaultVisible: false,
      enableColumnFilter: false,
    }),
    createCountColumn<DomainItem>({
      accessorKey: "malicious_count",
      id: "malicious_count",
      title: "Malicious Count",
      align: "right",
      highlightThreats: true,
      defaultVisible: false,
      enableColumnFilter: false,
    }),
    {
      id: "label_reason",
      accessorKey: "label_reason",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Reason" />
      ),
      cell: ({ row }) => {
        const reason = row.getValue("label_reason") as string | null;
        return (
          <div className="text-xs text-muted-foreground truncate max-w-[180px]">
            {reason || "-"}
          </div>
        );
      },
      meta: {
        label: "Reason",
        variant: "text",
        defaultVisible: false,
      },
      enableColumnFilter: false,
      enableSorting: false,
    },
    createActionsColumn<DomainItem>({
      actions: (row) => [
        {
          label: "Investigate Domain",
          onClick: () =>
            router.push(`/investigate/domains/${encodeURIComponent(row.original.domain)}`),
        },
        {
          label: "Copy Domain Name",
          onClick: () => {
            navigator.clipboard.writeText(row.original.domain);
          },
        },
        {
          label: "Copy Raw JSON",
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
    tableId: "domains-table",
    data: domains,
    columns,
    pageCount: meta.pages,
    presets: DOMAIN_PRESETS,
    manualPagination: true,
    manualSorting: true,
    manualFiltering: true,
    initialState: {
      columnPinning: {
        left: ["select", "expander", "domain"],
        right: ["actions"],
      },
      columnVisibility: {
        first_seen: false,
        clean_count: false,
        malicious_count: false,
        label_reason: false,
      },
      pagination: {
        pageIndex: 0,
        pageSize: 50,
      },
    },
    getRowId: (row) => row.domain,
  });

  // Extract label filter from columnFilters
  const labelFilter = React.useMemo(() => {
    const filter = columnFilters.find((f) => f.id === "label");
    if (!filter || !filter.value) return undefined;
    if (Array.isArray(filter.value)) {
      return filter.value[0] || undefined;
    }
    return String(filter.value) || undefined;
  }, [columnFilters]);

  // Fetch Domains from real backend
  const fetchDomains = React.useCallback(
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

        const res = await apiClient.getDomains({
          page,
          pageSize: perPage,
          search: search || undefined,
          label: labelFilter !== "all" ? labelFilter : undefined,
          start_time: startIso,
          end_time: endIso,
          window: timeRange.isCustom ? undefined : timeRange.preset,
        });

        if (seq !== requestSeq.current) return;

        setDomains(res.data || []);
        hasLoadedRef.current = true;
        if (res.meta) {
          setMeta({
            total: res.meta.total,
            page: res.meta.page,
            pageSize: (res.meta as any).page_size ?? perPage,
            pages: res.meta.pages,
          });
        }
      } catch (err: any) {
        if (seq !== requestSeq.current) return;
        console.error("Error fetching domains:", err);
        setError(
          err.response?.data?.detail ||
            err.message ||
            "Failed to load domains from backend",
        );
      } finally {
        if (seq === requestSeq.current) {
          setLoading(false);
        }
      }
    },
    [page, perPage, search, labelFilter, timeRange.startDate, timeRange.endDate, timeRange.preset, timeRange.isCustom],
  );

  React.useEffect(() => {
    fetchDomains();
  }, [fetchDomains]);

  React.useEffect(() => {
    const unregister = registerRefreshHandler(() => fetchDomains(true));
    return () => unregister();
  }, [registerRefreshHandler, fetchDomains]);

  // Floating Action Bar on Selection
  const selectedRows = table.getFilteredSelectedRowModel().rows;
  const handleCopySelected = React.useCallback(() => {
    const text = selectedRows.map((r) => r.original.domain).join("\n");
    navigator.clipboard.writeText(text);
  }, [selectedRows]);

  const handleInvestigateFirstSelected = React.useCallback(() => {
    if (selectedRows.length > 0) {
      router.push(`/investigate/domains/${encodeURIComponent(selectedRows[0].original.domain)}`);
    }
  }, [selectedRows, router]);

  // Expandable Row Subcomponent
  const renderSubComponent = React.useCallback(
    ({ row }: { row: Row<DomainItem> }) => {
      const item = row.original;
      return (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 p-2 bg-muted/10 rounded border border-border/50 text-xs">
          <div>
            <span className="text-muted-foreground block text-[11px] font-medium">First Seen</span>
            <span className="font-mono text-foreground">{formatFullTimestamp(item.first_seen)}</span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px] font-medium">Clean Queries</span>
            <span className="font-mono text-foreground">{item.clean_count?.toLocaleString() || 0}</span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px] font-medium">Malicious Queries</span>
            <span className="font-mono text-red-500 font-semibold">{item.malicious_count?.toLocaleString() || 0}</span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px] font-medium">Classification Reason</span>
            <span className="text-foreground truncate block">{item.label_reason || "Behavioral heuristic match"}</span>
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
            Domains Investigation
          </h1>
          <p className="text-xs text-muted-foreground">
            Explore observed domains, threat classifications, query metrics, and reputation intelligence.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-xs font-normal">
            {meta.total.toLocaleString()} domains
          </Badge>
        </div>
      </div>

      {/* Enterprise Data Table */}
      <DataTable
        table={table}
        loading={loading}
        error={error}
        onRetry={fetchDomains}
        totalRows={meta.total}
        density={density}
        renderSubComponent={renderSubComponent}
        onRowClick={(row) => {
          router.push(`/investigate/domains/${encodeURIComponent(row.original.domain)}`);
        }}
        onResetAll={resetAll}
        emptyState={
          <DataTableEmpty
            title="No domains found"
            description="No domains match the current time range and filters."
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
              <span>{selectedRows.length} visible domain(s) selected</span>
            </ActionBarSelection>

            <ActionBarGroup>
              <ActionBarItem onClick={handleCopySelected}>
                <Copy className="size-3.5 mr-1" />
                Copy Domains
              </ActionBarItem>

              <ActionBarItem onClick={handleInvestigateFirstSelected}>
                <ExternalLink className="size-3.5 mr-1" />
                Investigate
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
          searchPlaceholder="Search domain..."
          presets={DOMAIN_PRESETS}
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
            onClick={() => fetchDomains()}
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

export default DomainsPage;
