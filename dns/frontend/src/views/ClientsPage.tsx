"use client";

import { ColumnDef, Row } from "@tanstack/react-table";
import {
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
  createExpandColumn,
  createIpColumn,
  createSelectColumn,
  createTimestampColumn,
} from "@/components/data-table/data-table-column-helpers";
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
import type { ClientItem } from "@/types/api";
import type { TablePreset } from "@/types/data-table";

const CLIENT_PRESETS: TablePreset<ClientItem>[] = [
  {
    id: "all",
    label: "All Clients",
    icon: Globe,
    search: "",
    filters: {},
  },
  {
    id: "threats",
    label: "Threat Clients",
    icon: ShieldAlert,
    filters: {},
  },
  {
    id: "clean",
    label: "Clean Clients",
    icon: ShieldCheck,
    filters: {},
  },
];

export const ClientsPage: React.FC = () => {
  const router = useRouter();
  const { timeRange, registerRefreshHandler } = useTimeRange();

  const [clients, setClients] = React.useState<ClientItem[]>([]);
  const [meta, setMeta] = React.useState({
    total: 0,
    page: 1,
    pageSize: 50,
    pages: 1,
  });
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  // Stale-request tracking
  const requestSeq = React.useRef(0);
  const hasLoadedRef = React.useRef(false);

  // Column Definitions
  const columns = React.useMemo<ColumnDef<ClientItem>[]>(() => [
    createSelectColumn<ClientItem>(),
    createExpandColumn<ClientItem>(),
    createIpColumn<ClientItem>({
      accessorKey: "client_ip",
      id: "client_ip",
      title: "Client IP",
      linkToClient: true,
      required: true,
      defaultVisible: true,
      enableFilter: false,
    }),
    createCountColumn<ClientItem>({
      accessorKey: "total_queries",
      id: "total_queries",
      title: "Total Queries",
      align: "right",
      defaultVisible: true,
      enableColumnFilter: false,
    }),
    createCountColumn<ClientItem>({
      accessorKey: "unique_domains",
      id: "unique_domains",
      title: "Destination Domains",
      align: "right",
      defaultVisible: true,
      enableColumnFilter: false,
    }),
    createCountColumn<ClientItem>({
      accessorKey: "threat_count",
      id: "threat_count",
      title: "Threats",
      align: "right",
      highlightThreats: true,
      defaultVisible: true,
      enableColumnFilter: false,
    }),
    createCountColumn<ClientItem>({
      accessorKey: "clean_count",
      id: "clean_count",
      title: "Benign Queries",
      align: "right",
      defaultVisible: true,
      enableColumnFilter: false,
    }),
    createTimestampColumn<ClientItem>({
      accessorKey: "first_seen",
      id: "first_seen",
      title: "First Seen",
      align: "right",
      fullPrecision: true,
      stacked: false,
      defaultVisible: true,
      enableColumnFilter: false,
    }),
    createTimestampColumn<ClientItem>({
      accessorKey: "last_seen",
      id: "last_seen",
      title: "Last Seen",
      align: "right",
      fullPrecision: true,
      stacked: false,
      defaultVisible: true,
      enableColumnFilter: false,
    }),
    createActionsColumn<ClientItem>({
      actions: (row) => [
        {
          label: "Investigate Client",
          onClick: () =>
            router.push(`/investigate/clients/${encodeURIComponent(row.original.client_ip)}`),
        },
        {
          label: "Copy Client IP",
          onClick: () => {
            navigator.clipboard.writeText(row.original.client_ip);
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
  } = useDataTable({
    tableId: "clients-table",
    data: clients,
    columns,
    pageCount: meta.pages,
    presets: CLIENT_PRESETS,
    manualPagination: true,
    manualSorting: true,
    manualFiltering: true,
    initialState: {
      columnPinning: {
        left: ["select", "expander", "client_ip"],
        right: ["actions"],
      },
      columnVisibility: {},
      pagination: {
        pageIndex: 0,
        pageSize: 50,
      },
    },
    getRowId: (row) => row.client_ip,
  });

  // Fetch Clients from real backend
  const fetchClients = React.useCallback(
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

        const res = await apiClient.getClients({
          page,
          pageSize: perPage,
          search: search || undefined,
          start_time: startIso,
          end_time: endIso,
          window: timeRange.isCustom ? undefined : timeRange.preset,
        });

        if (seq !== requestSeq.current) return;

        setClients(res.data || []);
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
        console.error("Error fetching clients:", err);
        setError(
          err.response?.data?.detail ||
            err.message ||
            "Failed to load clients from backend",
        );
      } finally {
        if (seq === requestSeq.current) {
          setLoading(false);
        }
      }
    },
    [page, perPage, search, timeRange.startDate, timeRange.endDate, timeRange.preset, timeRange.isCustom],
  );

  React.useEffect(() => {
    fetchClients();
  }, [fetchClients]);

  React.useEffect(() => {
    const unregister = registerRefreshHandler(() => fetchClients(true));
    return () => unregister();
  }, [registerRefreshHandler, fetchClients]);

  // Floating Action Bar on Selection
  const selectedRows = table.getFilteredSelectedRowModel().rows;
  const handleCopySelected = React.useCallback(() => {
    const text = selectedRows.map((r) => r.original.client_ip).join("\n");
    navigator.clipboard.writeText(text);
  }, [selectedRows]);

  const handleInvestigateFirstSelected = React.useCallback(() => {
    if (selectedRows.length > 0) {
      router.push(`/investigate/clients/${encodeURIComponent(selectedRows[0].original.client_ip)}`);
    }
  }, [selectedRows, router]);

  // Expandable Row Subcomponent
  const renderSubComponent = React.useCallback(
    ({ row }: { row: Row<ClientItem> }) => {
      const item = row.original;
      return (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 p-2 bg-muted/10 rounded border border-border/50 text-xs">
          <div>
            <span className="text-muted-foreground block text-[11px] font-medium">First Seen</span>
            <span className="font-mono text-foreground">{formatFullTimestamp(item.first_seen)}</span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px] font-medium">Last Seen</span>
            <span className="font-mono text-foreground">{formatFullTimestamp(item.last_seen)}</span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px] font-medium">Destination Domains</span>
            <span className="font-mono text-foreground">{item.unique_domains?.toLocaleString() || 0}</span>
          </div>
          <div>
            <span className="text-muted-foreground block text-[11px] font-medium">Threat Count</span>
            <span className="font-mono text-red-500 font-semibold">{item.threat_count?.toLocaleString() || 0}</span>
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
            Client Endpoints
          </h1>
          <p className="text-xs text-muted-foreground">
            Explore internal hosts, query volume, resolution patterns, and correlated threats.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-xs font-normal">
            {meta.total.toLocaleString()} endpoints
          </Badge>
        </div>
      </div>

      {/* Enterprise Data Table */}
      <DataTable
        table={table}
        loading={loading}
        error={error}
        onRetry={fetchClients}
        totalRows={meta.total}
        density={density}
        renderSubComponent={renderSubComponent}
        onRowClick={(row) => {
          router.push(`/investigate/clients/${encodeURIComponent(row.original.client_ip)}`);
        }}
        onResetAll={resetAll}
        emptyState={
          <DataTableEmpty
            title="No clients found"
            description="No clients match the current time range and search criteria."
            hasFilters={Boolean(search)}
            onClearFilters={() => {
              setSearch("");
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
              <span>{selectedRows.length} visible client(s) selected</span>
            </ActionBarSelection>

            <ActionBarGroup>
              <ActionBarItem onClick={handleCopySelected}>
                <Copy className="size-3.5 mr-1" />
                Copy IPs
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
          searchPlaceholder="Search client IP..."
          presets={CLIENT_PRESETS}
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
            onClick={() => fetchClients()}
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

export default ClientsPage;
