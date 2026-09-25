"use client"

import * as React from "react"
import {
  useTable,
  type ColumnFiltersState,
  type ColumnVisibilityState,
  type PaginationState,
  type RowSelectionState,
  type SortingState,
} from "@tanstack/react-table"
import { Table } from "@/components/ui/table"
import { dnsnetraTableFeatures } from "@/lib/data-table/features"
import type { DataTableProps, EntityIdentifier } from "@/lib/data-table/types"
import { DataTableToolbar } from "./data-table-toolbar"
import { DataTableHeader } from "./data-table-header"
import { DataTableBody } from "./data-table-body"
import { DataTablePagination } from "./data-table-pagination"
import { DataTableDetailDrawer } from "./data-table-detail-drawer"
import { cn } from "cn"

export function DataTable<TData extends object>({
  tableId,
  data,
  columns,
  getRowId,
  totalRows,
  loading = false,
  error = null,
  onRetry,

  // Server-side manual mode controls
  manualPagination = false,
  manualSorting = false,
  manualFiltering = false,

  // Controlled pagination
  pagination: controlledPagination,
  onPaginationChange: setControlledPagination,
  pageSizeOptions = [10, 25, 50, 100],

  // Controlled sorting
  sorting: controlledSorting,
  onSortingChange: setControlledSorting,

  // Controlled search
  searchQuery,
  onSearchChange,
  searchPlaceholder,
  showSearch = true,

  // Controlled column filters
  columnFilters: controlledColumnFilters,
  onColumnFiltersChange: setControlledColumnFilters,
  filters,

  // Controlled column visibility
  columnVisibility: controlledColumnVisibility,
  onColumnVisibilityChange: setControlledColumnVisibility,
  showColumnVisibility = true,

  // Controlled row selection
  rowSelection: controlledRowSelection,
  onRowSelectionChange: setControlledRowSelection,
  enableRowSelection = true,

  // Top segmented tabs
  tabs,
  activeTab,
  onTabChange,

  // Actions
  bulkActions,
  toolbarActions,
  timeRangeControl,
  onExport,

  // Detail drawer
  enableDetailDrawer = true,
  selectedEntity: controlledSelectedEntity,
  onSelectedEntityChange: setControlledSelectedEntity,
  detailRenderer,

  // Empty state customizations
  emptyTitle,
  emptyDescription,
  onClearFilters,

  // Layout
  stickyHeader = false,
  className,
}: DataTableProps<TData>) {
  // Uncontrolled state fallbacks if not controlled from parent
  const [internalSorting, setInternalSorting] = React.useState<SortingState>([])
  const [internalFilters, setInternalFilters] = React.useState<ColumnFiltersState>([])
  const [internalVisibility, setInternalVisibility] = React.useState<ColumnVisibilityState>({})
  const [internalSelection, setInternalSelection] = React.useState<RowSelectionState>({})
  const [internalPagination, setInternalPagination] = React.useState<PaginationState>({
    pageIndex: 0,
    pageSize: 25,
  })
  const [internalEntity, setInternalEntity] = React.useState<EntityIdentifier | null>(null)

  // LocalStorage persistence for column visibility preferences
  const storageKey = tableId ? `dnsnetra_table_columns_${tableId}` : null

  React.useEffect(() => {
    if (!storageKey || typeof window === "undefined") return
    try {
      const saved = window.localStorage.getItem(storageKey)
      if (saved) {
        const parsed = JSON.parse(saved)
        if (parsed && typeof parsed === "object") {
          if (setControlledColumnVisibility) {
            setControlledColumnVisibility(parsed)
          } else {
            setInternalVisibility(parsed)
          }
        }
      }
    } catch {
      // Ignore invalid JSON
    }
  }, [storageKey, setControlledColumnVisibility])

  // Resolve controlled vs uncontrolled state
  const sorting = controlledSorting ?? internalSorting
  const onSortingChange = setControlledSorting ?? setInternalSorting

  const columnFilters = controlledColumnFilters ?? internalFilters
  const onColumnFiltersChange = setControlledColumnFilters ?? setInternalFilters

  const columnVisibility = controlledColumnVisibility ?? internalVisibility
  const baseOnColumnVisibilityChange = setControlledColumnVisibility ?? setInternalVisibility

  const onColumnVisibilityChange = React.useCallback(
    (updater: ColumnVisibilityState | ((old: ColumnVisibilityState) => ColumnVisibilityState)) => {
      baseOnColumnVisibilityChange((old) => {
        const next = typeof updater === "function" ? updater(old) : updater
        if (storageKey && typeof window !== "undefined") {
          try {
            window.localStorage.setItem(storageKey, JSON.stringify(next))
          } catch {
            // ignore
          }
        }
        return next
      })
    },
    [baseOnColumnVisibilityChange, storageKey]
  )

  const handleResetColumns = React.useCallback(() => {
    baseOnColumnVisibilityChange({})
    if (storageKey && typeof window !== "undefined") {
      try {
        window.localStorage.removeItem(storageKey)
      } catch {
        // ignore
      }
    }
  }, [baseOnColumnVisibilityChange, storageKey])

  const rowSelection = controlledRowSelection ?? internalSelection
  const onRowSelectionChange = setControlledRowSelection ?? setInternalSelection

  const pagination = controlledPagination ?? internalPagination
  const onPaginationChange = setControlledPagination ?? setInternalPagination

  const activeEntity = controlledSelectedEntity !== undefined ? controlledSelectedEntity : internalEntity
  const setActiveEntity = React.useCallback(
    (entity: EntityIdentifier | null) => {
      if (setControlledSelectedEntity) {
        setControlledSelectedEntity(entity)
      } else {
        setInternalEntity(entity)
      }
    },
    [setControlledSelectedEntity]
  )

  // Calculate pageCount for server-side pagination
  const pageCount =
    manualPagination && totalRows !== undefined
      ? Math.ceil(totalRows / (pagination.pageSize || 25))
      : undefined

  // TanStack Table v9 hook initialization
  const table = useTable({
    features: dnsnetraTableFeatures,
    data,
    columns,
    state: {
      sorting,
      columnFilters,
      columnVisibility,
      rowSelection,
      pagination,
    },
    meta: {
      onEntityClick: setActiveEntity,
    },
    getRowId:
      getRowId ??
      ((row: TData, index: number) => {
        const r = row as Record<string, unknown>
        return (
          (r.id as string | number | undefined)?.toString() ??
          (r.domain as string | undefined) ??
          (r.client_ip as string | undefined) ??
          (r.query_id as string | undefined) ??
          String(index)
        )
      }),
    enableRowSelection,
    manualPagination,
    manualSorting,
    manualFiltering,
    pageCount,
    onSortingChange,
    onColumnFiltersChange,
    onColumnVisibilityChange,
    onRowSelectionChange,
    onPaginationChange,
  })

  const isDrawerOpen = enableDetailDrawer && activeEntity !== null
  const isFiltered =
    columnFilters.length > 0 || (searchQuery && searchQuery.trim().length > 0)

  return (
    <div
      data-slot="dnsnetra-data-table"
      data-table-id={tableId}
      className={cn("flex w-full flex-col gap-2.5", className)}
    >
      {/* 1. Table Toolbar */}
      <DataTableToolbar
        table={table}
        searchQuery={searchQuery}
        onSearchChange={onSearchChange}
        searchPlaceholder={searchPlaceholder}
        showSearch={showSearch}
        tabs={tabs}
        activeTab={activeTab}
        onTabChange={onTabChange}
        filters={filters}
        showColumnVisibility={showColumnVisibility}
        bulkActions={bulkActions}
        toolbarActions={toolbarActions}
        timeRangeControl={timeRangeControl}
        onExport={onExport}
        onClearFilters={onClearFilters}
        onResetColumns={handleResetColumns}
      />

      {/* 2. Table Surface Container */}
      <div className="relative w-full overflow-hidden rounded-md border border-border/80 bg-card shadow-xs transition-colors">
        <Table className="w-full">
          <DataTableHeader
            headerGroups={table.getHeaderGroups()}
            stickyHeader={stickyHeader}
          />
          <DataTableBody
            rowModel={table.getRowModel()}
            columnCount={table.getVisibleLeafColumns().length || columns.length}
            loading={loading}
            error={error}
            onRetry={onRetry}
            isFiltered={!!isFiltered}
            emptyTitle={emptyTitle}
            emptyDescription={emptyDescription}
            onClearFilters={onClearFilters}
          />
        </Table>
      </div>

      {/* 3. Table Pagination Footer */}
      <DataTablePagination
        table={table}
        pageSizeOptions={pageSizeOptions}
        totalRows={totalRows}
        enableRowSelection={enableRowSelection}
      />

      {/* 4. Entity Detail Drawer */}
      {enableDetailDrawer && (
        <DataTableDetailDrawer
          entity={activeEntity}
          open={isDrawerOpen}
          onOpenChange={(open) => {
            if (!open) setActiveEntity(null)
          }}
        >
          {activeEntity && detailRenderer
            ? detailRenderer(activeEntity, () => setActiveEntity(null))
            : null}
        </DataTableDetailDrawer>
      )}
    </div>
  )
}
