import * as React from "react"
import type {
  ColumnDef,
  ColumnFiltersState,
  ColumnVisibilityState,
  OnChangeFn,
  PaginationState,
  RowSelectionState,
  SortingState,
} from "@tanstack/react-table"
import type { DnsnetraTableFeatures } from "./features"

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type DnsnetraColumnDef<TData extends object, TValue = any> = ColumnDef<
  DnsnetraTableFeatures,
  TData,
  TValue
>

export type EntityType = "domain" | "client" | "query" | "daily_review" | "custom"

export interface EntityIdentifier<TData = unknown> {
  type: EntityType
  id: string
  label?: string
  data?: TData
}

export interface TableFilterOption {
  label: string
  value: string
  count?: number
  icon?: React.ReactNode
}

export interface TableFilterConfig {
  id: string
  title: string
  options: TableFilterOption[]
  isMulti?: boolean
  type?: "select" | "multi-select"
}

export interface TableTabItem {
  id: string
  label: string
  count?: number | string
}

export interface TableBulkAction<TData> {
  id: string
  label: string
  icon?: React.ReactNode
  variant?: "default" | "secondary" | "destructive" | "outline"
  onClick: (selectedRows: TData[]) => void
}

export interface DataTableProps<TData extends object> {
  /** Stable identifier for this table instance (e.g. "domains", "clients") */
  tableId: string

  /** Data array to render in table */
  data: TData[]

  /** Strongly-typed TanStack Table v9 Column definitions */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  columns: DnsnetraColumnDef<TData, any>[]

  /** Extract unique row ID (defaults to (row) => (row as any).id ?? (row as any).domain ?? ...) */
  getRowId?: (row: TData) => string

  /** Total number of rows matching the query on the server */
  totalRows?: number

  /** Loading state flag */
  loading?: boolean

  /** Error message or object */
  error?: string | Error | null

  /** Retry callback if fetching fails */
  onRetry?: () => void

  /** Server-side control flags */
  manualPagination?: boolean
  manualSorting?: boolean
  manualFiltering?: boolean

  /** Controlled pagination */
  pagination?: PaginationState
  onPaginationChange?: OnChangeFn<PaginationState>
  pageSizeOptions?: number[]

  /** Controlled sorting */
  sorting?: SortingState
  onSortingChange?: OnChangeFn<SortingState>

  /** Controlled search / global filter */
  searchQuery?: string
  onSearchChange?: (query: string) => void
  searchPlaceholder?: string
  showSearch?: boolean

  /** Controlled column filters */
  columnFilters?: ColumnFiltersState
  onColumnFiltersChange?: OnChangeFn<ColumnFiltersState>
  filters?: TableFilterConfig[]

  /** Controlled column visibility */
  columnVisibility?: ColumnVisibilityState
  onColumnVisibilityChange?: OnChangeFn<ColumnVisibilityState>
  showColumnVisibility?: boolean

  /** Controlled row selection */
  rowSelection?: RowSelectionState
  onRowSelectionChange?: OnChangeFn<RowSelectionState>
  enableRowSelection?: boolean

  /** Segmented top tabs */
  tabs?: TableTabItem[]
  activeTab?: string
  onTabChange?: (tabId: string) => void

  /** Bulk actions shown when 1+ rows are selected */
  bulkActions?: TableBulkAction<TData>[]

  /** Custom actions rendered in toolbar (e.g. Export, Refresh) */
  toolbarActions?: React.ReactNode
  /** Dedicated Time Range component embedded in filter bar */
  timeRangeControl?: React.ReactNode
  onExport?: () => void

  /** Entity detail drawer interaction */
  enableDetailDrawer?: boolean
  selectedEntity?: EntityIdentifier | null
  onSelectedEntityChange?: (entity: EntityIdentifier | null) => void
  detailRenderer?: (
    entity: EntityIdentifier,
    onClose: () => void
  ) => React.ReactNode

  /** Empty state overrides */
  emptyTitle?: string
  emptyDescription?: string
  onClearFilters?: () => void

  /** Layout options */
  stickyHeader?: boolean
  className?: string
}

export interface DnsnetraTableMeta {
  onEntityClick?: (entity: EntityIdentifier) => void
  align?: "left" | "right" | "center"
}

export type CanonicalVerdictType =
  | "Benign"
  | "Malicious"
  | "Review Needed"
  | "Unknown"
  | "clean"
  | "malicious"
  | "suspicious"
  | "review_needed"
  | "unknown"
  | "blocked"
  | "active"
  | "inactive"
  | "Done"
  | "In Process"
