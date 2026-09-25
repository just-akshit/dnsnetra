"use client"

import * as React from "react"
import { SearchIcon, XIcon, DownloadIcon } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { DataTableColumnMenu } from "./data-table-column-menu"
import { DataTableFilter } from "./data-table-filter"
import type { ReactTable } from "@tanstack/react-table"
import type { DnsnetraTableFeatures } from "@/lib/data-table/features"
import type {
  TableBulkAction,
  TableFilterConfig,
  TableTabItem,
} from "@/lib/data-table/types"

export interface DataTableToolbarProps<TData extends object> {
  table: ReactTable<DnsnetraTableFeatures, TData>
  searchQuery?: string
  onSearchChange?: (query: string) => void
  searchPlaceholder?: string
  showSearch?: boolean
  tabs?: TableTabItem[]
  activeTab?: string
  onTabChange?: (tabId: string) => void
  filters?: TableFilterConfig[]
  showColumnVisibility?: boolean
  bulkActions?: TableBulkAction<TData>[]
  toolbarActions?: React.ReactNode
  timeRangeControl?: React.ReactNode
  onExport?: () => void
  onClearFilters?: () => void
  onResetColumns?: () => void
}

export function DataTableToolbar<TData extends object>({
  table,
  searchQuery = "",
  onSearchChange,
  searchPlaceholder = "Search...",
  showSearch = true,
  tabs,
  activeTab,
  onTabChange,
  filters,
  showColumnVisibility = true,
  bulkActions,
  toolbarActions,
  timeRangeControl,
  onExport,
  onClearFilters,
  onResetColumns,
}: DataTableToolbarProps<TData>) {
  // Local debounced search state
  const [prevQuery, setPrevQuery] = React.useState(searchQuery)
  const [localSearch, setLocalSearch] = React.useState(searchQuery)

  if (searchQuery !== prevQuery) {
    setPrevQuery(searchQuery)
    setLocalSearch(searchQuery)
  }

  // Debounce search input by 300ms
  React.useEffect(() => {
    if (localSearch === searchQuery) return
    const timer = setTimeout(() => {
      onSearchChange?.(localSearch)
    }, 300)
    return () => clearTimeout(timer)
  }, [localSearch, searchQuery, onSearchChange])

  const selectedRows = table.getSelectedRowModel().rows.map((r) => r.original)
  const hasSelection = selectedRows.length > 0

  const columnFilters = table.state.columnFilters
  const hasFilters = columnFilters.length > 0 || (searchQuery && searchQuery.length > 0)

  const handleClearAll = () => {
    setLocalSearch("")
    onSearchChange?.("")
    table.resetColumnFilters()
    onClearFilters?.()
  }

  return (
    <div className="flex flex-col gap-3 py-2">
      {/* Optional Top Segmented Tabs */}
      {tabs && tabs.length > 0 && (
        <div className="flex items-center justify-between">
          <Tabs
            value={activeTab ?? tabs[0]?.id}
            onValueChange={(val) => onTabChange?.(val)}
            className="w-full"
          >
            <TabsList className="h-8 bg-muted/50 p-0.5">
              {tabs.map((tab) => (
                <TabsTrigger
                  key={tab.id}
                  value={tab.id}
                  className="h-7 px-3 text-xs font-medium gap-1.5"
                >
                  <span>{tab.label}</span>
                  {tab.count !== undefined && (
                    <Badge
                      variant="secondary"
                      className="ml-1 h-4 px-1 text-[10px] font-mono leading-none"
                    >
                      {tab.count}
                    </Badge>
                  )}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
        </div>
      )}

      {/* Main Controls Row */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-1 flex-wrap items-center gap-2">
          {/* Search Box */}
          {showSearch && onSearchChange && (
            <div className="relative w-full max-w-xs min-w-[200px]">
              <SearchIcon className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground pointer-events-none" />
              <Input
                type="search"
                value={localSearch}
                onChange={(e) => setLocalSearch(e.target.value)}
                placeholder={searchPlaceholder}
                className="h-8 pl-8 pr-8 text-xs font-normal"
                aria-label={searchPlaceholder}
              />
              {localSearch && (
                <button
                  type="button"
                  onClick={() => {
                    setLocalSearch("")
                    onSearchChange("")
                  }}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <XIcon className="size-3" />
                  <span className="sr-only">Clear search</span>
                </button>
              )}
            </div>
          )}

          {/* Configurable Filters */}
          {filters?.map((filterConfig) => {
            const currentFilter = columnFilters.find(
              (f: { id: string; value?: unknown }) => f.id === filterConfig.id
            )
            return (
              <DataTableFilter
                key={filterConfig.id}
                config={filterConfig}
                value={currentFilter?.value as string | string[] | undefined}
                onChange={(val) => {
                  table.getColumn(filterConfig.id)?.setFilterValue(val)
                }}
              />
            )
          })}

          {/* Time Range Control if provided */}
          {timeRangeControl}

          {/* Reset All Filters button */}
          {hasFilters && (
            <Button
              variant="ghost"
              size="sm"
              onClick={handleClearAll}
              className="h-8 px-2 text-xs font-normal text-muted-foreground hover:text-foreground"
            >
              <XIcon className="mr-1 size-3" />
              Reset
            </Button>
          )}

          {/* Bulk Actions (visible only when rows are selected) */}
          {hasSelection && bulkActions && bulkActions.length > 0 && (
            <div className="flex items-center gap-1.5 pl-2 border-l border-border">
              <span className="text-xs font-medium text-foreground">
                {selectedRows.length} selected
              </span>
              {bulkActions.map((action) => (
                <Button
                  key={action.id}
                  variant={action.variant ?? "outline"}
                  size="sm"
                  onClick={() => action.onClick(selectedRows)}
                  className="h-7 px-2 text-xs gap-1"
                >
                  {action.icon}
                  {action.label}
                </Button>
              ))}
            </div>
          )}
        </div>

        {/* Right side options: Export, Custom Actions, Columns Menu */}
        <div className="flex items-center gap-2">
          {onExport && (
            <Button
              variant="outline"
              size="sm"
              onClick={onExport}
              className="h-8 gap-1.5 text-xs font-normal"
            >
              <DownloadIcon className="size-3.5" />
              <span>Export</span>
            </Button>
          )}

          {toolbarActions}

          {showColumnVisibility && (
            <DataTableColumnMenu table={table} onResetColumns={onResetColumns} />
          )}
        </div>
      </div>
    </div>
  )
}
