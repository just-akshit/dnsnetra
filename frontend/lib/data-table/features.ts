import {
  columnFilteringFeature,
  columnOrderingFeature,
  columnSizingFeature,
  columnVisibilityFeature,
  createColumnHelper,
  createFilteredRowModel,
  createPaginatedRowModel,
  createSortedRowModel,
  globalFilteringFeature,
  rowPaginationFeature,
  rowSelectionFeature,
  rowSortingFeature,
  tableFeatures,
} from "@tanstack/react-table"

/**
 * Authoritative TanStack Table v9 feature registration for DNSNetra.
 * All tables across the application share this standardized feature set.
 */
export const dnsnetraTableFeatures = tableFeatures({
  columnFilteringFeature,
  columnOrderingFeature,
  columnSizingFeature,
  columnVisibilityFeature,
  globalFilteringFeature,
  rowPaginationFeature,
  rowSelectionFeature,
  rowSortingFeature,
  filteredRowModel: createFilteredRowModel(),
  paginatedRowModel: createPaginatedRowModel(),
  sortedRowModel: createSortedRowModel(),
})

export type DnsnetraTableFeatures = typeof dnsnetraTableFeatures

/**
 * Standard typed column helper bound to DNSNetra table features.
 */
export function createDnsnetraColumnHelper<TData extends object>() {
  return createColumnHelper<DnsnetraTableFeatures, TData>()
}
