"use client"

import * as React from "react"
import { usePathname, useRouter, useSearchParams } from "next/navigation"
import type { ColumnFiltersState, PaginationState, SortingState } from "@tanstack/react-table"

export interface TableUrlStateOptions {
  defaultPageSize?: number
  defaultSort?: { id: string; desc: boolean }
}

/**
 * Hook to synchronize table pagination, sorting, search, column filters, and primary criteria with URL search params.
 */
export function useTableUrlState(options: TableUrlStateOptions = {}) {
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()

  const defaultPageSize = options.defaultPageSize ?? 25
  const defaultSort = options.defaultSort

  // Parse page and pageSize from URL
  const pageParam = searchParams.get("page")
  const pageSizeParam = searchParams.get("pageSize") || searchParams.get("page_size") || searchParams.get("limit")
  const pageIndex = Math.max(0, (pageParam ? parseInt(pageParam, 10) : 1) - 1)
  const pageSize = pageSizeParam ? parseInt(pageSizeParam, 10) : defaultPageSize

  const pagination: PaginationState = React.useMemo(
    () => ({
      pageIndex,
      pageSize,
    }),
    [pageIndex, pageSize]
  )

  // Parse sorting from URL
  const sortParam = searchParams.get("sort")
  const orderParam = searchParams.get("order")
  const sorting: SortingState = React.useMemo(() => {
    if (sortParam) {
      return [{ id: sortParam, desc: orderParam === "desc" }]
    }
    return defaultSort ? [{ id: defaultSort.id, desc: defaultSort.desc }] : []
  }, [sortParam, orderParam, defaultSort])

  // Parse search query
  const search = searchParams.get("q") ?? searchParams.get("search") ?? ""

  // Parse tab
  const tab = searchParams.get("tab") ?? ""

  // Parse discrete filters
  const verdict = searchParams.get("verdict") ?? ""
  const status = searchParams.get("status") ?? ""
  const queryType = searchParams.get("query_type") ?? ""

  // Assemble TanStack Table columnFilters state from URL
  const columnFilters: ColumnFiltersState = React.useMemo(() => {
    const filters: ColumnFiltersState = []
    if (verdict) filters.push({ id: "verdict", value: verdict })
    if (status) filters.push({ id: "status", value: status })
    if (queryType) filters.push({ id: "query_type", value: queryType })
    return filters
  }, [verdict, status, queryType])

  // Update URL helper preserving unrelated params
  const setUrlParams = React.useCallback(
    (newParams: Record<string, string | number | null | undefined>) => {
      const params = new URLSearchParams(searchParams.toString())

      for (const [key, value] of Object.entries(newParams)) {
        if (value === null || value === undefined || value === "") {
          params.delete(key)
        } else {
          params.set(key, String(value))
        }
      }

      const queryString = params.toString()
      const newUrl = queryString ? `${pathname}?${queryString}` : pathname
      router.push(newUrl, { scroll: false })
    },
    [pathname, router, searchParams]
  )

  const handlePaginationChange = React.useCallback(
    (updater: PaginationState | ((old: PaginationState) => PaginationState)) => {
      const nextPagination =
        typeof updater === "function" ? updater(pagination) : updater
      setUrlParams({
        page: nextPagination.pageIndex + 1,
        pageSize: nextPagination.pageSize,
      })
    },
    [pagination, setUrlParams]
  )

  const handleSortingChange = React.useCallback(
    (updater: SortingState | ((old: SortingState) => SortingState)) => {
      const nextSorting =
        typeof updater === "function" ? updater(sorting) : updater
      if (nextSorting.length > 0) {
        setUrlParams({
          sort: nextSorting[0].id,
          order: nextSorting[0].desc ? "desc" : "asc",
          page: 1, // reset to page 1 on sort change
        })
      } else {
        setUrlParams({
          sort: null,
          order: null,
          page: 1,
        })
      }
    },
    [sorting, setUrlParams]
  )

  const handleSearchChange = React.useCallback(
    (query: string) => {
      setUrlParams({
        search: query.trim() || null,
        q: null,
        page: 1, // reset to page 1 on search change
      })
    },
    [setUrlParams]
  )

  const handleTabChange = React.useCallback(
    (newTab: string) => {
      setUrlParams({
        tab: newTab || null,
        page: 1,
      })
    },
    [setUrlParams]
  )

  const handleColumnFiltersChange = React.useCallback(
    (updater: ColumnFiltersState | ((old: ColumnFiltersState) => ColumnFiltersState)) => {
      const nextFilters =
        typeof updater === "function" ? updater(columnFilters) : updater

      const verdictFilter = nextFilters.find((f) => f.id === "verdict")
      const statusFilter = nextFilters.find((f) => f.id === "status")
      const queryTypeFilter = nextFilters.find((f) => f.id === "query_type")

      setUrlParams({
        verdict: verdictFilter?.value ? String(verdictFilter.value) : null,
        status: statusFilter?.value ? String(statusFilter.value) : null,
        query_type: queryTypeFilter?.value ? String(queryTypeFilter.value) : null,
        page: 1,
      })
    },
    [columnFilters, setUrlParams]
  )

  const setVerdict = React.useCallback(
    (val: string | null) => {
      setUrlParams({ verdict: val || null, page: 1 })
    },
    [setUrlParams]
  )

  const setStatus = React.useCallback(
    (val: string | null) => {
      setUrlParams({ status: val || null, page: 1 })
    },
    [setUrlParams]
  )

  const resetFilters = React.useCallback(() => {
    setUrlParams({
      search: null,
      q: null,
      verdict: null,
      status: null,
      query_type: null,
      tab: null,
      sort: null,
      order: null,
      page: 1,
    })
  }, [setUrlParams])

  const hasActiveFilters = Boolean(
    search || verdict || status || queryType || (tab && tab !== "all")
  )

  return {
    pagination,
    sorting,
    search,
    tab,
    verdict,
    status,
    queryType,
    columnFilters,
    hasActiveFilters,
    setUrlParams,
    setVerdict,
    setStatus,
    resetFilters,
    onPaginationChange: handlePaginationChange,
    onSortingChange: handleSortingChange,
    onSearchChange: handleSearchChange,
    onTabChange: handleTabChange,
    onColumnFiltersChange: handleColumnFiltersChange,
  }
}
