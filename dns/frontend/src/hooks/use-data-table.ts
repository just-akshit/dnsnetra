import {
  type ColumnFiltersState,
  type ColumnPinningState,
  type ExpandedState,
  getCoreRowModel,
  getExpandedRowModel,
  getFacetedMinMaxValues,
  getFacetedRowModel,
  getFacetedUniqueValues,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  type PaginationState,
  type RowSelectionState,
  type SortingState,
  type TableOptions,
  type TableState,
  type Updater,
  useReactTable,
  type VisibilityState,
} from "@tanstack/react-table";
import {
  parseAsArrayOf,
  parseAsInteger,
  parseAsString,
  type SingleParser,
  type UseQueryStateOptions,
  useQueryState,
  useQueryStates,
} from "nuqs";
import * as React from "react";

import { useDebouncedCallback } from "@/hooks/use-debounced-callback";
import { getSortingStateParser } from "@/lib/parsers";
import type {
  ExtendedColumnSort,
  QueryKeys,
  TableDensity,
  TablePreset,
} from "@/types/data-table";

const PAGE_KEY = "page";
const PER_PAGE_KEY = "pageSize";
const SORT_KEY = "sort";
const FILTERS_KEY = "filters";
const JOIN_OPERATOR_KEY = "joinOperator";
const SEARCH_KEY = "search";
const ARRAY_SEPARATOR = ",";
const DEBOUNCE_MS = 300;
const THROTTLE_MS = 50;

export interface UseDataTableProps<TData>
  extends Omit<
      TableOptions<TData>,
      | "state"
      | "pageCount"
      | "getCoreRowModel"
      | "manualFiltering"
      | "manualPagination"
      | "manualSorting"
    >,
    Partial<Pick<TableOptions<TData>, "pageCount">> {
  tableId?: string;
  initialState?: Omit<Partial<TableState>, "sorting"> & {
    sorting?: ExtendedColumnSort<TData>[];
  };
  queryKeys?: Partial<QueryKeys>;
  history?: "push" | "replace";
  debounceMs?: number;
  throttleMs?: number;
  clearOnDefault?: boolean;
  enableAdvancedFilter?: boolean;
  enableUrlSync?: boolean;
  manualPagination?: boolean;
  manualSorting?: boolean;
  manualFiltering?: boolean;
  defaultDensity?: TableDensity;
  presets?: TablePreset<TData>[];
  scroll?: boolean;
  shallow?: boolean;
  startTransition?: React.TransitionStartFunction;
}

export function useDataTable<TData>(props: UseDataTableProps<TData>) {
  const {
    tableId,
    columns,
    pageCount = -1,
    initialState,
    queryKeys,
    history = "replace",
    debounceMs = DEBOUNCE_MS,
    throttleMs = THROTTLE_MS,
    clearOnDefault = false,
    enableAdvancedFilter = false,
    enableUrlSync = true,
    manualPagination = true,
    manualSorting = true,
    manualFiltering = true,
    defaultDensity = "default",
    presets = [],
    scroll = false,
    shallow = true,
    startTransition,
    ...tableProps
  } = props;

  // Derive default column visibility from columns metadata and initialState
  const defaultVisibility = React.useMemo<VisibilityState>(() => {
    const visibility: VisibilityState = { ...(initialState?.columnVisibility ?? {}) };
    columns.forEach((col) => {
      const colId = (col.id ?? (col as any).accessorKey) as string;
      if (colId && (col as any).meta?.defaultVisible !== undefined) {
        if (visibility[colId] === undefined) {
          visibility[colId] = Boolean((col as any).meta.defaultVisible);
        }
      }
    });
    return visibility;
  }, [columns, initialState?.columnVisibility]);

  // Read saved column visibility from localStorage if tableId is provided
  const getSavedVisibility = React.useCallback((): VisibilityState => {
    if (typeof window === "undefined" || !tableId) return defaultVisibility;
    try {
      const saved = localStorage.getItem(`datatable:columns:${tableId}`);
      if (saved) {
        return { ...defaultVisibility, ...JSON.parse(saved) };
      }
    } catch {
      // ignore
    }
    return defaultVisibility;
  }, [tableId, defaultVisibility]);

  // Column visibility state with local persistence
  const [columnVisibility, setColumnVisibility] = React.useState<VisibilityState>(
    getSavedVisibility,
  );

  // Sync saved localStorage state once on client mount
  React.useEffect(() => {
    if (tableId && typeof window !== "undefined") {
      try {
        const saved = localStorage.getItem(`datatable:columns:${tableId}`);
        if (saved) {
          setColumnVisibility((prev) => ({ ...prev, ...JSON.parse(saved) }));
        }
      } catch {
        // ignore
      }
    }
  }, [tableId]);

  const onColumnVisibilityChange = React.useCallback(
    (updaterOrValue: Updater<VisibilityState>) => {
      setColumnVisibility((prev) => {
        const next =
          typeof updaterOrValue === "function"
            ? updaterOrValue(prev)
            : updaterOrValue;

        if (tableId && typeof window !== "undefined") {
          try {
            localStorage.setItem(
              `datatable:columns:${tableId}`,
              JSON.stringify(next),
            );
          } catch {
            // ignore
          }
        }
        return next;
      });
    },
    [tableId],
  );

  const resetColumns = React.useCallback(() => {
    setColumnVisibility(defaultVisibility);
    if (tableId && typeof window !== "undefined") {
      try {
        localStorage.removeItem(`datatable:columns:${tableId}`);
      } catch {
        // ignore
      }
    }
  }, [defaultVisibility, tableId]);

  const pageKey = queryKeys?.page ?? PAGE_KEY;
  const perPageKey = queryKeys?.perPage ?? PER_PAGE_KEY;
  const sortKey = queryKeys?.sort ?? SORT_KEY;
  const filtersKey = queryKeys?.filters ?? FILTERS_KEY;
  const joinOperatorKey = queryKeys?.joinOperator ?? JOIN_OPERATOR_KEY;
  const searchKey = queryKeys?.search ?? SEARCH_KEY;

  const queryStateOptions = React.useMemo<
    Omit<UseQueryStateOptions<string>, "parse">
  >(
    () => ({
      history,
      scroll,
      shallow,
      throttleMs,
      debounceMs,
      clearOnDefault,
      startTransition,
    }),
    [
      history,
      scroll,
      shallow,
      throttleMs,
      debounceMs,
      clearOnDefault,
      startTransition,
    ],
  );

  // Density state
  const [density, setDensity] = React.useState<TableDensity>(defaultDensity);

  // Active preset state
  const [activePresetId, setActivePresetId] = React.useState<string | null>(null);

  // Selection state
  const [rowSelection, setRowSelection] = React.useState<RowSelectionState>(
    initialState?.rowSelection ?? {},
  );

  // Expansion state
  const [expanded, setExpanded] = React.useState<ExpandedState>(
    initialState?.expanded ?? {},
  );

  // Column pinning state
  const [columnPinning, setColumnPinning] = React.useState<ColumnPinningState>(
    initialState?.columnPinning ?? {},
  );

  // Search state
  const [search, setSearch] = useQueryState(
    searchKey,
    parseAsString.withOptions(queryStateOptions).withDefault(""),
  );

  // Page state
  const [page, setPage] = useQueryState(
    pageKey,
    parseAsInteger.withOptions(queryStateOptions).withDefault(1),
  );

  // Page size state
  const [perPage, setPerPage] = useQueryState(
    perPageKey,
    parseAsInteger
      .withOptions(queryStateOptions)
      .withDefault(initialState?.pagination?.pageSize ?? 50),
  );

  const pagination: PaginationState = React.useMemo(() => {
    return {
      pageIndex: Math.max(0, page - 1),
      pageSize: perPage,
    };
  }, [page, perPage]);

  const onPaginationChange = React.useCallback(
    (updaterOrValue: Updater<PaginationState>) => {
      if (typeof updaterOrValue === "function") {
        const newPagination = updaterOrValue(pagination);
        void setPage(newPagination.pageIndex + 1);
        void setPerPage(newPagination.pageSize);
      } else {
        void setPage(updaterOrValue.pageIndex + 1);
        void setPerPage(updaterOrValue.pageSize);
      }
    },
    [pagination, setPage, setPerPage],
  );

  const columnIds = React.useMemo(() => {
    return new Set(
      columns.map((column) => column.id).filter(Boolean) as string[],
    );
  }, [columns]);

  // Sorting state
  const [sorting, setSorting] = useQueryState(
    sortKey,
    getSortingStateParser<TData>(columnIds)
      .withOptions(queryStateOptions)
      .withDefault(initialState?.sorting ?? []),
  );

  const onSortingChange = React.useCallback(
    (updaterOrValue: Updater<SortingState>) => {
      if (typeof updaterOrValue === "function") {
        const newSorting = updaterOrValue(sorting);
        setSorting(newSorting as ExtendedColumnSort<TData>[]);
      } else {
        setSorting(updaterOrValue as ExtendedColumnSort<TData>[]);
      }
    },
    [sorting, setSorting],
  );

  // Filterable columns
  const filterableColumns = React.useMemo(() => {
    if (enableAdvancedFilter) return [];
    return columns.filter((column) => column.enableColumnFilter);
  }, [columns, enableAdvancedFilter]);

  const filterParsers = React.useMemo(() => {
    if (enableAdvancedFilter) return {};

    return filterableColumns.reduce<
      Record<string, SingleParser<string> | SingleParser<string[]>>
    >((acc, column) => {
      if (column.meta?.options) {
        acc[column.id ?? ""] = parseAsArrayOf(
          parseAsString,
          ARRAY_SEPARATOR,
        ).withOptions(queryStateOptions);
      } else {
        acc[column.id ?? ""] = parseAsString.withOptions(queryStateOptions);
      }
      return acc;
    }, {});
  }, [filterableColumns, queryStateOptions, enableAdvancedFilter]);

  const [filterValues, setFilterValues] = useQueryStates(filterParsers);

  const debouncedSetFilterValues = useDebouncedCallback(
    (values: typeof filterValues) => {
      void setPage(1);
      void setFilterValues(values);
    },
    debounceMs,
  );

  const initialColumnFilters: ColumnFiltersState = React.useMemo(() => {
    if (enableAdvancedFilter) return [];

    return Object.entries(filterValues).reduce<ColumnFiltersState>(
      (filters, [key, value]) => {
        if (value !== null) {
          const processedValue = Array.isArray(value)
            ? value
            : typeof value === "string" && /[^a-zA-Z0-9]/.test(value)
              ? value.split(/[^a-zA-Z0-9]+/).filter(Boolean)
              : [value];

          filters.push({
            id: key,
            value: processedValue,
          });
        }
        return filters;
      },
      [],
    );
  }, [filterValues, enableAdvancedFilter]);

  const [columnFilters, setColumnFilters] =
    React.useState<ColumnFiltersState>(initialColumnFilters);

  const onColumnFiltersChange = React.useCallback(
    (updaterOrValue: Updater<ColumnFiltersState>) => {
      if (enableAdvancedFilter) return;

      setColumnFilters((prev) => {
        const next =
          typeof updaterOrValue === "function"
            ? updaterOrValue(prev)
            : updaterOrValue;

        const filterUpdates = next.reduce<
          Record<string, string | string[] | null>
        >((acc, filter) => {
          if (filterableColumns.find((column) => column.id === filter.id)) {
            acc[filter.id] = filter.value as string | string[];
          }
          return acc;
        }, {});

        for (const prevFilter of prev) {
          if (!next.some((filter) => filter.id === prevFilter.id)) {
            filterUpdates[prevFilter.id] = null;
          }
        }

        debouncedSetFilterValues(filterUpdates);
        return next;
      });
    },
    [debouncedSetFilterValues, filterableColumns, enableAdvancedFilter],
  );

  // Reset Everything action
  const resetAll = React.useCallback(() => {
    void setSearch("");
    void setPage(1);
    setSorting(initialState?.sorting ?? []);
    setColumnFilters([]);
    setColumnVisibility(initialState?.columnVisibility ?? {});
    setColumnPinning(initialState?.columnPinning ?? {});
    setRowSelection({});
    setExpanded({});
    setDensity(defaultDensity);
    setActivePresetId(null);

    // Clear URL filter states
    const clearedFilters = Object.keys(filterParsers).reduce<
      Record<string, null>
    >((acc, key) => {
      acc[key] = null;
      return acc;
    }, {});
    void setFilterValues(clearedFilters);
  }, [
    setSearch,
    setPage,
    setSorting,
    initialState,
    defaultDensity,
    filterParsers,
    setFilterValues,
  ]);

  // Apply Preset action
  const applyPreset = React.useCallback(
    (preset: TablePreset<TData>) => {
      setActivePresetId(preset.id);
      void setPage(1);

      if (typeof preset.search === "string") {
        void setSearch(preset.search);
      }

      if (preset.sorting) {
        setSorting(preset.sorting);
      }

      if (preset.filters) {
        const newFilters: ColumnFiltersState = [];
        const urlUpdates: Record<string, string | string[] | null> = {};

        for (const [key, value] of Object.entries(preset.filters)) {
          if (value !== undefined && value !== null) {
            newFilters.push({ id: key, value });
            urlUpdates[key] = value as string | string[];
          }
        }

        setColumnFilters(newFilters);
        void setFilterValues(urlUpdates);
      }
    },
    [setPage, setSearch, setSorting, setFilterValues],
  );

  const table = useReactTable({
    ...tableProps,
    columns,
    initialState,
    pageCount,
    state: {
      pagination,
      sorting,
      columnVisibility,
      columnPinning,
      rowSelection,
      columnFilters,
      expanded,
    },
    defaultColumn: {
      ...tableProps.defaultColumn,
      enableColumnFilter: false,
    },
    enableRowSelection: true,
    enableColumnPinning: true,
    onRowSelectionChange: setRowSelection,
    onExpandedChange: setExpanded,
    onPaginationChange,
    onSortingChange,
    onColumnFiltersChange,
    onColumnVisibilityChange,
    onColumnPinningChange: setColumnPinning,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFacetedRowModel: getFacetedRowModel(),
    getFacetedUniqueValues: getFacetedUniqueValues(),
    getFacetedMinMaxValues: getFacetedMinMaxValues(),
    getExpandedRowModel: getExpandedRowModel(),
    manualPagination,
    manualSorting,
    manualFiltering,
    meta: {
      ...tableProps.meta,
      density,
      setDensity,
      tableId,
      defaultVisibility,
      queryKeys: {
        page: pageKey,
        perPage: perPageKey,
        sort: sortKey,
        filters: filtersKey,
        joinOperator: joinOperatorKey,
        search: searchKey,
      },
    },
  });

  return {
    table,
    search,
    setSearch,
    page,
    setPage,
    perPage,
    setPerPage,
    sorting,
    setSorting,
    columnFilters,
    setColumnFilters,
    density,
    setDensity,
    activePresetId,
    applyPreset,
    resetAll,
    resetColumns,
    defaultVisibility,
    presets,
  };
}
