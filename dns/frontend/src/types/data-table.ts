import type { ColumnSort, Row, RowData } from "@tanstack/react-table";
import type * as React from "react";
import type { DataTableConfig } from "@/config/data-table";
import type { FilterItemSchema } from "@/lib/parsers";

declare module "@tanstack/react-table" {
  interface TableMeta<TData extends RowData> {
    queryKeys?: QueryKeys;
    density?: TableDensity;
    setDensity?: (density: TableDensity) => void;
    tableId?: string;
    defaultVisibility?: Record<string, boolean>;
  }

  interface ColumnMeta<TData extends RowData, TValue> {
    label?: string;
    placeholder?: string;
    variant?: FilterVariant;
    options?: Option[];
    range?: [number, number];
    unit?: string;
    icon?: React.ComponentType<React.ComponentProps<"svg">>;
    required?: boolean;
    hideable?: boolean;
    defaultVisible?: boolean;
    description?: string;
  }
}

export type TableDensity = "compact" | "default" | "comfortable";

export interface QueryKeys {
  page: string;
  perPage: string;
  sort: string;
  filters: string;
  joinOperator: string;
  search: string;
}

export interface Option {
  label: string;
  value: string;
  count?: number;
  icon?: React.ComponentType<React.ComponentProps<"svg">>;
}

export type FilterOperator = DataTableConfig["operators"][number];
export type FilterVariant = DataTableConfig["filterVariants"][number];
export type JoinOperator = DataTableConfig["joinOperators"][number];

export interface ExtendedColumnSort<TData> extends Omit<ColumnSort, "id"> {
  id: Extract<keyof TData, string>;
}

export interface ExtendedColumnFilter<TData> extends FilterItemSchema {
  id: Extract<keyof TData, string>;
}

export interface DataTableRowAction<TData> {
  row: Row<TData>;
  variant: "update" | "delete" | "view" | "investigate";
}

export interface TablePreset<TData> {
  id: string;
  label: string;
  description?: string;
  icon?: React.ComponentType<{ className?: string }>;
  search?: string;
  filters?: Partial<Record<Extract<keyof TData, string> | string, string | string[]>>;
  sorting?: ExtendedColumnSort<TData>[];
}
