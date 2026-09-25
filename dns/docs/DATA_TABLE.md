# Reusable Enterprise Data Table System

The enterprise data table system provides a unified, production-ready table infrastructure built on **Dice UI Data Table**, **TanStack Table**, and **nuqs** for the entire DNS threat detection and security analytics dashboard.

---

## 1. Quick Start: Create a New Table in 5 Minutes

To add a new table (e.g. Clients, Threats, Cases), follow these 4 steps:

### Step 1: Define Your Row Type

```typescript
export interface ClientItem {
  client_ip: string;
  total_queries: number;
  unique_domains: number;
  threat_count: number;
  first_seen: string | null;
  last_seen: string | null;
}
```

### Step 2: Define Columns with Composable Helpers

```typescript
import {
  createSelectColumn,
  createExpandColumn,
  createIpColumn,
  createCountColumn,
  createTimestampColumn,
  createActionsColumn,
} from "@/components/data-table";

const columns = React.useMemo<ColumnDef<ClientItem>[]>(() => [
  createSelectColumn<ClientItem>(),
  createExpandColumn<ClientItem>(),
  createIpColumn<ClientItem>({
    accessorKey: "client_ip",
    title: "Client IP",
    linkToClient: true,
  }),
  createCountColumn<ClientItem>({
    accessorKey: "total_queries",
    title: "Total Queries",
    align: "right",
  }),
  createCountColumn<ClientItem>({
    accessorKey: "unique_domains",
    title: "Unique Domains",
    align: "right",
  }),
  createCountColumn<ClientItem>({
    accessorKey: "threat_count",
    title: "Threats",
    align: "right",
    highlightThreats: true,
  }),
  createTimestampColumn<ClientItem>({
    accessorKey: "last_seen",
    title: "Last Seen",
    align: "right",
  }),
  createActionsColumn<ClientItem>({
    actions: (row) => [
      {
        label: "Investigate Client",
        onClick: () => router.push(`/investigate/clients/${row.original.client_ip}`),
      },
      {
        label: "Copy IP",
        onClick: () => navigator.clipboard.writeText(row.original.client_ip),
      },
    ],
  }),
], [router]);
```

### Step 3: Initialize the Table Hook

```typescript
import { useDataTable } from "@/hooks/use-data-table";

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
  data: clients,
  columns,
  pageCount: meta.pages,
  presets: CLIENT_PRESETS,
  initialState: {
    columnPinning: { left: ["select", "client_ip"], right: ["actions"] },
    pagination: { pageSize: 50 },
  },
  getRowId: (row) => row.client_ip,
});
```

### Step 4: Render the Table and Toolbar

```tsx
import { DataTable, DataTableToolbar } from "@/components/data-table";

return (
  <DataTable
    table={table}
    loading={loading}
    error={error}
    onRetry={fetchClients}
    density={density}
    totalRows={meta.total}
    onResetAll={resetAll}
  >
    <DataTableToolbar
      table={table}
      search={search}
      onSearchChange={setSearch}
      searchPlaceholder="Search clients..."
      presets={CLIENT_PRESETS}
      activePresetId={activePresetId}
      onSelectPreset={applyPreset}
      onResetAll={resetAll}
      density={density}
      onDensityChange={setDensity}
    />
  </DataTable>
);
```

---

## 2. Key Capabilities & Configuration

### Column Pinning (Sticky Columns)
Columns can be pinned to the left or right:
- Programmatically via `initialState.columnPinning`
- Interactively by the user through the column header dropdown (**Pin to left**, **Pin to right**, **Unpin column**)

### Column Filtering & Types
Columns define their filter variant in `column.meta`:
- `text`: Substring match input
- `number`: Numeric comparison input
- `range`: Slider range filter
- `select`: Single-select facet filter dropdown
- `multiSelect`: Multi-select facet filter dropdown with badge counter
- `date`: Single calendar date picker
- `dateRange`: Date range picker

### Investigation Presets
Predefine analysis contexts for investigators:
```typescript
const DOMAIN_PRESETS: TablePreset<DomainItem>[] = [
  { id: "all", label: "All Domains", filters: { label: [] } },
  { id: "malicious", label: "Malicious", filters: { label: ["malicious"] } },
  { id: "suspicious", label: "Suspicious", filters: { label: ["suspicious"] } },
  { id: "clean", label: "Clean", filters: { label: ["clean"] } },
];
```

### Reset Everything
The `resetAll()` function atomically resets:
1. Search query
2. All column filters
3. Sorting back to initial state
4. Pagination back to page 1
5. Column visibility & pinning back to defaults
6. Density back to default

### Row Selection & Floating Action Bar
Enable row selection with `createSelectColumn<T>()` and pass the floating action bar to `DataTable`:
```tsx
<DataTable
  table={table}
  actionBar={
    <ActionBar open={selectedRows.length > 0} onOpenChange={(open) => !open && table.toggleAllRowsSelected(false)}>
      <ActionBarSelection>
        <span>{selectedRows.length} row(s) selected</span>
      </ActionBarSelection>
      <ActionBarGroup>
        <ActionBarItem onClick={handleBatchAction}>Perform Action</ActionBarItem>
        <ActionBarClose />
      </ActionBarGroup>
    </ActionBar>
  }
/>
```

### Expandable Rows
Enable expandable rows with `createExpandColumn<T>()` and pass `renderSubComponent`:
```tsx
<DataTable
  table={table}
  renderSubComponent={({ row }) => (
    <div className="p-3 bg-muted/10 rounded border border-border/50 text-xs">
      Telemetry details for {row.original.domain}...
    </div>
  )}
/>
```

---

## 3. Server-Side vs. Client-Side Modes

| Mode | Hook Options | Description |
|---|---|---|
| **Server-Side** (Default) | `manualPagination: true`, `manualSorting: true`, `manualFiltering: true` | The table triggers external API requests when page, sort, or filters change. |
| **Client-Side** | `manualPagination: false`, `manualSorting: false`, `manualFiltering: false` | The table performs sorting, filtering, and pagination locally in-memory on the loaded dataset. |

---

## 4. Current Backend API Capabilities & Boundaries

- **Supported Server-Side Query Parameters**:
  - `page`: Page index (1-based)
  - `page_size` / `pageSize`: Rows per page (up to 500)
  - `search`: Substring search on primary identity fields (`domain`, `client_ip`)
  - `label`: Verdict filter (`all`, `malicious`, `suspicious`, `clean`, `unknown`)
- **Client-Side Telemetry Parameters**:
  - Record types, response codes, and latency filtering on live event streams are processed client-side.
- **Batch / Bulk Actions**:
  - Selection is strictly scoped to visible loaded rows; global batch updates across unselected server pages require dedicated backend batch APIs.
