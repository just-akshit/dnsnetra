import type { TableFilterConfig, TableTabItem } from "@/lib/data-table/types"

export const queryTabs: TableTabItem[] = [
  { id: "all", label: "Recent Queries" },
  { id: "suspicious", label: "Suspicious" },
  { id: "blocked", label: "Blocked" },
]

export const queryFilters: TableFilterConfig[] = [
  {
    id: "verdict",
    title: "Verdict",
    options: [
      { label: "Clean / Benign", value: "Benign" },
      { label: "Malicious", value: "Malicious" },
      { label: "Review Needed", value: "Review Needed" },
      { label: "Unknown", value: "Unknown" },
    ],
  },
  {
    id: "query_type",
    title: "Record Type",
    options: [
      { label: "A", value: "A" },
      { label: "AAAA", value: "AAAA" },
      { label: "CNAME", value: "CNAME" },
      { label: "TXT", value: "TXT" },
      { label: "MX", value: "MX" },
      { label: "PTR", value: "PTR" },
      { label: "SRV", value: "SRV" },
    ],
  },
]

export const queryDefaultSort = {
  id: "timestamp",
  desc: true,
}
