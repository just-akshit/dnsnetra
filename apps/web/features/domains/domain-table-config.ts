import type { TableFilterConfig } from "@/lib/data-table/types"

export const domainFilters: TableFilterConfig[] = [
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
]

export const domainDefaultSort = {
  id: "total_queries",
  desc: true,
}
