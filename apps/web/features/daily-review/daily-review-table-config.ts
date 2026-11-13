import type { TableFilterConfig, TableTabItem } from "@/lib/data-table/types"

export const dailyReviewTabs: TableTabItem[] = [
  { id: "all", label: "All Review Queue" },
  { id: "review_needed", label: "Review Needed" },
  { id: "clean", label: "Clean" },
  { id: "malicious", label: "Malicious" },
]

export const dailyReviewFilters: TableFilterConfig[] = [
  {
    id: "status",
    title: "Status",
    options: [
      { label: "Review Needed", value: "review_needed" },
      { label: "Clean", value: "clean" },
      { label: "Malicious", value: "malicious" },
    ],
  },
]
