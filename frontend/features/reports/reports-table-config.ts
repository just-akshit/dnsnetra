import type { TableTabItem } from "@/lib/data-table/types"

export const reportTabs: TableTabItem[] = [
  { id: "domains", label: "Domain Activity Report" },
  { id: "clients", label: "Client Activity Report" },
  { id: "queries", label: "Query Forensic Audit" },
  { id: "malicious", label: "Malicious Threat Log" },
]
