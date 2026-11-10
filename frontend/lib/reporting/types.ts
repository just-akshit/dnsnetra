export interface SavedReportSummary {
  public_id: string
  kind: string
  entity_type?: string | null
  entity_value?: string | null
  title: string
  status: string
  verdict?: string | null
  created_by?: number | null
  reviewed_at?: string | null
  case_public_id?: string | null
  created_at: string
}

export interface SavedReportDetail extends SavedReportSummary {
  window_start?: string | null
  window_end?: string | null
  filters: Record<string, unknown>
  snapshot: Record<string, unknown>
  conclusion?: string | null
  reviewed_by?: number | null
  row_count: number
}

export interface SavedReportList {
  total: number
  limit: number
  offset: number
  items: SavedReportSummary[]
}
