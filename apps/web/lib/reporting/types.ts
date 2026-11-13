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

export interface CaseSummary {
  public_id: string
  title: string
  status: string
  priority: string
  entity_type?: string | null
  entity_value?: string | null
  assigned_to?: number | null
  created_by?: number | null
  resolution?: string | null
  created_at: string
  updated_at: string
}

export interface CaseEvent {
  id: number
  kind: string
  actor_id?: number | null
  body?: string | null
  metadata: Record<string, unknown>
  created_at: string
}

export interface CaseDetail extends CaseSummary {
  description?: string | null
  resolved_by?: number | null
  resolved_at?: string | null
  closed_at?: string | null
  events: CaseEvent[]
  reports: string[]
}

export interface CaseList {
  total: number
  limit: number
  offset: number
  has_more: boolean
  items: CaseSummary[]
}
