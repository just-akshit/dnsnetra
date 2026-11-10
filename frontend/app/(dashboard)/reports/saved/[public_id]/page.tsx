"use client"

import * as React from "react"
import Link from "next/link"
import { useParams } from "next/navigation"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { dnsnetraApi } from "@/lib/data-table/api-client"
import type { SavedReportDetail } from "@/lib/reporting/types"

const VERDICTS = ["Benign", "Malicious", "Review Needed", "Unknown"] as const

type QueryEvent = {
  id?: number
  timestamp?: string
  client_ip?: string
  domain?: string
  query_type?: string
  response_code?: string | null
  final_label?: string
  ti_source?: string | null
}

type Registration = {
  status?: string
  source?: string
  registrar?: string | null
  registrar_id?: string | null
  created_at?: string | null
  updated_at?: string | null
  expires_at?: string | null
  domain_status?: string[]
  nameservers?: string[]
  error?: string | null
}

type DNSRecords = {
  status?: string
  a?: string[]
  aaaa?: string[]
  cname?: string[]
  ns?: string[]
  mx?: Array<{ priority: number; exchange: string }>
  error?: string | null
}

type ProviderEvidence = {
  provider?: string
  status?: string
  malicious?: number
  suspicious?: number
  harmless?: number
  undetected?: number
  total?: number
  pulse_count?: number
  error?: string | null
}

type LiveIntel = {
  indicator?: string
  kind?: string
  verdict?: {
    state?: string
    confidence?: number
    reasons?: string[]
    sources_with_data?: number
    sources_queried?: number
  }
  providers?: ProviderEvidence[]
  registration?: Registration | null
  dns_records?: DNSRecords | null
  ip_context?: {
    asn?: number | null
    as_owner?: string | null
    country?: string | null
    network?: string | null
    reputation?: number | null
  } | null
  checked_at?: string
}

type Dossier = {
  domain?: string
  client_ip?: string
  profile?: Record<string, unknown>
  recent_queries?: QueryEvent[]
  live_intel?: LiveIntel | null
  registration?: Registration | null
  dns_records?: DNSRecords | null
  threat_intel?: {
    reputation?: Record<string, unknown> | null
    daily_review?: Record<string, unknown> | null
    reviewed_clean?: Record<string, unknown> | null
  }
}

type SnapshotSummary = {
  total_queries?: number
  unique_clients?: number
  unique_domains?: number
  verdict_breakdown?: {
    benign?: number
    malicious?: number
    review_needed?: number
    unknown?: number
  }
  malicious_query_percentage?: number
}

type TimelineBucket = {
  timestamp?: string
  total_queries?: number
  benign_queries?: number
  malicious_queries?: number
  review_needed_queries?: number
  unknown_queries?: number
}

type ReportSnapshot = {
  observed_in_network?: boolean
  entity?: { type?: string; value?: string }
  window?: { start?: string | null; end?: string | null; label?: string | null }
  row_count?: number
  summary?: SnapshotSummary
  timeline?: TimelineBucket[]
  dossier?: Dossier
  provenance?: {
    sources?: string[]
    live_intel_checked_at?: string | null
    timeline_available?: boolean
    generated_at?: string
  }
}

function present(value: unknown): value is string | number | boolean {
  return value !== null && value !== undefined && value !== ""
}

function asNode(value: unknown, fallback = "—"): React.ReactNode {
  return present(value) ? String(value) : fallback
}

function DetailRow({
  label,
  value,
  mono = false,
}: {
  label: string
  value: React.ReactNode
  mono?: boolean
}) {
  if (!present(value) && typeof value !== "number") return null
  return (
    <div className="flex items-center justify-between gap-4 border-b border-border/40 py-1 last:border-0">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className={mono ? "font-mono text-xs text-foreground" : "text-xs text-foreground"}>
        {value}
      </span>
    </div>
  )
}

function StatCard({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="font-mono text-2xl font-semibold">{value}</p>
      </CardContent>
    </Card>
  )
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {}
}

export default function ReportDetailPage() {
  const params = useParams<{ public_id: string }>()
  const publicId = decodeURIComponent(params.public_id)
  const [report, setReport] = React.useState<SavedReportDetail | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [conclusion, setConclusion] = React.useState("")
  const [verdict, setVerdict] = React.useState("")
  const [saving, setSaving] = React.useState(false)
  const [creating, setCreating] = React.useState(false)
  const [exporting, setExporting] = React.useState<"csv" | "xlsx" | null>(null)

  const loadReport = React.useCallback(
    () =>
      dnsnetraApi
        .getSavedReport(publicId)
        .then((data) => {
          setReport(data)
          setConclusion(data.conclusion ?? "")
          setVerdict(data.verdict ?? "")
          setError(null)
        })
        .catch(() => {
          setError("Failed to load report.")
          toast.error("Failed to load report.")
        }),
    [publicId]
  )

  React.useEffect(() => {
    loadReport()
  }, [loadReport])

  async function markReviewed() {
    if (!report) return
    setSaving(true)
    try {
      const updated = await dnsnetraApi.reviewSavedReport(publicId, {
        status: "reviewed",
        conclusion,
        verdict: verdict || undefined,
      })
      setReport(updated)
      setConclusion(updated.conclusion ?? "")
      setVerdict(updated.verdict ?? "")
      toast.success("Report marked reviewed.")
    } catch {
      toast.error("Review failed.")
    } finally {
      setSaving(false)
    }
  }

  async function exportReport(format: "csv" | "xlsx") {
    setExporting(format)
    try {
      await dnsnetraApi.downloadSavedReport(publicId, format)
      toast.success("Export started.")
    } catch {
      toast.error("Export failed.")
    } finally {
      setExporting(null)
    }
  }

  if (error) {
    return (
      <div className="flex flex-col items-start gap-2 p-6">
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
        <Button variant="outline" size="sm" onClick={loadReport}>
          Retry
        </Button>
      </div>
    )
  }

  if (!report) {
    return <p className="p-6 text-sm text-muted-foreground">Loading report…</p>
  }

  const snapshot = report.snapshot as ReportSnapshot
  const dossier = snapshot.dossier ?? {}
  const profile = asRecord(dossier.profile)
  const summary = snapshot.summary ?? {}
  const breakdown = summary.verdict_breakdown ?? {}
  const timeline = snapshot.timeline ?? []
  const hasProfile = Object.keys(profile).length > 0
  const live = dossier.live_intel ?? {}
  const registration = dossier.registration
  const threatIntel = dossier.threat_intel ?? {}
  const provenance = snapshot.provenance ?? {}
  const entityValue = dossier.domain ?? dossier.client_ip ?? snapshot.entity?.value
  const entityType = snapshot.entity?.type ?? report.entity_type
  const recentQueries = (dossier.recent_queries ?? []).slice(0, 50)

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{report.title}</h1>
          <p className="font-mono text-[11px] text-muted-foreground">
            {report.public_id} · {report.kind} · {report.created_at}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={creating}
            aria-busy={creating}
            onClick={async () => {
              if (creating) return
              setCreating(true)
              try {
                const created = await dnsnetraApi.createCase({
                  title: `Investigate ${report.entity_value ?? report.title}`,
                  priority: "medium",
                  entity_type: report.entity_type ?? undefined,
                  entity_value: report.entity_value ?? undefined,
                  report_id: report.public_id,
                })
                setReport((prev) =>
                  prev ? { ...prev, case_public_id: created.public_id } : prev
                )
                toast.success(`Case ${created.public_id} opened.`)
              } catch {
                toast.error("Could not open a case.")
              } finally {
                setCreating(false)
              }
            }}
          >
            Open case
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => exportReport("csv")}
            disabled={exporting !== null}
          >
            Export CSV
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => exportReport("xlsx")}
            disabled={exporting !== null}
          >
            Export XLSX
          </Button>
          <Badge variant="outline">{report.status}</Badge>
          {report.case_public_id && (
            <Link
              href={`/cases/${encodeURIComponent(report.case_public_id)}`}
              className="font-mono text-[10px] text-primary hover:underline"
            >
              {report.case_public_id}
            </Link>
          )}
          {report.reviewed_at && (
            <span className="font-mono text-[10px] text-muted-foreground">
              {report.reviewed_at}
              {report.reviewed_by != null ? ` · by ${report.reviewed_by}` : ""}
            </span>
          )}
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Identity &amp; registration</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-1">
          <DetailRow label="Entity" value={entityValue} mono />
          <DetailRow label="Entity type" value={entityType} />
          <DetailRow label="Window" value={snapshot.window?.label} />
          {registration && (
            <>
              <DetailRow label="Registration status" value={registration.status} />
              <DetailRow label="Registrar" value={registration.registrar} />
              <DetailRow label="Registered" value={registration.created_at} mono />
              <DetailRow label="Updated" value={registration.updated_at} mono />
              <DetailRow label="Expires" value={registration.expires_at} mono />
              <DetailRow
                label="Nameservers"
                value={registration.nameservers?.join(", ")}
                mono
              />
              <DetailRow
                label="Domain status"
                value={registration.domain_status?.join(", ")}
              />
              {registration.error && (
                <p role="status" className="pt-1 text-xs text-muted-foreground">
                  Registration lookup: {registration.error}
                </p>
              )}
            </>
          )}
          {!entityValue && !registration && (
            <p className="text-sm text-muted-foreground">No identity recorded in this snapshot.</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Local telemetry</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {snapshot.observed_in_network === false && (
            <p className="text-sm text-muted-foreground">No local telemetry for this window.</p>
          )}
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard label="Total queries" value={asNode(summary.total_queries)} />
            <StatCard label="Unique clients" value={asNode(summary.unique_clients)} />
            <StatCard label="Unique domains" value={asNode(summary.unique_domains)} />
            <StatCard label="Malicious" value={asNode(breakdown.malicious)} />
            <StatCard label="Review needed" value={asNode(breakdown.review_needed)} />
          </div>
          <div className="grid gap-x-6 gap-y-1 sm:grid-cols-2">
            <DetailRow label="Benign queries" value={breakdown.benign} mono />
            <DetailRow label="Unknown queries" value={breakdown.unknown} mono />
            <DetailRow
              label="Malicious %"
              value={
                present(summary.malicious_query_percentage)
                  ? `${summary.malicious_query_percentage}%`
                  : undefined
              }
              mono
            />
            <DetailRow label="Rows in window" value={snapshot.row_count} mono />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Timeline</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {timeline.length === 0 ? (
            <p className="p-4 text-sm text-muted-foreground">No timeline for this window.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs">Timestamp</TableHead>
                  <TableHead className="text-xs">Total</TableHead>
                  <TableHead className="text-xs">Benign</TableHead>
                  <TableHead className="text-xs">Malicious</TableHead>
                  <TableHead className="text-xs">Review needed</TableHead>
                  <TableHead className="text-xs">Unknown</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {timeline.map((bucket, index) => (
                  <TableRow key={bucket.timestamp ?? index}>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {bucket.timestamp ?? "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {bucket.total_queries ?? 0}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {bucket.benign_queries ?? 0}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {bucket.malicious_queries ?? 0}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {bucket.review_needed_queries ?? 0}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {bucket.unknown_queries ?? 0}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {hasProfile && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Lifetime profile</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-1">
            <p className="pb-1 text-xs text-muted-foreground">
              All-time counters for this entity, not limited to the report window.
            </p>
            <div className="grid gap-x-6 gap-y-1 sm:grid-cols-2">
              <DetailRow label="First seen" value={profile.first_seen as string} mono />
              <DetailRow label="Last seen" value={profile.last_seen as string} mono />
              <DetailRow label="Total queries" value={profile.total_queries as number} mono />
              <DetailRow
                label={profile.unique_domains !== undefined ? "Unique domains" : "Unique clients"}
                value={
                  (profile.unique_domains !== undefined
                    ? profile.unique_domains
                    : profile.unique_clients) as number
                }
                mono
              />
              <DetailRow label="Benign queries" value={profile.benign_queries as number} mono />
              <DetailRow label="Malicious queries" value={profile.malicious_queries as number} mono />
              <DetailRow
                label="Review needed queries"
                value={profile.review_needed_queries as number}
                mono
              />
              <DetailRow label="Unknown queries" value={profile.unknown_queries as number} mono />
              <DetailRow label="Last label" value={profile.last_label as string} />
              <DetailRow label="Last TI source" value={profile.last_ti_source as string} mono />
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Recent queries</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {recentQueries.length === 0 ? (
            <p className="p-4 text-sm text-muted-foreground">No recent queries in this snapshot.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs">Timestamp</TableHead>
                  <TableHead className="text-xs">Client</TableHead>
                  <TableHead className="text-xs">Domain</TableHead>
                  <TableHead className="text-xs">Type</TableHead>
                  <TableHead className="text-xs">Response</TableHead>
                  <TableHead className="text-xs">Verdict</TableHead>
                  <TableHead className="text-xs">TI source</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recentQueries.map((query, index) => (
                  <TableRow key={query.id ?? index}>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {query.timestamp ?? "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{query.client_ip ?? "—"}</TableCell>
                    <TableCell className="font-mono text-xs">{query.domain ?? "—"}</TableCell>
                    <TableCell className="font-mono text-xs">{query.query_type ?? "—"}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {query.response_code ?? "—"}
                    </TableCell>
                    <TableCell className="text-xs">{query.final_label ?? "—"}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {query.ti_source ?? "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Persisted intelligence</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {threatIntel.reputation && (
              <div className="flex flex-col gap-1">
                <p className="text-xs font-medium">Reputation match</p>
                <DetailRow label="Status" value={String(threatIntel.reputation.status ?? "—")} />
                <DetailRow label="Source" value={String(threatIntel.reputation.source ?? "—")} mono />
                <DetailRow
                  label="Matched domain"
                  value={threatIntel.reputation.matched_domain as string}
                  mono
                />
                <DetailRow label="Last seen" value={threatIntel.reputation.last_seen as string} mono />
              </div>
            )}
            {threatIntel.daily_review && (
              <div className="flex flex-col gap-1">
                <p className="text-xs font-medium">Daily review queue</p>
                <DetailRow label="Status" value={String(threatIntel.daily_review.status ?? "—")} />
                <DetailRow
                  label="Reason"
                  value={threatIntel.daily_review.review_reason as string}
                />
                <DetailRow
                  label="Next check"
                  value={threatIntel.daily_review.next_check_at as string}
                  mono
                />
              </div>
            )}
            {threatIntel.reviewed_clean && (
              <div className="flex flex-col gap-1">
                <p className="text-xs font-medium">Analyst reviewed clean</p>
                <DetailRow
                  label="Status"
                  value={String(threatIntel.reviewed_clean.status ?? "—")}
                />
                <DetailRow
                  label="Verification"
                  value={threatIntel.reviewed_clean.verification_source as string}
                />
                <DetailRow
                  label="Verified"
                  value={threatIntel.reviewed_clean.verified_at as string}
                  mono
                />
              </div>
            )}
            {!threatIntel.reputation && !threatIntel.daily_review && !threatIntel.reviewed_clean && (
              <p className="text-sm text-muted-foreground">
                No persisted intelligence recorded for this entity.
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Provenance</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-1">
            <DetailRow
              label="Sources"
              value={provenance.sources?.length ? provenance.sources.join(", ") : undefined}
              mono
            />
            <DetailRow label="Generated" value={provenance.generated_at} mono />
            <DetailRow
              label="Live intel checked"
              value={provenance.live_intel_checked_at}
              mono
            />
            <DetailRow
              label="Timeline available"
              value={present(provenance.timeline_available) ? String(provenance.timeline_available) : undefined}
            />
            {!provenance.sources?.length &&
              !provenance.generated_at &&
              !provenance.live_intel_checked_at && (
                <p className="text-sm text-muted-foreground">No provenance recorded.</p>
              )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Live intelligence</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {!live.verdict && !live.providers?.length && !live.checked_at ? (
            <p className="text-sm text-muted-foreground">No live intelligence recorded.</p>
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline">{live.verdict?.state ?? "unknown"}</Badge>
                {live.verdict?.confidence !== undefined && (
                  <span className="font-mono text-xs text-muted-foreground">
                    confidence {Math.round((live.verdict?.confidence ?? 0) * 100)}%
                  </span>
                )}
                {live.checked_at && (
                  <span className="font-mono text-xs text-muted-foreground">
                    checked {live.checked_at}
                  </span>
                )}
              </div>
              {live.verdict?.reasons?.length ? (
                <p className="text-xs text-muted-foreground">
                  {live.verdict.reasons.join(" · ")}
                </p>
              ) : null}
              {(live.verdict?.sources_with_data !== undefined ||
                live.verdict?.sources_queried !== undefined) && (
                <p className="font-mono text-xs text-muted-foreground">
                  sources with data {live.verdict?.sources_with_data ?? "—"} /{" "}
                  {live.verdict?.sources_queried ?? "—"}
                </p>
              )}
              {live.providers?.length ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="text-xs">Provider</TableHead>
                      <TableHead className="text-xs">Status</TableHead>
                      <TableHead className="text-xs">Malicious</TableHead>
                      <TableHead className="text-xs">Suspicious</TableHead>
                      <TableHead className="text-xs">Harmless</TableHead>
                      <TableHead className="text-xs">Total</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {live.providers.map((provider, index) => (
                      <TableRow key={`${provider.provider ?? "provider"}-${index}`}>
                        <TableCell className="font-mono text-xs">{provider.provider ?? "—"}</TableCell>
                        <TableCell className="text-xs">{provider.status ?? "—"}</TableCell>
                        <TableCell className="font-mono text-xs">{provider.malicious ?? 0}</TableCell>
                        <TableCell className="font-mono text-xs">{provider.suspicious ?? 0}</TableCell>
                        <TableCell className="font-mono text-xs">{provider.harmless ?? 0}</TableCell>
                        <TableCell className="font-mono text-xs">{provider.total ?? 0}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : null}
              {live.ip_context && (
                <div className="grid gap-x-6 gap-y-1 sm:grid-cols-2">
                  <DetailRow label="ASN" value={live.ip_context.asn ?? undefined} mono />
                  <DetailRow label="AS owner" value={live.ip_context.as_owner ?? undefined} />
                  <DetailRow label="Country" value={live.ip_context.country ?? undefined} />
                  <DetailRow label="Network" value={live.ip_context.network ?? undefined} mono />
                </div>
              )}
              {live.dns_records && (
                <div className="grid gap-x-6 gap-y-1 sm:grid-cols-2">
                  <DetailRow label="A" value={live.dns_records.a?.join(", ")} mono />
                  <DetailRow label="AAAA" value={live.dns_records.aaaa?.join(", ")} mono />
                  <DetailRow label="CNAME" value={live.dns_records.cname?.join(", ")} mono />
                  <DetailRow label="NS" value={live.dns_records.ns?.join(", ")} mono />
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Analyst assessment</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <p className="text-xs text-muted-foreground">
            Current verdict:{" "}
            <span className="font-medium text-foreground">{report.verdict ?? "Not assessed"}</span>
          </p>
          <label htmlFor="conclusion" className="text-sm font-medium">
            Conclusion
          </label>
          <Input
            id="conclusion"
            value={conclusion}
            onChange={(event) => setConclusion(event.target.value)}
            placeholder="What did you conclude?"
          />
          <label htmlFor="assessed-verdict" className="text-sm font-medium">
            Assessed verdict
          </label>
          <select
            id="assessed-verdict"
            value={verdict}
            onChange={(event) => setVerdict(event.target.value)}
            className="h-8 w-fit rounded-lg border border-input bg-transparent px-2.5 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
          >
            <option value="">Not assessed</option>
            {VERDICTS.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
          <div>
            <Button
              size="sm"
              onClick={markReviewed}
              disabled={saving || !conclusion.trim()}
              aria-busy={saving}
            >
              {saving ? "Saving…" : "Mark reviewed"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
