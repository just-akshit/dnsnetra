"use client"

import * as React from "react"
import {
  ActivityIcon,
  AlertTriangleIcon,
  DatabaseIcon,
  GlobeIcon,
  HelpCircleIcon,
  NetworkIcon,
  ServerIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { formatDnsnetraTimestamp } from "@/lib/data-table/formatters"
import type { LiveIntelReport, LiveProviderEvidence } from "@/lib/data-table/api-client"

interface LiveIntelSectionProps {
  live?: LiveIntelReport | null
  kind: "domain" | "ip"
  observedInNetwork: boolean
}

const VERDICT_STYLES: Record<
  string,
  {
    label: string
    icon: React.ReactNode
    card: string
    text: string
  }
> = {
  malicious: {
    label: "Malicious",
    icon: <ShieldAlertIcon className="size-6" />,
    card: "border-rose-500/30 bg-rose-500/5",
    text: "text-rose-700 dark:text-rose-400",
  },
  suspicious: {
    label: "Suspicious",
    icon: <AlertTriangleIcon className="size-6" />,
    card: "border-amber-500/30 bg-amber-500/5",
    text: "text-amber-700 dark:text-amber-400",
  },
  clean: {
    label: "Clean",
    icon: <ShieldCheckIcon className="size-6" />,
    card: "border-emerald-500/30 bg-emerald-500/5",
    text: "text-emerald-700 dark:text-emerald-400",
  },
  unknown: {
    label: "Unknown",
    icon: <HelpCircleIcon className="size-6" />,
    card: "border-border bg-muted/20",
    text: "text-muted-foreground",
  },
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
}

function asStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : []
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null
}

function Chip({ children }: { children: React.ReactNode }) {
  return (
    <Badge variant="outline" className="font-mono text-[10px] font-normal">
      {children}
    </Badge>
  )
}

function RecordRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 py-1 border-b border-border/40 last:border-0">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-mono text-foreground text-right break-all">{value}</span>
    </div>
  )
}

function ProviderCard({ evidence }: { evidence: LiveProviderEvidence }) {
  const details = asRecord(evidence.details)
  const isVirusTotal = evidence.provider === "VirusTotal"
  const isOtx = evidence.provider === "AlienVault OTX"

  const categories = Object.values(asRecord(details.categories)).filter(
    (value): value is string => typeof value === "string"
  )
  const pulseNames = asStrings(details.pulse_names)
  const tags = asStrings(details.tags)
  const reputation = asNumber(details.reputation)

  const total = evidence.total || 0
  const segments = [
    { key: "malicious", value: evidence.malicious, className: "bg-rose-500" },
    { key: "suspicious", value: evidence.suspicious, className: "bg-amber-500" },
    { key: "harmless", value: evidence.harmless, className: "bg-emerald-500" },
    { key: "undetected", value: evidence.undetected, className: "bg-muted-foreground/30" },
  ]

  return (
    <Card className="bg-card border-border/80">
      <CardHeader className="pb-3 border-b border-border/60">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            {isVirusTotal ? (
              <ShieldAlertIcon className="size-4 text-primary" />
            ) : (
              <ActivityIcon className="size-4 text-primary" />
            )}
            <span>{evidence.provider}</span>
          </CardTitle>
          <Badge
            variant="outline"
            className="text-[10px] font-mono uppercase tracking-wide"
          >
            {evidence.status === "ok" ? "Data" : evidence.status === "no_data" ? "No data" : "Unavailable"}
          </Badge>
        </div>
        <CardDescription className="text-xs">
          {isVirusTotal
            ? "Live multi-engine scanning results."
            : isOtx
              ? "Open threat exchange pulse references."
              : "External reputation provider."}
        </CardDescription>
      </CardHeader>
      <CardContent className="pt-4 flex flex-col gap-3 text-xs">
        {evidence.status === "unavailable" ? (
          <p className="text-muted-foreground text-[11px]">
            {evidence.error || "Provider could not be reached."}
          </p>
        ) : isVirusTotal ? (
          <>
            {total > 0 ? (
              <>
                <div className="flex items-baseline justify-between">
                  <span className="font-mono text-lg font-semibold text-foreground">
                    {evidence.malicious}/{total}
                  </span>
                  <span className="text-[11px] text-muted-foreground">engines flagged malicious</span>
                </div>
                <div className="flex h-2 w-full overflow-hidden rounded-full bg-muted">
                  {segments.map((segment) =>
                    segment.value > 0 ? (
                      <div
                        key={segment.key}
                        className={segment.className}
                        style={{ width: `${(segment.value / total) * 100}%` }}
                        title={`${segment.key}: ${segment.value}`}
                      />
                    ) : null
                  )}
                </div>
                <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[11px]">
                  <span className="text-muted-foreground">Malicious: {evidence.malicious}</span>
                  <span className="text-muted-foreground">Suspicious: {evidence.suspicious}</span>
                  <span className="text-muted-foreground">Harmless: {evidence.harmless}</span>
                  <span className="text-muted-foreground">Undetected: {evidence.undetected}</span>
                </div>
              </>
            ) : (
              <p className="text-muted-foreground text-[11px]">
                Indexed by VirusTotal, but no scanning engine has analysed it yet.
              </p>
            )}

            {reputation !== null && (
              <RecordRow label="VT reputation" value={reputation > 0 ? `+${reputation}` : reputation} />
            )}
            {categories.length > 0 && (
              <div className="flex flex-col gap-1.5">
                <span className="text-muted-foreground text-[11px]">Categories</span>
                <div className="flex flex-wrap gap-1.5">
                  {Array.from(new Set(categories)).slice(0, 8).map((category) => (
                    <Chip key={category}>{category}</Chip>
                  ))}
                </div>
              </div>
            )}
            {tags.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {Array.from(new Set(tags)).slice(0, 8).map((tag) => (
                  <Chip key={tag}>{tag}</Chip>
                ))}
              </div>
            )}
          </>
        ) : isOtx ? (
          <>
            <div className="flex items-baseline justify-between">
              <span className="font-mono text-lg font-semibold text-foreground">
                {evidence.pulse_count}
              </span>
              <span className="text-[11px] text-muted-foreground">threat pulses</span>
            </div>
            {pulseNames.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {pulseNames.slice(0, 8).map((name) => (
                  <Chip key={name}>{name}</Chip>
                ))}
              </div>
            ) : (
              <p className="text-muted-foreground text-[11px]">
                No threat pulses reference this indicator.
              </p>
            )}
          </>
        ) : (
          <p className="text-muted-foreground text-[11px]">
            {evidence.status === "no_data" ? "No record found." : "Provider returned no usable data."}
          </p>
        )}
      </CardContent>
    </Card>
  )
}

export function LiveIntelSection({ live, kind, observedInNetwork }: LiveIntelSectionProps) {
  if (!live) {
    return (
      <Card className="border-dashed border-border bg-muted/10">
        <CardContent className="flex items-center gap-2 p-4 text-xs text-muted-foreground">
          <DatabaseIcon className="size-4" />
          <span>Live external intelligence is temporarily unavailable. Local telemetry is shown below.</span>
        </CardContent>
      </Card>
    )
  }

  const verdict = live.verdict
  const style = VERDICT_STYLES[verdict.state] ?? VERDICT_STYLES.unknown
  const registration = live.registration ?? null
  const dns = live.dns_records ?? null
  const ipContext = live.ip_context ?? null
  const confidence = Math.round((verdict.confidence ?? 0) * 100)

  return (
    <div className="flex flex-col gap-4">
      {/* Verdict hero */}
      <Card className={style.card}>
        <CardContent className="p-4 lg:p-5 flex flex-col gap-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-3">
              <div className={`flex size-11 items-center justify-center rounded-full bg-background/70 ${style.text}`}>
                {style.icon}
              </div>
              <div className="flex flex-col">
                <div className="flex items-center gap-2">
                  <span className={`text-lg font-semibold ${style.text}`}>{style.label}</span>
                  <Badge variant="outline" className="font-mono text-[10px]">
                    {confidence}% confidence
                  </Badge>
                </div>
                <span className="text-[11px] text-muted-foreground font-mono">{live.indicator}</span>
              </div>
            </div>
            <div className="flex flex-col items-start sm:items-end gap-1 text-[11px] text-muted-foreground">
              <span>
                {verdict.sources_with_data} of {verdict.sources_queried} sources returned data
              </span>
              <span className="font-mono">Checked {formatDnsnetraTimestamp(live.checked_at)} UTC</span>
            </div>
          </div>

          {verdict.reasons.length > 0 && (
            <ul className="flex flex-col gap-1 text-[11px] text-foreground/80">
              {verdict.reasons.map((reason, index) => (
                <li key={`${reason}-${index}`} className="flex gap-2">
                  <span className="text-muted-foreground">•</span>
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          )}

          <div className="flex items-center gap-2 text-[11px] text-muted-foreground border-t border-border/40 pt-3">
            {observedInNetwork ? (
              <>
                <DatabaseIcon className="size-3.5" />
                <span>Also observed in this network&apos;s DNS telemetry — local details are below.</span>
              </>
            ) : (
              <>
                <GlobeIcon className="size-3.5" />
                <span>
                  No DNS telemetry observed in this network. This verdict comes from live external sources.
                </span>
              </>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Provider evidence */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {live.providers.length > 0 ? (
          live.providers.map((evidence) => (
            <ProviderCard key={evidence.provider} evidence={evidence} />
          ))
        ) : (
          <Card className="md:col-span-2 border-border/80 bg-card">
            <CardContent className="p-4 text-xs text-muted-foreground">
              No external providers were queried for this indicator.
            </CardContent>
          </Card>
        )}
      </div>

      {/* Activity */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {kind === "domain" && (
          <Card className="bg-card border-border/80">
            <CardHeader className="pb-2 border-b border-border/60">
              <CardTitle className="text-xs font-semibold uppercase tracking-wider flex items-center gap-1.5 text-muted-foreground">
                <ServerIcon className="size-3.5" />
                <span>Live DNS Records</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-3 flex flex-col gap-2 text-[11px]">
              {dns && dns.status === "AVAILABLE" ? (
                <>
                  {asStrings(dns.a).length > 0 && (
                    <div className="flex flex-col gap-1">
                      <span className="text-muted-foreground">A</span>
                      <div className="flex flex-wrap gap-1.5">
                        {asStrings(dns.a).map((value) => <Chip key={value}>{value}</Chip>)}
                      </div>
                    </div>
                  )}
                  {asStrings(dns.aaaa).length > 0 && (
                    <div className="flex flex-col gap-1">
                      <span className="text-muted-foreground">AAAA</span>
                      <div className="flex flex-wrap gap-1.5">
                        {asStrings(dns.aaaa).map((value) => <Chip key={value}>{value}</Chip>)}
                      </div>
                    </div>
                  )}
                  {asStrings(dns.cname).length > 0 && (
                    <div className="flex flex-col gap-1">
                      <span className="text-muted-foreground">CNAME</span>
                      <div className="flex flex-wrap gap-1.5">
                        {asStrings(dns.cname).map((value) => <Chip key={value}>{value}</Chip>)}
                      </div>
                    </div>
                  )}
                  {asStrings(dns.ns).length > 0 && (
                    <div className="flex flex-col gap-1">
                      <span className="text-muted-foreground">NS</span>
                      <div className="flex flex-wrap gap-1.5">
                        {asStrings(dns.ns).map((value) => <Chip key={value}>{value}</Chip>)}
                      </div>
                    </div>
                  )}
                  {Array.isArray(dns.mx) && dns.mx.length > 0 && (
                    <div className="flex flex-col gap-1">
                      <span className="text-muted-foreground">MX</span>
                      <div className="flex flex-wrap gap-1.5">
                        {dns.mx.map((record) => (
                          <Chip key={`${record.priority}-${record.exchange}`}>
                            {record.priority} {record.exchange}
                          </Chip>
                        ))}
                      </div>
                    </div>
                  )}
                  {asStrings(dns.a).length === 0 &&
                    asStrings(dns.aaaa).length === 0 &&
                    asStrings(dns.cname).length === 0 &&
                    asStrings(dns.ns).length === 0 &&
                    (!Array.isArray(dns.mx) || dns.mx.length === 0) && (
                      <span className="text-muted-foreground">No records returned.</span>
                    )}
                </>
              ) : (
                <span className="text-muted-foreground">
                  {dns?.status === "NO_DATA"
                    ? "No DNS records found for this domain."
                    : dns?.error || "DNS records unavailable."}
                </span>
              )}
            </CardContent>
          </Card>
        )}

        {kind === "domain" && (
          <Card className="bg-card border-border/80">
            <CardHeader className="pb-2 border-b border-border/60">
              <CardTitle className="text-xs font-semibold uppercase tracking-wider flex items-center gap-1.5 text-muted-foreground">
                <GlobeIcon className="size-3.5" />
                <span>Registration (RDAP)</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-3 flex flex-col gap-1 text-[11px]">
              {registration && registration.status === "AVAILABLE" ? (
                <>
                  <RecordRow label="Registrar" value={registration.registrar || "—"} />
                  <RecordRow
                    label="Created"
                    value={formatDnsnetraTimestamp(registration.created_at)}
                  />
                  <RecordRow
                    label="Expires"
                    value={formatDnsnetraTimestamp(registration.expires_at)}
                  />
                  {asStrings(registration.nameservers).length > 0 && (
                    <div className="flex flex-col gap-1 pt-1">
                      <span className="text-muted-foreground">Nameservers</span>
                      <div className="flex flex-wrap gap-1.5">
                        {asStrings(registration.nameservers).slice(0, 6).map((value) => (
                          <Chip key={value}>{value}</Chip>
                        ))}
                      </div>
                    </div>
                  )}
                  {asStrings(registration.domain_status).length > 0 && (
                    <div className="flex flex-wrap gap-1.5 pt-1">
                      {asStrings(registration.domain_status).slice(0, 4).map((value) => (
                        <Chip key={value}>{value}</Chip>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <span className="text-muted-foreground">
                  {registration?.status === "NO_DATA"
                    ? "No registration record found for this domain."
                    : registration?.error || "Registration data unavailable."}
                </span>
              )}
            </CardContent>
          </Card>
        )}

        {kind === "ip" && (
          <Card className="md:col-span-2 bg-card border-border/80">
            <CardHeader className="pb-2 border-b border-border/60">
              <CardTitle className="text-xs font-semibold uppercase tracking-wider flex items-center gap-1.5 text-muted-foreground">
                <NetworkIcon className="size-3.5" />
                <span>Network Ownership</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-3 grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 text-[11px]">
              {ipContext ? (
                <>
                  <RecordRow label="ASN" value={ipContext.asn !== null && ipContext.asn !== undefined ? `AS${ipContext.asn}` : "—"} />
                  <RecordRow label="Owner" value={ipContext.as_owner || "—"} />
                  <RecordRow label="Country" value={ipContext.country || "—"} />
                  <RecordRow label="Network" value={ipContext.network || "—"} />
                  <RecordRow
                    label="VT reputation"
                    value={
                      ipContext.reputation !== null && ipContext.reputation !== undefined
                        ? ipContext.reputation > 0
                          ? `+${ipContext.reputation}`
                          : ipContext.reputation
                        : "—"
                    }
                  />
                </>
              ) : (
                <span className="text-muted-foreground sm:col-span-2">
                  No network ownership data available for this address.
                </span>
              )}
            </CardContent>
          </Card>
        )}
      </div>

      <p className="text-[10px] text-muted-foreground font-mono">
        Sources: {live.providers.map((provider) => provider.provider).join(", ") || "none"} · external lookups are sent to these providers
      </p>
    </div>
  )
}
