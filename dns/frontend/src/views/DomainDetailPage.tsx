"use client";

import React, { useEffect, useState, useCallback, useRef } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  ExternalLink,
  RefreshCw,
  Copy,
  Check,
  Search,
  ArrowRight,
  FileBarChart,
} from "lucide-react";
import apiClient from "@/lib/api-client";
import { useTimeRange } from "@/context/TimeRangeContext";
import { DomainInvestigationData } from "@/types/api";
import { VerdictBadge } from "@/components/security/VerdictBadge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  DomainThreatIntelCard,
  DomainQueryingClientsTable,
} from "@/components/investigation";
import { DomainEnrichmentCard } from "@/components/investigation/DomainEnrichmentCard";
import { validateDomainSearchInput } from "@/lib/domain-utils";

export const DomainDetailPage: React.FC = () => {
  const router = useRouter();
  const params = useParams();
  const rawDomain = params?.domain as string | undefined;
  const domain = rawDomain ? decodeURIComponent(rawDomain) : undefined;
  const { timeRange, registerRefreshHandler } = useTimeRange();

  const [data, setData] = useState<DomainInvestigationData | null>(null);
  const [loading, setLoading] = useState(true);
  // Distinguish API/network errors from "no intelligence" (unindexed)
  const [apiError, setApiError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [copied, setCopied] = useState(false);

  // Search bar state on detail page
  const [searchInput, setSearchInput] = useState("");
  const [searchError, setSearchError] = useState<string | null>(null);

  // Request sequence guard to prevent stale out-of-order responses overwriting current result
  const requestSeqRef = useRef(0);

  const fetchInvestigation = useCallback(
    async (forceExternal = false) => {
      if (!domain) return;

      // Assign a sequence number to this request
      const seq = ++requestSeqRef.current;

      if (forceExternal) {
        setIsRefreshing(true);
      } else {
        // Atomically clear previous result so stale data can't linger behind loading
        setData(null);
        setLoading(true);
      }
      setApiError(null);

      try {
        const startIso = timeRange.startDate ? timeRange.startDate.toISOString() : undefined;
        const endIso = timeRange.endDate ? timeRange.endDate.toISOString() : undefined;
        const res = await apiClient.getDomainInvestigation(domain, forceExternal, {
          start_time: startIso,
          end_time: endIso,
          window: timeRange.isCustom ? undefined : timeRange.preset,
        });

        // Discard stale responses from superseded requests
        if (seq !== requestSeqRef.current) return;

        setData(res.data);
      } catch (err: any) {
        if (seq !== requestSeqRef.current) return;

        // Differentiate API/network failure from "not found / no intelligence"
        const status = err?.response?.status;
        if (status === 400) {
          setApiError("Invalid domain format rejected by server.");
        } else if (status === 404) {
          // 404 here is a routing/application error (backend returns 200 for unindexed domains)
          setApiError("Investigation endpoint not found. Check the API configuration.");
        } else if (status >= 500) {
          setApiError("Unable to retrieve domain intelligence. The server encountered an error.");
        } else if (err?.message === "Network Error" || !err?.response) {
          setApiError("Unable to retrieve domain intelligence. Check your network connection.");
        } else {
          setApiError(
            err?.response?.data?.detail || err?.message || "Unable to retrieve domain intelligence."
          );
        }
      } finally {
        if (seq === requestSeqRef.current) {
          setLoading(false);
          setIsRefreshing(false);
        }
      }
    },
    [domain, timeRange.startDate, timeRange.endDate, timeRange.preset, timeRange.isCustom]
  );

  useEffect(() => {
    fetchInvestigation();
  }, [fetchInvestigation]);

  useEffect(() => {
    const unregister = registerRefreshHandler(() => fetchInvestigation());
    return () => unregister();
  }, [registerRefreshHandler, fetchInvestigation]);

  const handleCopy = () => {
    if (!domain) return;
    navigator.clipboard.writeText(domain);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const handleSearch = () => {
    const result = validateDomainSearchInput(searchInput);
    if (!result.valid) {
      setSearchError(result.error || "Please enter a valid domain.");
      return;
    }
    setSearchError(null);
    if (result.isIp) {
      router.push(`/investigate/clients/${encodeURIComponent(result.normalized)}`);
    } else {
      router.push(`/investigate/domains/${encodeURIComponent(result.normalized)}`);
    }
  };

  // Loading skeleton
  if (loading && !data) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-5 w-24 rounded" />
        <Skeleton className="h-28 w-full rounded-md" />
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3.5">
          <Skeleton className="h-44 rounded-md" />
          <Skeleton className="h-44 rounded-md" />
          <Skeleton className="h-44 rounded-md" />
        </div>
      </div>
    );
  }

  // API/network error — never convert to empty/benign state
  if (apiError && !data) {
    return (
      <div className="space-y-3">
        <Link
          href="/investigate/domains"
          className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Domains</span>
        </Link>
        <div className="p-6 text-center bg-card border border-border/70 rounded-md space-y-2">
          <p className="text-xs font-semibold text-destructive">Unable to retrieve domain intelligence.</p>
          <p className="text-xs text-muted-foreground">{apiError}</p>
          <button
            onClick={() => fetchInvestigation()}
            className="px-2.5 py-1 rounded bg-primary text-primary-foreground text-xs font-medium cursor-pointer"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  const classification = data?.classification;
  const localIntel = data?.local_intelligence;
  const extIntel = data?.external_intelligence;
  const dnsActivity = data?.dns_activity;
  const queryingClients = data?.querying_clients || [];
  const normalized = data?.domain;
  const enrichment = data?.enrichment;
  const reputation = data?.reputation;

  // Strict four-status vocabulary — no "suspicious" or "clean"
  const label = classification?.label;
  const isMalicious = label === "malicious";
  const isReviewNeeded = label === "review_needed";
  const isUnknown = !label || label === "unknown";

  const riskScoreBg = isMalicious
    ? "bg-red-500/15 text-red-500 border border-red-500/30"
    : isReviewNeeded
    ? "bg-amber-500/15 text-amber-500 border border-amber-500/30"
    : isUnknown
    ? "bg-secondary text-muted-foreground border border-border"
    : "bg-emerald-500/15 text-emerald-500 border border-emerald-500/30";

  // "No intelligence" state: 200 OK from backend but unindexed domain
  const isUnindexed =
    data !== null &&
    dnsActivity?.status === "NOT_OBSERVED" &&
    !reputation?.active_record &&
    classification?.source === "NO_DATA";

  return (
    <div className="space-y-4 pb-12">
      {/* Top Nav Row */}
      <div className="flex items-center justify-between gap-4">
        <Link
          href="/investigate/domains"
          className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors shrink-0"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Domains Investigation</span>
        </Link>

        {/* In-page domain search bar */}
        <div className="flex items-center gap-2 flex-1 max-w-md">
          <div className="relative flex items-center w-full h-8 rounded-lg border bg-muted/30 focus-within:border-primary focus-within:ring-1 focus-within:ring-primary/20">
            <Search className="absolute left-2.5 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
            <input
              type="text"
              value={searchInput}
              onChange={(e) => { setSearchInput(e.target.value); setSearchError(null); }}
              onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); handleSearch(); } }}
              placeholder="Search another domain..."
              aria-invalid={!!searchError}
              className="flex-1 pl-8 pr-2 bg-transparent text-xs outline-none text-foreground placeholder:text-muted-foreground"
            />
          </div>
          <button
            type="button"
            onClick={handleSearch}
            className="flex items-center gap-1 px-2.5 h-8 bg-primary hover:bg-primary/90 text-primary-foreground text-xs font-medium rounded-lg transition-colors cursor-pointer shrink-0"
          >
            <span>Go</span>
            <ArrowRight className="w-3 h-3" />
          </button>
          {searchError && (
            <span className="text-[10px] text-destructive whitespace-nowrap">{searchError}</span>
          )}
        </div>

        <span className="text-[11px] font-mono text-muted-foreground shrink-0">
          Lookup: {data?.duration_ms ?? "—"}ms
        </span>
      </div>

      {/* Unindexed domain — no intelligence state */}
      {isUnindexed && (
        <div className="p-4 rounded-md border border-border/60 bg-muted/20 text-xs text-muted-foreground">
          <p className="font-medium text-foreground mb-1">No intelligence data found for this domain.</p>
          <p>This domain has no observed DNS telemetry, reputation record, or threat intelligence match. It is not classified as BENIGN or MALICIOUS — its status is <span className="font-mono">REVIEW_NEEDED</span> pending evidence.</p>
        </div>
      )}

      {/* Primary Target Forensics Banner Card */}
      <div className="p-5 bg-card border border-border/70 rounded-lg shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-5">
        <div className="space-y-2 min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-2xl font-bold font-mono text-foreground tracking-tight truncate">
              {domain}
            </h1>

            <button
              type="button"
              onClick={handleCopy}
              title="Copy domain name"
              className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
            </button>

            {label && <VerdictBadge verdict={label} />}

            {typeof classification?.risk_score === "number" && (
              <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold font-mono ${riskScoreBg}`}>
                Risk: {classification.risk_score}/100
              </span>
            )}

            {typeof classification?.confidence === "number" && (
              <span className="text-[11px] text-muted-foreground font-mono">
                {Math.round(classification.confidence * 100)}% Confidence
              </span>
            )}
          </div>

          {classification?.reason && (
            <p className="text-xs text-muted-foreground leading-relaxed max-w-3xl">
              {classification.reason}
            </p>
          )}

          {/* Domain Metadata Pills */}
          <div className="flex flex-wrap items-center gap-3 pt-1 text-xs text-muted-foreground">
            {normalized?.registered_domain && (
              <span>
                Apex: <strong className="text-foreground font-mono">{normalized.registered_domain}</strong>
              </span>
            )}
            {normalized?.tld && (
              <>
                <span>•</span>
                <span>TLD: <strong className="text-foreground font-mono">.{normalized.tld}</strong></span>
              </>
            )}
            <span>•</span>
            <span>
              Observed Queries: <strong className="text-foreground font-mono">{(dnsActivity?.query_count || 0).toLocaleString()}</strong>
            </span>
            <span>•</span>
            <span>
              Clients: <strong className="text-foreground font-mono">{queryingClients.length}</strong>
            </span>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <Link
            href={`/reports?entity=${encodeURIComponent(domain || "")}&entity_type=domain`}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-[#2F6FED]/30 bg-[#2F6FED]/10 hover:bg-[#2F6FED]/20 text-xs font-semibold text-[#2F6FED] transition-colors cursor-pointer shadow-xs"
          >
            <FileBarChart className="w-3.5 h-3.5" />
            <span>View Full Report</span>
          </Link>

          <button
            onClick={() => fetchInvestigation(true)}
            disabled={isRefreshing}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-border/80 bg-background hover:bg-muted text-xs font-medium text-foreground transition-colors disabled:opacity-50 cursor-pointer shadow-xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
            <span>Force Live Lookup</span>
          </button>

          <a
            href={`https://www.virustotal.com/gui/domain/${domain}`}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 px-3 py-1.5 rounded-md border border-border/80 bg-background hover:bg-muted text-xs font-medium text-foreground transition-colors shadow-xs"
          >
            <span>VirusTotal</span>
            <ExternalLink className="w-3 h-3 text-muted-foreground" />
          </a>

          <a
            href={`https://otx.alienvault.com/indicator/domain/${domain}`}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 px-3 py-1.5 rounded-md border border-border/80 bg-background hover:bg-muted text-xs font-medium text-foreground transition-colors shadow-xs"
          >
            <span>AlienVault OTX</span>
            <ExternalLink className="w-3 h-3 text-muted-foreground" />
          </a>
        </div>
      </div>

      {/* Inline API error banner (when data exists but refresh failed) */}
      {apiError && data && (
        <div className="px-4 py-2 rounded border border-destructive/30 bg-destructive/10 flex items-center justify-between gap-3">
          <p className="text-xs text-destructive">{apiError}</p>
          <button
            onClick={() => fetchInvestigation()}
            className="text-xs px-2 py-0.5 rounded bg-destructive/20 hover:bg-destructive/30 text-destructive font-medium cursor-pointer"
          >
            Retry
          </button>
        </div>
      )}

      {/* Threat Intelligence & DNS Activity */}
      <DomainThreatIntelCard
        localIntel={localIntel}
        extIntel={extIntel}
        dnsActivity={dnsActivity}
      />

      {/* Phase 4 Enrichment: DNS Infrastructure, IP Geo/ASN, RDAP Registration */}
      {enrichment && (
        <DomainEnrichmentCard enrichment={enrichment} reputation={reputation} />
      )}

      {/* Querying Clients */}
      <DomainQueryingClientsTable clients={queryingClients} />
    </div>
  );
};

export default DomainDetailPage;
