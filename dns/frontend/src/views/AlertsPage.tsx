"use client";

import React, { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  Bell,
  RefreshCw,
  ShieldAlert,
  CheckCircle2,
  Filter,
  ExternalLink,
  ChevronRight,
  AlertTriangle,
  Flame,
  ShieldCheck,
  MoreHorizontal,
  Eye,
  Check,
  Archive,
  Search,
} from "lucide-react";
import apiClient from "@/lib/api-client";
import { DashboardBundleData } from "@/types/api";
import { Skeleton } from "@/components/ui/skeleton";
import { GlobalFilterBar } from "@/components/layout/GlobalFilterBar";
import { GlobalTimeRangePicker } from "@/components/layout/GlobalTimeRangePicker";
import { formatNumber, formatFullTimestamp } from "@/lib/format";
import { SeverityBadge } from "@/components/security/SeverityBadge";

export type AlertSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type AlertStatus = "New" | "Acknowledged" | "Investigating" | "Resolved" | "Suppressed";

export interface SocAlert {
  id: string;
  severity: AlertSeverity;
  alert_type: string;
  domain: string;
  client_ip: string;
  detection_reason: string;
  ti_source: string;
  confidence: number;
  status: AlertStatus;
  first_seen: string;
  last_seen: string;
  query_count: number;
}

const INITIAL_ALERTS: SocAlert[] = [
  {
    id: "ALT-8921",
    severity: "CRITICAL",
    alert_type: "C2 Callback",
    domain: "update.system-patcher.top",
    client_ip: "172.16.8.99",
    detection_reason: "Cobalt Strike beaconing detected with persistent 60s jitter interval",
    ti_source: "ThreatFox C2 Feed",
    confidence: 96,
    status: "New",
    first_seen: "2026-08-28 04:12:00",
    last_seen: "2026-08-28 06:22:15",
    query_count: 420,
  },
  {
    id: "ALT-8922",
    severity: "CRITICAL",
    alert_type: "DNS Tunneling",
    domain: "tunnel-data.cdn-storage.org",
    client_ip: "192.168.1.105",
    detection_reason: "Abnormal volume of high-entropy TXT records containing base64 encoded payload",
    ti_source: "Entropy Engine",
    confidence: 98,
    status: "Investigating",
    first_seen: "2026-08-28 02:10:00",
    last_seen: "2026-08-28 06:15:30",
    query_count: 1420,
  },
  {
    id: "ALT-8923",
    severity: "HIGH",
    alert_type: "Credential Phishing",
    domain: "auth-portal.sso-verify.cc",
    client_ip: "10.0.4.22",
    detection_reason: "Target domain mimics enterprise Okta/Microsoft identity provider SSO portal",
    ti_source: "URLhaus + AlienVault",
    confidence: 92,
    status: "Acknowledged",
    first_seen: "2026-08-28 05:40:00",
    last_seen: "2026-08-28 06:05:45",
    query_count: 86,
  },
  {
    id: "ALT-8924",
    severity: "HIGH",
    alert_type: "DGA Domain Query",
    domain: "dga-v2-7x92kp.biz",
    client_ip: "192.168.2.88",
    detection_reason: "Algorithmically generated domain matching Mirai / Necurs seed family",
    ti_source: "ML Classifier",
    confidence: 88,
    status: "New",
    first_seen: "2026-08-28 06:01:00",
    last_seen: "2026-08-28 06:20:10",
    query_count: 34,
  },
  {
    id: "ALT-8925",
    severity: "MEDIUM",
    alert_type: "Fast-Flux DNS",
    domain: "fastflux-node99.asia",
    client_ip: "172.16.8.99",
    detection_reason: "Frequent A-record TTL alteration with 40+ distinct IPs within 60 minutes",
    ti_source: "Passive DNS",
    confidence: 76,
    status: "New",
    first_seen: "2026-08-28 03:30:00",
    last_seen: "2026-08-28 05:45:00",
    query_count: 210,
  },
  {
    id: "ALT-8926",
    severity: "LOW",
    alert_type: "Uncategorized ASN Burst",
    domain: "telemetry.cloud-metrics.ru",
    client_ip: "10.0.12.54",
    detection_reason: "Newly registered high-entropy domain generating abnormal burst queries",
    ti_source: "Tranco Heuristic",
    confidence: 64,
    status: "Resolved",
    first_seen: "2026-08-27 14:20:00",
    last_seen: "2026-08-28 01:10:00",
    query_count: 65,
  },
];

export const AlertsPage: React.FC = () => {
  const router = useRouter();
  const [alerts, setAlerts] = useState<SocAlert[]>(INITIAL_ALERTS);
  const [loading, setLoading] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState<SocAlert | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [search, setSearch] = useState<string>("");

  const handleStatusChange = (alertId: string, newStatus: AlertStatus) => {
    setAlerts((prev) =>
      prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a))
    );
    if (selectedAlert && selectedAlert.id === alertId) {
      setSelectedAlert((prev) => (prev ? { ...prev, status: newStatus } : null));
    }
  };

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await new Promise((r) => setTimeout(r, 400));
    setIsRefreshing(false);
  };

  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      if (statusFilter !== "all" && a.status !== statusFilter) return false;
      if (severityFilter !== "all" && a.severity !== severityFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          a.domain.toLowerCase().includes(q) ||
          a.client_ip.toLowerCase().includes(q) ||
          a.alert_type.toLowerCase().includes(q) ||
          a.detection_reason.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [alerts, statusFilter, severityFilter, search]);

  const newCount = alerts.filter((a) => a.status === "New").length;
  const investigatingCount = alerts.filter((a) => a.status === "Investigating").length;
  const criticalCount = alerts.filter((a) => a.severity === "CRITICAL" && a.status !== "Resolved").length;
  const resolvedCount = alerts.filter((a) => a.status === "Resolved").length;

  return (
    <div className="space-y-5 pb-12 select-none">
      {/* 1. Header Row */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-foreground">
              SOC Threat Alerts & Incident Operations
            </h1>
            {criticalCount > 0 && (
              <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-red-500/15 text-red-500 border border-red-500/30">
                {criticalCount} Critical
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            Active security alert queue, incident triage workflow, and automated response triggers.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <GlobalTimeRangePicker />
          <button
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-border/80 bg-background hover:bg-muted text-xs font-medium text-foreground transition-colors cursor-pointer disabled:opacity-50 shadow-xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin text-blue-500" : "text-muted-foreground"}`} />
            <span>{isRefreshing ? "Refreshing..." : "Refresh Queue"}</span>
          </button>
        </div>
      </div>

      {/* 2. Operations Metrics Overview */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="p-4 rounded-lg bg-card border border-border/70 shadow-xs space-y-1">
          <span className="text-xs text-muted-foreground font-medium">New Unacknowledged</span>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-red-500">{newCount}</span>
            <span className="text-xs text-red-500 font-medium">Needs Triage</span>
          </div>
          <span className="text-[11px] text-muted-foreground">Highest priority queue</span>
        </div>

        <div className="p-4 rounded-lg bg-card border border-border/70 shadow-xs space-y-1">
          <span className="text-xs text-muted-foreground font-medium">Under Active Investigation</span>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-amber-500">{investigatingCount}</span>
            <span className="text-xs text-amber-500 font-medium">In Progress</span>
          </div>
          <span className="text-[11px] text-muted-foreground">Assigned to SOC analysts</span>
        </div>

        <div className="p-4 rounded-lg bg-card border border-border/70 shadow-xs space-y-1">
          <span className="text-xs text-muted-foreground font-medium">Critical Threat Severity</span>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-destructive">{criticalCount}</span>
            <span className="text-xs text-destructive font-medium flex items-center gap-0.5">
              <ShieldAlert className="w-3.5 h-3.5" /> High Risk
            </span>
          </div>
          <span className="text-[11px] text-muted-foreground">C2 / Data Exfiltration events</span>
        </div>

        <div className="p-4 rounded-lg bg-card border border-border/70 shadow-xs space-y-1">
          <span className="text-xs text-muted-foreground font-medium">Resolved Today</span>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-emerald-500">{resolvedCount}</span>
            <span className="text-xs text-emerald-500 font-medium flex items-center gap-0.5">
              <CheckCircle2 className="w-3.5 h-3.5" /> Closed
            </span>
          </div>
          <span className="text-[11px] text-muted-foreground">Mitigated & verified clean</span>
        </div>
      </div>

      {/* 3. Filter & Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-card border border-border/70 rounded-lg shadow-xs">
        <div className="flex items-center gap-2 flex-1 max-w-md">
          <div className="relative w-full">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search alert by domain, IP, reason..."
              className="w-full pl-8 pr-3 py-1.5 bg-background border border-border rounded-md text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-ring"
            />
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          {/* Status Filter */}
          <div className="flex items-center gap-1">
            <span className="text-muted-foreground text-[11px]">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-2 py-1 bg-background border border-border rounded text-xs text-foreground focus:outline-none"
            >
              <option value="all">All Statuses</option>
              <option value="New">New</option>
              <option value="Acknowledged">Acknowledged</option>
              <option value="Investigating">Investigating</option>
              <option value="Resolved">Resolved</option>
              <option value="Suppressed">Suppressed</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1">
            <span className="text-muted-foreground text-[11px]">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-2 py-1 bg-background border border-border rounded text-xs text-foreground focus:outline-none"
            >
              <option value="all">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* 4. Main Alert Queue Table */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-2 bg-card border border-border/70 rounded-lg shadow-xs overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead className="bg-muted/40 text-muted-foreground border-b border-border/50">
                <tr>
                  <th className="px-4 py-2.5 font-medium">Severity</th>
                  <th className="px-4 py-2.5 font-medium">Alert Type</th>
                  <th className="px-4 py-2.5 font-medium">Domain & Endpoint</th>
                  <th className="px-4 py-2.5 font-medium">Status</th>
                  <th className="px-4 py-2.5 font-medium text-right">Timestamp</th>
                  <th className="px-4 py-2.5 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/30">
                {filteredAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-muted-foreground">
                      No alerts match the selected criteria.
                    </td>
                  </tr>
                ) : (
                  filteredAlerts.map((alert) => (
                    <tr
                      key={alert.id}
                      onClick={() => setSelectedAlert(alert)}
                      className={`hover:bg-muted/30 cursor-pointer transition-colors ${
                        selectedAlert?.id === alert.id ? "bg-muted/40" : ""
                      }`}
                    >
                      {/* Severity Badge */}
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase ${
                            alert.severity === "CRITICAL"
                              ? "bg-red-500/15 text-red-500 border border-red-500/30"
                              : alert.severity === "HIGH"
                              ? "bg-orange-500/15 text-orange-500 border border-orange-500/30"
                              : alert.severity === "MEDIUM"
                              ? "bg-amber-500/15 text-amber-500 border border-amber-500/30"
                              : "bg-blue-500/15 text-blue-500 border border-blue-500/30"
                          }`}
                        >
                          {alert.severity}
                        </span>
                      </td>

                      {/* Alert Type */}
                      <td className="px-4 py-3 font-medium text-foreground">
                        <div className="space-y-0.5">
                          <p className="truncate max-w-[140px]">{alert.alert_type}</p>
                          <span className="text-[10px] font-mono text-muted-foreground">{alert.id}</span>
                        </div>
                      </td>

                      {/* Domain & Client */}
                      <td className="px-4 py-3">
                        <div className="space-y-0.5 max-w-[200px]">
                          <p className="font-mono text-foreground font-medium truncate">{alert.domain}</p>
                          <p className="font-mono text-muted-foreground text-[11px] truncate">Host: {alert.client_ip}</p>
                        </div>
                      </td>

                      {/* Status Selector Dropdown */}
                      <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                        <select
                          value={alert.status}
                          onChange={(e) => handleStatusChange(alert.id, e.target.value as AlertStatus)}
                          className={`px-2 py-0.5 rounded text-[11px] font-semibold border cursor-pointer ${
                            alert.status === "New"
                              ? "bg-red-500/10 text-red-500 border-red-500/20"
                              : alert.status === "Investigating"
                              ? "bg-amber-500/10 text-amber-500 border-amber-500/20"
                              : alert.status === "Acknowledged"
                              ? "bg-blue-500/10 text-blue-500 border-blue-500/20"
                              : alert.status === "Resolved"
                              ? "bg-emerald-500/10 text-emerald-500 border-emerald-500/20"
                              : "bg-muted text-muted-foreground border-border"
                          }`}
                        >
                          <option value="New">New</option>
                          <option value="Acknowledged">Acknowledged</option>
                          <option value="Investigating">Investigating</option>
                          <option value="Resolved">Resolved</option>
                          <option value="Suppressed">Suppressed</option>
                        </select>
                      </td>

                      {/* Full Timestamp */}
                      <td className="px-4 py-3 text-right font-mono text-[11px] text-muted-foreground whitespace-nowrap">
                        {alert.last_seen}
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-3 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => router.push(`/investigate/domains/${encodeURIComponent(alert.domain)}`)}
                            title="Investigate Domain"
                            className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* 5. Alert Forensic Inspector Sidebar Card */}
        <div className="bg-card border border-border/70 rounded-lg p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between border-b border-border/50 pb-3">
            <h2 className="text-sm font-semibold text-foreground tracking-tight">
              Alert Forensics & Triage
            </h2>
            {selectedAlert && (
              <span className="text-xs font-mono text-muted-foreground">
                {selectedAlert.id}
              </span>
            )}
          </div>

          {selectedAlert ? (
            <div className="space-y-4 text-xs">
              {/* Alert Title & Severity */}
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span
                    className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold font-mono ${
                      selectedAlert.severity === "CRITICAL"
                        ? "bg-red-500/15 text-red-500"
                        : "bg-amber-500/15 text-amber-500"
                    }`}
                  >
                    {selectedAlert.severity}
                  </span>
                  <h3 className="font-semibold text-foreground text-sm">
                    {selectedAlert.alert_type}
                  </h3>
                </div>
                <p className="text-muted-foreground leading-relaxed pt-1">
                  {selectedAlert.detection_reason}
                </p>
              </div>

              {/* Target Details */}
              <div className="space-y-2 p-3 bg-muted/20 rounded-md border border-border/40">
                <div className="flex justify-between items-center">
                  <span className="text-muted-foreground">Domain Indicator:</span>
                  <span
                    onClick={() => router.push(`/investigate/domains/${encodeURIComponent(selectedAlert.domain)}`)}
                    className="font-mono font-medium text-blue-500 hover:underline cursor-pointer truncate max-w-[160px]"
                  >
                    {selectedAlert.domain}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-muted-foreground">Origin Endpoint:</span>
                  <span
                    onClick={() => router.push(`/investigate/clients/${encodeURIComponent(selectedAlert.client_ip)}`)}
                    className="font-mono font-medium text-blue-500 hover:underline cursor-pointer"
                  >
                    {selectedAlert.client_ip}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-muted-foreground">Confidence Rating:</span>
                  <span className="font-mono font-semibold text-foreground">{selectedAlert.confidence}%</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-muted-foreground">Intelligence Feed:</span>
                  <span className="font-mono text-muted-foreground">{selectedAlert.ti_source}</span>
                </div>
              </div>

              {/* Timeline */}
              <div className="space-y-1.5">
                <div className="flex justify-between text-[11px]">
                  <span className="text-muted-foreground">First Event:</span>
                  <span className="font-mono text-foreground">{selectedAlert.first_seen}</span>
                </div>
                <div className="flex justify-between text-[11px]">
                  <span className="text-muted-foreground">Last Telemetry:</span>
                  <span className="font-mono text-foreground">{selectedAlert.last_seen}</span>
                </div>
              </div>

              {/* Triage Actions */}
              <div className="space-y-2 pt-2 border-t border-border/50">
                <span className="text-muted-foreground block text-[11px] font-medium uppercase tracking-wider">
                  Remediation Actions
                </span>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => handleStatusChange(selectedAlert.id, "Investigating")}
                    className="px-2.5 py-1.5 rounded bg-blue-500 text-white font-medium text-xs hover:bg-blue-600 transition-colors cursor-pointer"
                  >
                    Investigate Host
                  </button>
                  <button
                    onClick={() => handleStatusChange(selectedAlert.id, "Resolved")}
                    className="px-2.5 py-1.5 rounded bg-emerald-600 text-white font-medium text-xs hover:bg-emerald-700 transition-colors cursor-pointer"
                  >
                    Mark Resolved
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-xs text-muted-foreground space-y-2">
              <ShieldAlert className="w-8 h-8 mx-auto text-muted-foreground/50" />
              <p>Select any alert in the queue to inspect forensic evidence and execute remediation.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AlertsPage;
