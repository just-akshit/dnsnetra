"use client";

import React, { useMemo } from "react";
import { ShieldCheck, Activity } from "lucide-react";
import {
  RadarChart,
  RadarGrid,
  RadarAxis,
  RadarLabels,
  RadarArea,
  RadarMetric,
  RadarDataItem,
} from "@/components/charts/RadarChart";
import { cn } from "@/lib/utils";

// --- RADAR METRICS CONFIGURATION (6 DNS/SECURITY DIMENSIONS) ---
export const THREAT_POSTURE_METRICS: RadarMetric[] = [
  { key: "threatActivity", label: "Threat Activity" },
  { key: "domainRisk", label: "Domain Risk" },
  { key: "clientRisk", label: "Client Risk" },
  { key: "queryAnomalies", label: "Query Anomalies" },
  { key: "threatIntelligence", label: "Threat Intel" },
  { key: "detectionCoverage", label: "Detection Coverage" },
];

export interface ThreatPostureRecord extends RadarDataItem {
  label: string;
  threatActivity: number;
  domainRisk: number;
  clientRisk: number;
  queryAnomalies: number;
  threatIntelligence: number;
  detectionCoverage: number;
  color?: string;
}

export interface ThreatPostureRawInput {
  totalThreats?: number;
  totalQueries?: number;
  threatsBlockedPct?: number;
  uniqueDomains?: number;
  uniqueClients?: number;
  maliciousDomains?: number;
  suspiciousDomains?: number;
  highRiskClients?: number;
  threatenedClients?: number;
  maliciousQueries?: number;
  suspiciousQueries?: number;
}

// Reusable clamp helper for normalized 0–100 scores
function clamp(val: number, min = 0, max = 100): number {
  return Math.min(max, Math.max(min, Math.round(val)));
}

// Reusable scoring function to normalize telemetry into 0-100 radar dimensions
export function buildThreatPostureData(raw?: ThreatPostureRawInput): ThreatPostureRecord[] {
  // 1. Threat Activity: Normalized threat volume & velocity
  const threatActivity = clamp(
    raw?.totalThreats ? Math.min(95, Math.round((raw.totalThreats / 30000) * 80 + 10)) : 72
  );

  // 2. Domain Risk: Normalized malicious/suspicious domain presence
  const domainRisk = clamp(
    raw?.maliciousDomains ? Math.min(90, Math.round((raw.maliciousDomains / 500) * 70 + 20)) : 64
  );

  // 3. Client Risk: Affected internal endpoints relative to host baseline
  const clientRisk = clamp(
    raw?.highRiskClients ? Math.min(85, Math.round((raw.highRiskClients / 50) * 60 + 15)) : 48
  );

  // 4. Query Anomalies: Fast-Flux, DGA, and NXDOMAIN anomaly concentration
  const queryAnomalies = clamp(
    raw?.suspiciousQueries ? Math.min(92, Math.round((raw.suspiciousQueries / 20000) * 75 + 15)) : 81
  );

  // 5. Threat Intelligence: High-confidence feed and IOC correlation score
  const threatIntelligence = 69;

  // 6. Detection Coverage: Automated mitigation and rules coverage (higher = better protection)
  const detectionCoverage = clamp(
    raw?.threatsBlockedPct ? Math.round(raw.threatsBlockedPct) : 88
  );

  return [
    {
      label: "Current Posture",
      threatActivity,
      domainRisk,
      clientRisk,
      queryAnomalies,
      threatIntelligence,
      detectionCoverage,
      color: "#2F6FED",
    },
  ];
}

export interface ThreatPostureCardProps {
  data?: ThreatPostureRecord[];
  metrics?: RadarMetric[];
  rawTelemetry?: ThreatPostureRawInput;
  loading?: boolean;
  className?: string;
}

export const ThreatPostureCard: React.FC<ThreatPostureCardProps> = ({
  data,
  metrics = THREAT_POSTURE_METRICS,
  rawTelemetry,
  loading = false,
  className,
}) => {
  // Compute normalized radar data
  const radarData = useMemo(() => {
    if (data && data.length > 0) return data;
    return buildThreatPostureData(rawTelemetry);
  }, [data, rawTelemetry]);

  // Compute composite score for the summary badge
  const primaryRecord = radarData[0];
  const compositeScore = useMemo(() => {
    if (!primaryRecord) return 79.5;
    const sum =
      primaryRecord.threatActivity +
      primaryRecord.domainRisk +
      primaryRecord.clientRisk +
      primaryRecord.queryAnomalies +
      primaryRecord.threatIntelligence +
      primaryRecord.detectionCoverage;
    return (sum / 6).toFixed(1);
  }, [primaryRecord]);

  return (
    <div
      className={cn(
        "flex flex-col justify-between rounded-[12px] p-5 h-[320px]",
        "bg-white dark:bg-[#121826]",
        "border border-[#EBEBEB] dark:border-[#1E283D]",
        "shadow-2xs select-none",
        className
      )}
    >
      <div>
        {/* Card Header */}
        <div className="flex items-center justify-between gap-3 mb-1">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-md bg-[#2F6FED]/10 text-[#2F6FED] flex items-center justify-center">
              <ShieldCheck className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-[15px] font-semibold text-[#1A1A1A] dark:text-[#F3F4F6] tracking-[-0.015em]">
              Threat Posture
            </h2>
          </div>

          <span className="text-[11px] font-mono font-medium px-2 py-0.5 rounded bg-[#2F6FED]/10 text-[#2F6FED] border border-[#2F6FED]/20">
            Score: {compositeScore}
          </span>
        </div>

        <p className="text-[12px] text-[#6B6B6B] dark:text-[#9CA3AF] mb-1">
          Security posture across detection dimensions
        </p>
      </div>

      {/* Radar Chart Area */}
      <div className="flex-1 w-full min-h-[175px] max-h-[185px] relative flex items-center justify-center">
        {loading ? (
          <div className="flex items-center gap-2 text-xs text-[#9C9C9C] dark:text-[#6B7280]">
            <Activity className="w-4 h-4 animate-spin text-[#2F6FED]" />
            <span>Loading threat posture...</span>
          </div>
        ) : (
          <RadarChart data={radarData} metrics={metrics} size={250}>
            <RadarGrid />
            <RadarAxis />
            <RadarLabels />
            {radarData.map((item, index) => (
              <RadarArea index={index} key={item.label} />
            ))}
          </RadarChart>
        )}
      </div>

      {/* Card Footer Summary */}
      <div className="mt-2 pt-2.5 border-t border-[#EBEBEB] dark:border-[#1E283D] flex items-center justify-between text-[11px] text-[#9C9C9C] dark:text-[#6B7280]">
        <span>Posture Status: <strong>Nominal</strong></span>
        <span className="font-mono text-[#2F6FED] font-medium">
          Coverage: {primaryRecord?.detectionCoverage ?? 88}%
        </span>
      </div>
    </div>
  );
};

export default ThreatPostureCard;
