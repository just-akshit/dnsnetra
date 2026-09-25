"use client";

import React from "react";
import { DashboardWidget } from "@/components/dashboard/DashboardWidget";
import {
  LocalIntelligenceData,
  ExternalIntelligenceData,
  DNSActivityData,
} from "@/types/api";

interface DomainThreatIntelCardProps {
  localIntel?: LocalIntelligenceData;
  extIntel?: ExternalIntelligenceData;
  dnsActivity?: DNSActivityData;
}

export const DomainThreatIntelCard: React.FC<DomainThreatIntelCardProps> = ({
  localIntel,
  extIntel,
  dnsActivity,
}) => {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3.5">
      {/* 1. Local Feeds */}
      <DashboardWidget title="Local intelligence">
        <div className="space-y-2 text-xs">
          <div className="p-2.5 rounded border border-border/50 bg-muted/10 flex items-center justify-between">
            <div>
              <p className="font-medium text-foreground">URLhaus</p>
              <p className="text-[11px] text-muted-foreground">Malware & C2 database</p>
            </div>
            {localIntel?.urlhaus?.matched ? (
              <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-red-500/15 text-red-500">
                MATCHED
              </span>
            ) : (
              <span className="px-1.5 py-0.2 rounded text-[10px] text-muted-foreground bg-secondary">
                Not listed
              </span>
            )}
          </div>

          <div className="p-2.5 rounded border border-border/50 bg-muted/10 flex items-center justify-between">
            <div>
              <p className="font-medium text-foreground">Tranco List</p>
              <p className="text-[11px] text-muted-foreground">Top 1M global ranking</p>
            </div>
            {localIntel?.tranco?.matched ? (
              <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-emerald-500/15 text-emerald-500">
                Top 1M
              </span>
            ) : (
              <span className="px-1.5 py-0.2 rounded text-[10px] text-muted-foreground bg-secondary">
                Not listed
              </span>
            )}
          </div>
        </div>
      </DashboardWidget>

      {/* 2. External Providers */}
      <DashboardWidget title="External intelligence">
        <div className="space-y-2 text-xs">
          <div className="p-2.5 rounded border border-border/50 bg-muted/10 flex items-center justify-between">
            <div>
              <p className="font-medium text-foreground">VirusTotal</p>
              <p className="text-[11px] text-muted-foreground">Antivirus detections</p>
            </div>
            <span className="text-[11px] text-muted-foreground">
              {extIntel?.virustotal?.status === "AVAILABLE"
                ? `${extIntel.virustotal.malicious_count || 0} detections`
                : extIntel?.virustotal?.status || "No data"}
            </span>
          </div>

          <div className="p-2.5 rounded border border-border/50 bg-muted/10 flex items-center justify-between">
            <div>
              <p className="font-medium text-foreground">AlienVault OTX</p>
              <p className="text-[11px] text-muted-foreground">Threat exchange pulses</p>
            </div>
            <span className="text-[11px] text-muted-foreground">
              {extIntel?.otx?.status === "AVAILABLE" ? "Analyzed" : extIntel?.otx?.status || "No data"}
            </span>
          </div>
        </div>
      </DashboardWidget>

      {/* 3. DNS Records */}
      <DashboardWidget title="DNS records">
        <div className="space-y-1.5 text-xs">
          {dnsActivity?.query_types && Object.keys(dnsActivity.query_types).length > 0 ? (
            Object.entries(dnsActivity.query_types).map(([qType, count]) => (
              <div key={qType} className="flex items-center justify-between py-1 border-b border-border/30">
                <span className="text-muted-foreground font-mono">{qType}</span>
                <span className="font-medium text-foreground">
                  {typeof count === "number" ? count.toLocaleString() : String(count)}
                </span>
              </div>
            ))
          ) : (
            <p className="text-xs text-muted-foreground py-2 text-center">
              No record breakdown available.
            </p>
          )}
        </div>
      </DashboardWidget>
    </div>
  );
};

export default DomainThreatIntelCard;
