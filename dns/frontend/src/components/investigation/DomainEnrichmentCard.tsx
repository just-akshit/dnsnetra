"use client";

import React from "react";
import { Globe, Network, Calendar } from "lucide-react";
import {
  DomainEnrichmentData,
  ActiveReputationData,
} from "@/types/api";

interface Props {
  enrichment: DomainEnrichmentData;
  reputation?: ActiveReputationData | null;
}

function Pill({ label, value }: { label: string; value?: string | null }) {
  if (!value) return null;
  return (
    <div className="flex items-start gap-1.5 text-xs">
      <span className="text-muted-foreground shrink-0 w-24">{label}</span>
      <span className="text-foreground font-mono break-all">{value}</span>
    </div>
  );
}

function SectionHeader({ icon: Icon, title }: { icon: React.ElementType; title: string }) {
  return (
    <div className="flex items-center gap-1.5 mb-2.5">
      <Icon className="w-3.5 h-3.5 text-muted-foreground" />
      <h3 className="text-xs font-semibold text-foreground uppercase tracking-wide">{title}</h3>
    </div>
  );
}

export const DomainEnrichmentCard: React.FC<Props> = ({ enrichment, reputation }) => {
  const dns = enrichment?.dns;
  const ips = enrichment?.ips || [];
  const reg = enrichment?.registration;

  const hasDns = dns?.status === "AVAILABLE";
  const hasReg = reg?.status === "AVAILABLE";
  const hasIps = ips.length > 0;

  if (!hasDns && !hasReg && !hasIps) return null;

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
      {/* DNS Infrastructure */}
      {hasDns && (
        <div className="p-4 bg-card border border-border/70 rounded-lg shadow-sm space-y-1.5">
          <SectionHeader icon={Globe} title="DNS Infrastructure" />
          {(dns.a || []).slice(0, 4).map((ip) => (
            <Pill key={ip} label="A" value={ip} />
          ))}
          {(dns.aaaa || []).slice(0, 2).map((ip) => (
            <Pill key={ip} label="AAAA" value={ip} />
          ))}
          {(dns.cname || []).slice(0, 2).map((c) => (
            <Pill key={c} label="CNAME" value={c} />
          ))}
          {(dns.ns || []).slice(0, 2).map((ns) => (
            <Pill key={ns} label="NS" value={ns} />
          ))}
          {(dns.mx || []).slice(0, 2).map((mx) => (
            <Pill key={mx.exchange} label="MX" value={`${mx.priority} ${mx.exchange}`} />
          ))}
          <p className="text-[10px] text-muted-foreground mt-1 font-mono">
            via {dns.provider} · {dns.freshness}
          </p>
        </div>
      )}

      {/* IP Network / Geo */}
      {hasIps && (
        <div className="p-4 bg-card border border-border/70 rounded-lg shadow-sm space-y-3">
          <SectionHeader icon={Network} title="IP Intelligence" />
          {ips.slice(0, 3).map((item) => (
            <div key={item.ip} className="space-y-1">
              <span className="text-xs font-mono font-semibold text-foreground">{item.ip}</span>
              <Pill label="ASN" value={item.network?.asn ? `AS${item.network.asn}` : null} />
              <Pill label="Org" value={item.network?.asn_organization} />
              <Pill label="ISP" value={item.network?.isp} />
              <Pill
                label="Location"
                value={[item.geo?.city, item.geo?.region, item.geo?.country_code]
                  .filter(Boolean)
                  .join(", ") || null}
              />
            </div>
          ))}
        </div>
      )}

      {/* Registration / RDAP */}
      {hasReg && (
        <div className="p-4 bg-card border border-border/70 rounded-lg shadow-sm space-y-1.5">
          <SectionHeader icon={Calendar} title="Registration" />
          <Pill label="Registrar" value={reg.registrar} />
          <Pill
            label="Created"
            value={reg.created_at ? new Date(reg.created_at).toLocaleDateString() : null}
          />
          <Pill
            label="Expires"
            value={reg.expires_at ? new Date(reg.expires_at).toLocaleDateString() : null}
          />
          <Pill
            label="Updated"
            value={reg.updated_at ? new Date(reg.updated_at).toLocaleDateString() : null}
          />
          {(reg.nameservers || []).slice(0, 2).map((ns) => (
            <Pill key={ns} label="NS" value={ns} />
          ))}
          {(reg.domain_status || []).slice(0, 2).map((s) => (
            <div key={s} className="flex items-center gap-1.5 text-xs">
              <span className="text-muted-foreground w-24 shrink-0">Status</span>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-secondary text-muted-foreground">{s}</span>
            </div>
          ))}
          <p className="text-[10px] text-muted-foreground mt-1 font-mono">
            via {reg.provider} · {reg.freshness}
          </p>
        </div>
      )}
    </div>
  );
};

export default DomainEnrichmentCard;
