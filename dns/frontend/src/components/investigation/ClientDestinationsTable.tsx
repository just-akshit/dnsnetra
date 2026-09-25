"use client";

import React from "react";
import { useRouter } from "next/navigation";
import { VerdictBadge } from "@/components/security/VerdictBadge";
import { ClientThreatItem } from "@/types/api";

interface ClientDestinationsTableProps {
  topDomains?: ClientThreatItem[];
}

export const ClientDestinationsTable: React.FC<ClientDestinationsTableProps> = ({
  topDomains = [],
}) => {
  const router = useRouter();
  const displayDomains = topDomains.slice(0, 10);

  return (
    <div className="bg-card border border-border/70 rounded-lg shadow-2xs overflow-hidden">
      {/* Card Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border/50">
        <div>
          <h2 className="text-[13px] font-semibold text-foreground tracking-tight">
            Top Destinations
          </h2>
          <p className="text-[11px] text-muted-foreground mt-0.5">
            Most frequently queried destination domains for this client
          </p>
        </div>
        <span className="text-[11px] text-muted-foreground font-mono bg-muted/40 px-2 py-0.5 rounded">
          {displayDomains.length} {displayDomains.length === 1 ? "domain" : "domains"}
        </span>
      </div>

      {/* Table Content - strictly content-sized, zero top gap */}
      {displayDomains.length === 0 ? (
        <div className="py-8 text-center text-xs text-muted-foreground">
          No destinations found
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-muted/30 text-muted-foreground border-b border-border/50">
              <tr>
                <th className="px-4 py-2.5 font-medium">Domain</th>
                <th className="px-4 py-2.5 font-medium text-right">Queries</th>
                <th className="px-4 py-2.5 font-medium text-right">Verdict</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {displayDomains.map((item, idx) => (
                <tr
                  key={`${item.domain}-${idx}`}
                  onClick={() =>
                    router.push(
                      `/investigate/domains/${encodeURIComponent(item.domain)}`,
                    )
                  }
                  className="hover:bg-muted/30 cursor-pointer transition-colors group"
                >
                  <td className="px-4 py-2.5 font-mono font-medium text-foreground group-hover:text-primary transition-colors truncate max-w-[220px]">
                    {item.domain}
                  </td>
                  <td className="px-4 py-2.5 text-right text-muted-foreground tabular-nums font-mono">
                    {(item.query_count || 1).toLocaleString()}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    <VerdictBadge verdict={item.label} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default ClientDestinationsTable;
