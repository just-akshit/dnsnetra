"use client";

import React from "react";
import { useRouter } from "next/navigation";
import { DashboardWidget } from "@/components/dashboard/DashboardWidget";
import { QueryingClientItem } from "@/types/api";

interface DomainQueryingClientsTableProps {
  clients?: QueryingClientItem[];
}

export const DomainQueryingClientsTable: React.FC<DomainQueryingClientsTableProps> = ({
  clients = [],
}) => {
  const router = useRouter();

  return (
    <DashboardWidget
      title="Querying clients"
      empty={clients.length === 0}
      emptyMessage="No internal client endpoints queried this domain."
    >
      <div className="overflow-x-auto -mx-4 -my-2">
        <table className="w-full text-xs text-left">
          <thead className="bg-muted/30 text-muted-foreground border-b border-border/50">
            <tr>
              <th className="px-4 py-2 font-medium">Client IP</th>
              <th className="px-4 py-2 font-medium text-right">Queries</th>
              <th className="px-4 py-2 font-medium text-right">Last Observed</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/40">
            {clients.map((client, idx) => (
              <tr
                key={idx}
                onClick={() => router.push(`/investigate/clients/${encodeURIComponent(client.client_ip)}`)}
                className="hover:bg-muted/30 cursor-pointer transition-colors"
              >
                <td className="px-4 py-2 font-mono font-medium text-blue-600 dark:text-blue-400">
                  {client.client_ip}
                </td>
                <td className="px-4 py-2 text-right text-muted-foreground">
                  {(client.query_count || 1).toLocaleString()}
                </td>
                <td className="px-4 py-2 text-right text-muted-foreground text-[11px] font-mono">
                  {client.last_seen ? client.last_seen.substring(0, 19).replace("T", " ") : "-"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </DashboardWidget>
  );
};

export default DomainQueryingClientsTable;
