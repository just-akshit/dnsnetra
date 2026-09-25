"use client";

import React from "react";
import Link from "next/link";
import { RecentFlaggedDomain } from "../../types/api";

interface AlertsListProps {
  alerts?: RecentFlaggedDomain[];
}

const AlertsList: React.FC<AlertsListProps> = ({ alerts = [] }) => {
  return (
    <div className="w-full">
      <div className="grid grid-cols-4 text-xs font-mono text-slate-500 uppercase pb-2 border-b border-border">
        <span>Domain</span>
        <span>Reason</span>
        <span>Source</span>
        <span className="text-right">Timestamp</span>
      </div>

      <div className="mt-2 space-y-1">
        {alerts.length === 0 ? (
          <div className="py-6 text-center text-xs text-slate-500 font-mono">
            No recent threat alerts in database
          </div>
        ) : (
          alerts.map((alert, idx) => (
            <div
              key={idx}
              className="grid grid-cols-4 items-center text-sm py-2 hover:bg-muted/50 rounded px-1 transition-colors"
            >
              <div className="flex items-center gap-1.5 truncate pr-2">
                <div className="w-2 h-2 rounded-full bg-brand-red shrink-0" />
                <Link
                  href={`/investigate/domains/${encodeURIComponent(alert.domain)}`}
                  className="text-foreground font-mono text-xs hover:text-brand-blue truncate"
                >
                  {alert.domain}
                </Link>
              </div>
              <span className="text-slate-300 text-xs truncate">
                {alert.label_reason || alert.label || "Flagged"}
              </span>
              <span className="text-slate-400 text-xs font-mono truncate">
                {alert.ti_source || "rule"}
              </span>
              <span className="text-slate-500 text-xs font-mono text-right truncate">
                {alert.flagged_at ? alert.flagged_at.substring(11, 19) : "-"}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default AlertsList;
