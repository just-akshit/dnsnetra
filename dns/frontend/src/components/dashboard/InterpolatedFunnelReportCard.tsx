'use client';

import React, { useState, useMemo } from 'react';
import { motion } from 'motion/react';

export interface FunnelDataPoint {
  key: string;
  data: number | null;
}

export interface InterpolatedFunnelReportCardProps {
  data?: FunnelDataPoint[];
  title?: string;
}

export function InterpolatedFunnelReportCard({
  data,
  title = "Telemetry Funnel Report",
}: InterpolatedFunnelReportCardProps): React.ReactElement {
  const [activeWindow, setActiveWindow] = useState<string>("24h");

  const displayData = useMemo(() => {
    if (data && data.length > 0) return data;
    return [
      { key: "Total Traffic", data: 124000 },
      { key: "Inspected Queries", data: 118500 },
      { key: "Flagged Threats", data: 4230 },
      { key: "Blocked Responses", data: 3950 },
    ];
  }, [data]);

  return (
    <div className="bg-card border border-border/70 rounded-md p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-foreground">{title}</h3>
        <div className="flex items-center gap-1 text-xs">
          {["1h", "24h", "7d"].map((w) => (
            <button
              key={w}
              onClick={() => setActiveWindow(w)}
              className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                activeWindow === w
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {w}
            </button>
          ))}
        </div>
      </div>
      <div className="space-y-2">
        {displayData.map((item, idx) => (
          <div key={item.key} className="space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-muted-foreground">{item.key}</span>
              <span className="font-mono font-medium text-foreground">
                {item.data?.toLocaleString()}
              </span>
            </div>
            <div className="w-full bg-secondary/50 h-2 rounded-full overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${Math.max(5, 100 - idx * 25)}%` }}
                transition={{ duration: 0.5, delay: idx * 0.1 }}
                className="bg-primary h-full rounded-full"
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default InterpolatedFunnelReportCard;
