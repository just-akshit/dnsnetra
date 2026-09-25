import React from "react";
import { MetricsSummary } from "../../types/api";

interface StatCardsProps {
  summary?: MetricsSummary | null;
}

const StatCards: React.FC<StatCardsProps> = ({ summary }) => {
  const totalQueries = summary?.total_queries ?? 0;
  const totalThreats = summary?.total_threats ?? 0;
  const blockedPct = summary?.threats_blocked_pct ?? 0;
  const securePct = (100 - blockedPct).toFixed(1);

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 h-full">
      {/* Total Threats Flagged */}
      <div className="glass-card p-6 flex flex-col justify-center text-center items-center">
        <div className="flex items-center gap-1 text-2xl font-mono font-bold text-foreground">
          {totalThreats > 0 && <span className="text-red-400 text-sm">⚠</span>}
          <span>{totalThreats.toLocaleString()}</span>
        </div>
        <div className="flex items-center gap-2 mt-2">
          <div className="w-5 h-5 bg-brand-red/20 text-brand-red rounded flex items-center justify-center border border-brand-red/40">
            <span className="text-[10px]">⚠</span>
          </div>
          <span className="text-xs text-slate-300">Flagged Threats</span>
        </div>
      </div>

      {/* Total Queries Processed */}
      <div className="glass-card p-6 flex flex-col justify-center text-center items-center">
        <div className="flex items-center gap-1 text-2xl font-mono font-bold text-foreground">
          <span>{totalQueries.toLocaleString()}</span>
        </div>
        <div className="flex items-center gap-2 mt-2">
          <div className="w-5 h-5 bg-brand-blue/20 text-brand-blue rounded flex items-center justify-center border border-brand-blue/40">
            <span className="text-[10px]">⚡</span>
          </div>
          <span className="text-xs text-slate-300">Total Queries</span>
        </div>
      </div>

      {/* Clean Traffic Percentage */}
      <div className="glass-card p-6 flex flex-col justify-center text-center items-center">
        <div className="text-3xl font-mono font-bold text-brand-green text-glow">
          {securePct}%
        </div>
        <div className="flex items-center gap-2 mt-2">
          <div className="w-5 h-5 bg-brand-green/20 text-brand-green rounded flex items-center justify-center border border-brand-green/40">
            <span className="text-[10px]">✓</span>
          </div>
          <span className="text-xs text-slate-300">Clean Traffic Rate</span>
        </div>
      </div>
    </div>
  );
};

export default StatCards;
