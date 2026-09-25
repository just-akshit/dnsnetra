import React from "react";

export const Skeleton = ({ className = "" }: { className?: string }) => (
  <div className={`animate-pulse bg-slate-800/40 rounded ${className}`} />
);

export const CardSkeleton = () => (
  <div className="glass-card p-5 space-y-4">
    <div className="flex justify-between items-start">
      <div className="space-y-2">
        <Skeleton className="h-4 w-28" />
        <Skeleton className="h-8 w-20" />
      </div>
      <Skeleton className="h-10 w-10 rounded-lg" />
    </div>
    <Skeleton className="h-4 w-36" />
  </div>
);

export const TableSkeleton = ({ rows = 5, cols = 5 }: { rows?: number; cols?: number }) => (
  <div className="space-y-3 p-4">
    <div className="flex space-x-4 border-b border-border/40 pb-3">
      {Array.from({ length: cols }).map((_, i) => (
        <Skeleton key={`head-${i}`} className="h-4 flex-1" />
      ))}
    </div>
    {Array.from({ length: rows }).map((_, r) => (
      <div key={`row-${r}`} className="flex space-x-4 py-2 border-b border-border/20">
        {Array.from({ length: cols }).map((_, c) => (
          <Skeleton key={`cell-${r}-${c}`} className="h-5 flex-1" />
        ))}
      </div>
    ))}
  </div>
);
