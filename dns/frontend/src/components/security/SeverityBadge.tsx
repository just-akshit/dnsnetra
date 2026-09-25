import React from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export interface SeverityBadgeProps {
  severity?: string | null;
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className }) => {
  const norm = (severity || "low").toLowerCase().trim();

  if (norm === "critical") {
    return (
      <Badge
        variant="destructive"
        className={cn(
          "bg-rose-500/15 text-rose-500 dark:text-rose-400 border-rose-500/30 hover:bg-rose-500/20 font-mono uppercase text-[10px] tracking-wider font-semibold",
          className
        )}
      >
        <span className="w-1.5 h-1.5 rounded-full bg-rose-500 shrink-0 mr-1" />
        Critical
      </Badge>
    );
  }

  if (norm === "high") {
    return (
      <Badge
        variant="destructive"
        className={cn(
          "bg-red-500/15 text-red-500 dark:text-red-400 border-red-500/30 hover:bg-red-500/20 font-mono uppercase text-[10px] tracking-wider font-semibold",
          className
        )}
      >
        <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0 mr-1" />
        High
      </Badge>
    );
  }

  if (norm === "medium") {
    return (
      <Badge
        variant="warning"
        className={cn(
          "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30 hover:bg-amber-500/20 font-mono uppercase text-[10px] tracking-wider font-semibold",
          className
        )}
      >
        <span className="w-1.5 h-1.5 rounded-full bg-amber-500 shrink-0 mr-1" />
        Medium
      </Badge>
    );
  }

  return (
    <Badge
      variant="outline"
      className={cn(
        "bg-secondary text-muted-foreground border-border font-mono uppercase text-[10px] tracking-wider",
        className
      )}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-slate-400 shrink-0 mr-1" />
      Low
    </Badge>
  );
};

export default SeverityBadge;
