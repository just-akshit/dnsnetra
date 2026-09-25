import React from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export interface VerdictBadgeProps {
  verdict?: string | null;
  className?: string;
}

export const VerdictBadge: React.FC<VerdictBadgeProps> = ({ verdict, className }) => {
  const norm = (verdict || "unknown").toLowerCase().trim();

  if (norm === "malicious" || norm === "known_malicious") {
    return (
      <Badge
        variant="destructive"
        className={cn(
          "bg-red-500/15 text-red-500 dark:text-red-400 border-red-500/30 hover:bg-red-500/20 font-mono uppercase text-[10px] tracking-wider font-semibold",
          className
        )}
      >
        <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0 mr-1" />
        Malicious
      </Badge>
    );
  }

  if (norm === "review_needed" || norm === "review needed" || norm === "suspicious") {
    return (
      <Badge
        variant="warning"
        className={cn(
          "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30 hover:bg-amber-500/20 font-mono uppercase text-[10px] tracking-wider font-semibold",
          className
        )}
      >
        <span className="w-1.5 h-1.5 rounded-full bg-amber-500 shrink-0 mr-1" />
        Review Needed
      </Badge>
    );
  }

  if (norm === "benign" || norm === "clean" || norm === "popular_benign_context" || norm === "known_clean" || norm === "trusted") {
    return (
      <Badge
        variant="success"
        className={cn(
          "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20 font-mono uppercase text-[10px] tracking-wider font-semibold",
          className
        )}
      >
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0 mr-1" />
        Benign
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
      {verdict && !["suspicious", "clean"].includes(norm) ? verdict : "Unknown"}
    </Badge>
  );
};

export default VerdictBadge;
