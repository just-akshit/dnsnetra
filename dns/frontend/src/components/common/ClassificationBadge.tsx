import React from "react";

interface ClassificationBadgeProps {
  label?: string | null;
  className?: string;
}

export const ClassificationBadge: React.FC<ClassificationBadgeProps> = ({
  label,
  className = "",
}) => {
  const norm = (label || "unknown").toLowerCase();

  if (norm === "malicious") {
    return (
      <span
        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider bg-red-500/15 text-red-400 border border-red-500/30 ${className}`}
      >
        Malicious
      </span>
    );
  }

  if (norm === "review_needed" || norm === "review needed" || norm === "suspicious") {
    return (
      <span
        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider bg-amber-500/15 text-amber-400 border border-amber-500/30 ${className}`}
      >
        Review Needed
      </span>
    );
  }

  if (norm === "clean" || norm === "benign" || norm === "trusted") {
    return (
      <span
        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 ${className}`}
      >
        Benign
      </span>
    );
  }

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider bg-slate-500/15 text-slate-400 border border-slate-500/30 ${className}`}
    >
      {label && !["suspicious", "clean"].includes(norm) ? label : "Unknown"}
    </span>
  );
};

export default ClassificationBadge;
