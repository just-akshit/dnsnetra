import * as React from "react"
import { cn } from "cn"
import { Badge } from "@/components/ui/badge"
import {
  CircleCheckIcon,
  AlertTriangleIcon,
  ShieldAlertIcon,
  HelpCircleIcon,
  BanIcon,
  ActivityIcon,
} from "lucide-react"

export interface DataTableStatusProps {
  status: string | null | undefined
  className?: string
  showIcon?: boolean
}

type StatusStyle = {
  label: string
  variant: "default" | "secondary" | "destructive" | "outline"
  badgeClass: string
  icon: React.ReactNode
}

function resolveStatus(rawStatus: string | null | undefined): StatusStyle {
  if (!rawStatus) {
    return {
      label: "Unknown",
      variant: "outline",
      badgeClass: "bg-muted text-muted-foreground border-border",
      icon: <HelpCircleIcon className="size-3 text-muted-foreground" />,
    }
  }

  const s = rawStatus.trim().toLowerCase()

  // Clean / Benign / Done
  if (
    s === "clean" ||
    s === "benign" ||
    s === "done" ||
    s === "safe" ||
    s === "active"
  ) {
    return {
      label: s === "done" ? "Done" : s === "active" ? "Active" : "Clean",
      variant: "outline",
      badgeClass:
        "border-emerald-600/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 font-medium",
      icon: (
        <CircleCheckIcon className="size-3 text-emerald-600 dark:text-emerald-400 fill-emerald-500/20" />
      ),
    }
  }

  // Malicious / Blocked / Threat
  if (
    s === "malicious" ||
    s === "blocked" ||
    s === "threat" ||
    s === "blacklisted"
  ) {
    return {
      label: s === "blocked" ? "Blocked" : "Malicious",
      variant: "outline",
      badgeClass:
        "border-rose-600/30 bg-rose-500/10 text-rose-700 dark:text-rose-400 font-medium",
      icon: (
        <ShieldAlertIcon className="size-3 text-rose-600 dark:text-rose-400" />
      ),
    }
  }

  // Suspicious / Review Needed / In Process
  if (
    s === "suspicious" ||
    s === "review needed" ||
    s === "review_needed" ||
    s === "review" ||
    s === "in process" ||
    s === "flagged"
  ) {
    return {
      label:
        s === "in process"
          ? "In Process"
          : s === "suspicious"
          ? "Suspicious"
          : "Review Needed",
      variant: "outline",
      badgeClass:
        "border-amber-600/30 bg-amber-500/10 text-amber-700 dark:text-amber-400 font-medium",
      icon: (
        <AlertTriangleIcon className="size-3 text-amber-600 dark:text-amber-400" />
      ),
    }
  }

  // Inactive
  if (s === "inactive" || s === "disabled") {
    return {
      label: "Inactive",
      variant: "outline",
      badgeClass: "bg-muted text-muted-foreground border-border",
      icon: <BanIcon className="size-3 text-muted-foreground" />,
    }
  }

  // Fallback
  return {
    label: rawStatus,
    variant: "outline",
    badgeClass: "bg-muted text-muted-foreground border-border",
    icon: <ActivityIcon className="size-3 text-muted-foreground" />,
  }
}

/**
 * Standard DNSNetra status/verdict cell renderer.
 * Clean, restrained, compact, using semantic reinforcement rather than loud colors.
 */
export function DataTableStatus({
  status,
  className,
  showIcon = true,
}: DataTableStatusProps) {
  const resolved = resolveStatus(status)

  return (
    <Badge
      variant="outline"
      className={cn(
        "inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-mono tracking-tight",
        resolved.badgeClass,
        className
      )}
    >
      {showIcon && resolved.icon}
      <span>{resolved.label}</span>
    </Badge>
  )
}
