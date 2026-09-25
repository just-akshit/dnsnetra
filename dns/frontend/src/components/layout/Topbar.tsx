"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Search,
  RefreshCw,
  Check,
  Sun,
  Moon,
} from "lucide-react";
import { SidebarTrigger } from "@/components/ui/sidebar";
import {
  Breadcrumb,
  BreadcrumbList,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { GlobalTimeRangePicker } from "./GlobalTimeRangePicker";
import { useTimeRange } from "@/context/TimeRangeContext";
import { cn } from "@/lib/utils";

interface TopbarProps {
  onOpenSearch: () => void;
}

export const Topbar: React.FC<TopbarProps> = ({ onOpenSearch }) => {
  const pathname = usePathname() || "";
  const { isRefreshing, triggerRefresh } = useTimeRange();

  const [refreshState, setRefreshState] = useState<"idle" | "refreshing" | "success">("idle");
  const [theme, setTheme] = useState<"dark" | "light">("light");

  useEffect(() => {
    setTheme(document.documentElement.classList.contains("dark") ? "dark" : "light");
  }, []);

  const toggleTheme = () => {
    const nextTheme = theme === "dark" ? "light" : "dark";
    setTheme(nextTheme);
    if (nextTheme === "dark") {
      document.documentElement.classList.add("dark");
      localStorage.setItem("theme", "dark");
    } else {
      document.documentElement.classList.remove("dark");
      localStorage.setItem("theme", "light");
    }
  };

  const handleManualRefresh = async () => {
    if (isRefreshing) return;
    setRefreshState("refreshing");
    await triggerRefresh();
    setRefreshState("success");
    setTimeout(() => {
      setRefreshState("idle");
    }, 1200);
  };

  // Derive simple breadcrumbs
  const getBreadcrumbs = () => {
    const p = pathname;
    if (p === "/" || p === "/overview") {
      return [{ label: "Dashboards", href: "/overview" }, { label: "Overview" }];
    }
    if (p.startsWith("/dns") || p.startsWith("/analytics/dns")) {
      return [{ label: "Dashboards", href: "/overview" }, { label: "DNS" }];
    }
    if (p.startsWith("/domains") || p.startsWith("/investigate/domains")) {
      if (p !== "/domains" && p !== "/investigate/domains") {
        const domainParam = p.replace("/investigate/domains/", "").replace("/domains/", "");
        return [
          { label: "Domains", href: "/investigate/domains" },
          { label: decodeURIComponent(domainParam) },
        ];
      }
      return [{ label: "Dashboards", href: "/overview" }, { label: "Domains" }];
    }
    if (p.startsWith("/clients") || p.startsWith("/investigate/clients")) {
      if (p !== "/clients" && p !== "/investigate/clients") {
        const clientParam = p.replace("/investigate/clients/", "").replace("/clients/", "");
        return [
          { label: "Clients", href: "/investigate/clients" },
          { label: decodeURIComponent(clientParam) },
        ];
      }
      return [{ label: "Dashboards", href: "/overview" }, { label: "Clients" }];
    }
    if (p.startsWith("/threats") || p.startsWith("/analytics/threats")) {
      return [{ label: "Dashboards", href: "/overview" }, { label: "Threats" }];
    }
    if (p.startsWith("/analytics")) {
      return [{ label: "Dashboards", href: "/overview" }, { label: "Analytics" }];
    }
    if (p.startsWith("/settings")) {
      return [{ label: "Settings", href: "/settings" }, { label: "General" }];
    }
    return [{ label: "Dashboards", href: "/overview" }, { label: "Overview" }];
  };

  const breadcrumbs = getBreadcrumbs();

  return (
    <header className="h-11 border-b border-border/70 bg-background/95 backdrop-blur-md px-4 flex items-center justify-between gap-4 sticky top-0 z-30">
      {/* Left: Sidebar trigger + Breadcrumbs */}
      <div className="flex items-center gap-2.5 min-w-0">
        <SidebarTrigger className="text-muted-foreground hover:text-foreground cursor-pointer h-7 w-7" />
        <div className="h-3.5 w-px bg-border/60 hidden sm:block" />

        <Breadcrumb className="hidden sm:flex text-xs">
          <BreadcrumbList>
            {breadcrumbs.map((crumb, idx) => {
              const isLast = idx === breadcrumbs.length - 1;
              return (
                <React.Fragment key={idx}>
                  {idx > 0 && <BreadcrumbSeparator className="text-muted-foreground/50" />}
                  <BreadcrumbItem>
                    {isLast ? (
                      <BreadcrumbPage className="font-medium text-foreground truncate max-w-[200px]">
                        {crumb.label}
                      </BreadcrumbPage>
                    ) : (
                      <BreadcrumbLink
                        render={<Link href={crumb.href || "#"} className="text-muted-foreground hover:text-foreground" />}
                      >
                        {crumb.label}
                      </BreadcrumbLink>
                    )}
                  </BreadcrumbItem>
                </React.Fragment>
              );
            })}
          </BreadcrumbList>
        </Breadcrumb>
      </div>

      {/* Right Controls: Search, Refresh, Time Range, Theme */}
      <div className="flex items-center gap-2 shrink-0">
        {/* Quick Search */}
        <button
          onClick={onOpenSearch}
          className="hidden md:flex items-center gap-2 px-2.5 py-1 rounded border border-border/80 bg-muted/30 hover:bg-accent text-xs text-muted-foreground transition-colors cursor-pointer w-44"
          title="Search (⌘K)"
        >
          <Search className="w-3.5 h-3.5" />
          <span className="flex-1 text-left truncate text-[12px]">Search...</span>
          <kbd className="text-[10px] font-mono bg-background border border-border px-1 py-0.2 rounded text-muted-foreground">
            ⌘K
          </kbd>
        </button>

        {/* Stateful Refresh Button */}
        <button
          onClick={handleManualRefresh}
          disabled={isRefreshing}
          className={cn(
            "flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded border border-border/80 bg-background hover:bg-accent transition-all cursor-pointer select-none",
            refreshState === "success" && "text-emerald-500 border-emerald-500/30"
          )}
          title="Refresh data"
        >
          {refreshState === "refreshing" || isRefreshing ? (
            <>
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-500" />
              <span className="text-[12px] hidden sm:inline">Refreshing...</span>
            </>
          ) : refreshState === "success" ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-500" />
              <span className="text-[12px] hidden sm:inline">Updated</span>
            </>
          ) : (
            <>
              <RefreshCw className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="text-[12px] hidden sm:inline">Live refresh</span>
            </>
          )}
        </button>

        {/* Global Time Range Picker */}
        <GlobalTimeRangePicker />

        {/* Theme Toggle Button */}
        <button
          onClick={toggleTheme}
          className="p-1 rounded border border-border/80 bg-background hover:bg-accent text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
          title={`Switch to ${theme === "dark" ? "Light" : "Dark"} mode`}
        >
          {theme === "dark" ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
        </button>
      </div>
    </header>
  );
};

export default Topbar;
