"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Search,
  ChevronDown,
  LayoutDashboard,
  Radio,
  ShieldAlert,
  Globe,
  Users,
  BarChart2,
  PanelLeftClose,
  PanelLeft,
  Settings,
} from "lucide-react";
import { BrandLogo } from "./BrandLogo";
import { useAuth } from "@/context/AuthContext";
import { cn } from "@/lib/utils";

interface ControlSidebarProps {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
  onOpenSearch?: () => void;
}

export const ControlSidebar: React.FC<ControlSidebarProps> = ({
  collapsed = false,
  onToggleCollapse,
  onOpenSearch,
}) => {
  const pathname = usePathname() || "";
  const { user } = useAuth();

  const accountEmail = user?.email || "Akshitjain827@gmail.com";

  const isActive = (href: string) => Boolean(pathname && (pathname === href || pathname.startsWith(href + "/")));

  if (collapsed) {
    return (
      <aside className="w-16 bg-[#FFFFFF] dark:bg-[#0E1320] border-r border-[#EBEBEB] dark:border-[#1E283D] flex flex-col justify-between py-4 items-center shrink-0 select-none z-30 transition-all">
        <div className="flex flex-col items-center gap-4">
          <Link href="/analytics/dns" title="DNS Analytics">
            <BrandLogo className="w-7 h-7" />
          </Link>
          <button
            onClick={onOpenSearch}
            className="p-2 rounded-md hover:bg-[#F2F2F2] dark:hover:bg-[#1C2438] text-[#6B6B6B] transition-colors"
            title="Quick search (⌘K)"
          >
            <Search className="w-4 h-4" />
          </button>
        </div>

        <button
          onClick={onToggleCollapse}
          className="p-2 rounded-md hover:bg-[#F2F2F2] dark:hover:bg-[#1C2438] text-[#6B6B6B] transition-colors"
          title="Expand sidebar"
        >
          <PanelLeft className="w-4 h-4" />
        </button>
      </aside>
    );
  }

  return (
    <aside className="w-[300px] bg-[#FFFFFF] dark:bg-[#0E1320] border-r border-[#EBEBEB] dark:border-[#1E283D] flex flex-col justify-between shrink-0 select-none z-30 h-screen sticky top-0 transition-all">
      {/* Upper Content Area */}
      <div className="flex-1 overflow-y-auto">
        {/* 1. Account Switcher Header */}
        <div className="p-4 border-b border-[#EBEBEB] dark:border-[#1E283D]">
          <button
            className="w-full flex items-center justify-between gap-2.5 text-left group hover:opacity-90 transition-opacity cursor-pointer"
            title="Switch account"
          >
            <div className="flex items-center gap-2.5 min-w-0">
              <BrandLogo className="w-6 h-6 shrink-0" />
              <div className="min-w-0">
                <span className="text-[13px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6] truncate block">
                  {accountEmail}'s Account
                </span>
              </div>
            </div>
            <ChevronDown className="w-4 h-4 text-[#6B6B6B] dark:text-[#9CA3AF] shrink-0" />
          </button>

          {/* 2. Search Box */}
          <div className="mt-3 relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-[#9C9C9C]" />
            <input
              type="text"
              readOnly
              onClick={onOpenSearch}
              placeholder="Quick search..."
              className="w-full pl-8 pr-12 py-1.5 bg-[#FFFFFF] dark:bg-[#121826] border border-[#D9D9D9] dark:border-[#2D3A54] rounded-[6px] text-[13px] text-[#1A1A1A] dark:text-[#F3F4F6] placeholder:text-[#9C9C9C] focus:outline-none cursor-pointer"
            />
            <kbd className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-[#9C9C9C] bg-[#F2F2F2] dark:bg-[#1C2438] px-1.5 py-0.5 rounded font-mono">
              ⌘K
            </kbd>
          </div>
        </div>

        {/* 3. Navigation Section */}
        <nav className="p-2 space-y-1 mt-2">
          <div className="px-2 py-1 text-[11px] font-semibold text-[#9C9C9C] uppercase tracking-wider">
            DNS Threat Detection
          </div>

          <div className="space-y-0.5 mt-1">
            {/* Overview / Dashboards */}
            <Link
              href="/overview"
              className={cn(
                "flex items-center justify-between px-2.5 py-2 rounded-[6px] text-[14px] font-normal transition-colors group cursor-pointer",
                isActive("/overview") || pathname === "/"
                  ? "bg-[#F2F2F2] dark:bg-[#1C2438] font-medium text-[#1A1A1A] dark:text-[#F3F4F6]"
                  : "text-[#6B6B6B] dark:text-[#9CA3AF] hover:bg-[#F2F2F2]/60 dark:hover:bg-[#1C2438]/60 hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
              )}
            >
              <div className="flex items-center gap-2.5">
                <LayoutDashboard className="w-[18px] h-[18px] text-[#6B6B6B] dark:text-[#9CA3AF]" />
                <span>Overview</span>
              </div>
            </Link>

            {/* DNS Analytics */}
            <Link
              href="/analytics/dns"
              className={cn(
                "flex items-center justify-between px-2.5 py-2 rounded-[6px] text-[14px] font-normal transition-colors group cursor-pointer",
                isActive("/analytics/dns")
                  ? "bg-[#F2F2F2] dark:bg-[#1C2438] font-medium text-[#1A1A1A] dark:text-[#F3F4F6]"
                  : "text-[#6B6B6B] dark:text-[#9CA3AF] hover:bg-[#F2F2F2]/60 dark:hover:bg-[#1C2438]/60 hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
              )}
            >
              <div className="flex items-center gap-2.5">
                <Radio className="w-[18px] h-[18px] text-[#6B6B6B] dark:text-[#9CA3AF]" />
                <div>
                  <div className="leading-tight">DNS Analytics</div>
                  <div className="text-[11px] text-[#9C9C9C] leading-tight">Telemetry &amp; latency</div>
                </div>
              </div>
            </Link>

            {/* Security Events / Threats */}
            <Link
              href="/analytics/threats"
              className={cn(
                "flex items-center justify-between px-2.5 py-2 rounded-[6px] text-[14px] font-normal transition-colors group cursor-pointer",
                isActive("/analytics/threats")
                  ? "bg-[#F2F2F2] dark:bg-[#1C2438] font-medium text-[#1A1A1A] dark:text-[#F3F4F6]"
                  : "text-[#6B6B6B] dark:text-[#9CA3AF] hover:bg-[#F2F2F2]/60 dark:hover:bg-[#1C2438]/60 hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
              )}
            >
              <div className="flex items-center gap-2.5">
                <ShieldAlert className="w-[18px] h-[18px] text-[#6B6B6B] dark:text-[#9CA3AF]" />
                <span>Threats &amp; Incidents</span>
              </div>
            </Link>

            {/* Domains */}
            <Link
              href="/investigate/domains"
              className={cn(
                "flex items-center justify-between px-2.5 py-2 rounded-[6px] text-[14px] font-normal transition-colors group cursor-pointer",
                isActive("/investigate/domains")
                  ? "bg-[#F2F2F2] dark:bg-[#1C2438] font-medium text-[#1A1A1A] dark:text-[#F3F4F6]"
                  : "text-[#6B6B6B] dark:text-[#9CA3AF] hover:bg-[#F2F2F2]/60 dark:hover:bg-[#1C2438]/60 hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
              )}
            >
              <div className="flex items-center gap-2.5">
                <Globe className="w-[18px] h-[18px] text-[#6B6B6B] dark:text-[#9CA3AF]" />
                <span>Queried Domains</span>
              </div>
            </Link>

            {/* Client Endpoints */}
            <Link
              href="/investigate/clients"
              className={cn(
                "flex items-center justify-between px-2.5 py-2 rounded-[6px] text-[14px] font-normal transition-colors group cursor-pointer",
                isActive("/investigate/clients")
                  ? "bg-[#F2F2F2] dark:bg-[#1C2438] font-medium text-[#1A1A1A] dark:text-[#F3F4F6]"
                  : "text-[#6B6B6B] dark:text-[#9CA3AF] hover:bg-[#F2F2F2]/60 dark:hover:bg-[#1C2438]/60 hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
              )}
            >
              <div className="flex items-center gap-2.5">
                <Users className="w-[18px] h-[18px] text-[#6B6B6B] dark:text-[#9CA3AF]" />
                <span>Client Endpoints</span>
              </div>
            </Link>

            {/* Analytics */}
            <Link
              href="/analytics"
              className={cn(
                "flex items-center justify-between px-2.5 py-2 rounded-[6px] text-[14px] font-normal transition-colors group cursor-pointer",
                pathname === "/analytics"
                  ? "bg-[#F2F2F2] dark:bg-[#1C2438] font-medium text-[#1A1A1A] dark:text-[#F3F4F6]"
                  : "text-[#6B6B6B] dark:text-[#9CA3AF] hover:bg-[#F2F2F2]/60 dark:hover:bg-[#1C2438]/60 hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6]"
              )}
            >
              <div className="flex items-center gap-2.5">
                <BarChart2 className="w-[18px] h-[18px] text-[#6B6B6B] dark:text-[#9CA3AF]" />
                <span>Time-Window Analytics</span>
              </div>
            </Link>
          </div>
        </nav>
      </div>

      {/* Footer / Collapse & Settings */}
      <div className="p-3 border-t border-[#EBEBEB] dark:border-[#1E283D] flex items-center justify-between">
        <button
          onClick={onToggleCollapse}
          className="p-1.5 rounded-[6px] hover:bg-[#F2F2F2] dark:hover:bg-[#1C2438] text-[#6B6B6B] transition-colors cursor-pointer"
          title="Collapse sidebar"
        >
          <PanelLeftClose className="w-4 h-4" />
        </button>

        <Link
          href="/settings"
          className="text-[12px] text-[#6B6B6B] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6] flex items-center gap-1.5"
        >
          <Settings className="w-3.5 h-3.5" />
          <span>Settings</span>
        </Link>
      </div>
    </aside>
  );
};

export default ControlSidebar;
