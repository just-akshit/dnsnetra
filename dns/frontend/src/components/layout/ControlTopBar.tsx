"use client";

import React, { useState, useEffect } from "react";
import {
  Sun,
  Moon,
  LogOut,
} from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { DomainIntelligenceSearch } from "@/components/layout/DomainIntelligenceSearch";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface ControlTopBarProps {
  onOpenSearch?: () => void;
}

export const ControlTopBar: React.FC<ControlTopBarProps> = ({ onOpenSearch }) => {
  const { user, logout } = useAuth();
  const [theme, setTheme] = useState<"light" | "dark">("light");

  useEffect(() => {
    if (typeof window === "undefined") return;
    const isDark = document.documentElement.classList.contains("dark");
    const stored = localStorage.getItem("theme") as "light" | "dark" | null;
    const initialTheme = stored || (isDark ? "dark" : "light");
    setTheme(initialTheme);
    if (initialTheme === "dark") {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }

    const observer = new MutationObserver(() => {
      setTheme(document.documentElement.classList.contains("dark") ? "dark" : "light");
    });
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class"],
    });
    return () => observer.disconnect();
  }, []);

  const toggleTheme = () => {
    const nextTheme = theme === "light" ? "dark" : "light";
    setTheme(nextTheme);
    if (nextTheme === "dark") {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
    if (typeof window !== "undefined") {
      localStorage.setItem("theme", nextTheme);
    }
  };

  const initials = (user?.name || user?.email || "AJ").substring(0, 2).toUpperCase();

  return (
    <header className="h-14 bg-[#FFFFFF] dark:bg-[#0E1320] border-b border-[#EBEBEB] dark:border-[#1E283D] px-6 sm:px-8 flex items-center justify-between gap-4 z-20 shrink-0 select-none">
      {/* 1. LEFT: Workspace / Application Branding */}
      <div className="flex items-center gap-2.5 shrink-0">
        <span className="font-semibold text-[13px] tracking-tight text-[#1A1A1A] dark:text-[#F3F4F6] hidden sm:inline">
          DNS THREAT DETECTION
        </span>
      </div>

      {/* 2. CENTER: Global Domain Intelligence Search Engine */}
      <div className="flex flex-1 justify-center max-w-[680px] min-w-0">
        <DomainIntelligenceSearch onOpenDialog={onOpenSearch} />
      </div>

      {/* 3. RIGHT: Existing Theme Toggle & User Account Dropdown */}
      <div className="flex shrink-0 items-center gap-3.5 text-[13px] font-medium text-[#6B6B6B] dark:text-[#9CA3AF]">
        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="p-1.5 rounded-[6px] hover:bg-[#F2F2F2] dark:hover:bg-[#1C2438] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6] transition-colors cursor-pointer"
          title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
        >
          {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>

        {/* User Profile Avatar Dropdown */}
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <button
                className="w-7 h-7 rounded-full bg-[#1A1A1A] dark:bg-[#F3F4F6] text-[#FFFFFF] dark:text-[#1A1A1A] text-[11px] font-semibold flex items-center justify-center cursor-pointer hover:opacity-90 transition-opacity"
                title="Account menu"
              />
            }
          >
            <span>{initials}</span>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            align="end"
            className="w-56 bg-[#FFFFFF] dark:bg-[#121826] border-[#EBEBEB] dark:border-[#1E283D] rounded-[6px] shadow-sm text-[13px]"
          >
            <DropdownMenuLabel className="font-normal p-2">
              <div className="text-[13px] font-medium text-[#1A1A1A] dark:text-[#F3F4F6]">
                {user?.name || "Security Operator"}
              </div>
              <div className="text-[11px] text-[#6B6B6B] dark:text-[#9CA3AF] truncate">
                {user?.email || "admin@soc.local"}
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator className="bg-[#EBEBEB] dark:bg-[#1E283D]" />
            <DropdownMenuItem
              onClick={logout}
              className="text-red-500 hover:bg-red-50 dark:hover:bg-red-950/30 p-2 cursor-pointer rounded-[4px]"
            >
              <LogOut className="w-3.5 h-3.5 mr-2" />
              <span>Log out</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
};

export default ControlTopBar;
