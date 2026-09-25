"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  LayoutDashboard,
  Radio,
  Globe,
  Users,
  ShieldAlert,
  BarChart3,
  Settings,
  Search,
  ArrowRight,
  RefreshCw,
} from "lucide-react";
import {
  CommandDialog,
  CommandDialogPopup,
  Command,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandGroupLabel,
  CommandItem,
  CommandSeparator,
} from "@/components/ui/command";
import { useTimeRange } from "@/context/TimeRangeContext";

interface GlobalSearchDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export const GlobalSearchDialog: React.FC<GlobalSearchDialogProps> = ({
  open,
  onOpenChange,
}) => {
  const router = useRouter();
  const { triggerRefresh } = useTimeRange();
  const [query, setQuery] = useState("");

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        onOpenChange(!open);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, onOpenChange]);

  const handleSelect = (callback: () => void) => {
    onOpenChange(false);
    setQuery("");
    callback();
  };

  const handleDirectSearch = (searchTerm: string) => {
    const clean = searchTerm.trim();
    if (!clean) return;

    onOpenChange(false);
    setQuery("");

    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(clean) || clean.includes(":");
    if (isIp) {
      router.push(`/investigate/clients/${encodeURIComponent(clean)}`);
    } else {
      router.push(`/investigate/domains/${encodeURIComponent(clean)}`);
    }
  };

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange}>
      <CommandDialogPopup className="max-w-xl bg-popover border border-border shadow-xl rounded-lg overflow-hidden">
        <Command>
          <div className="flex items-center px-3 border-b border-border">
            <Search className="w-4 h-4 text-muted-foreground mr-2 shrink-0" />
            <CommandInput
              placeholder="Search domains, clients, pages..."
              value={query}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && query.trim()) {
                  e.preventDefault();
                  handleDirectSearch(query);
                }
              }}
              className="py-2.5 text-xs placeholder:text-muted-foreground focus:outline-none"
            />
          </div>

          <CommandList className="max-h-[300px] overflow-y-auto p-1.5 text-xs">
            <CommandEmpty className="py-6 text-center text-muted-foreground text-xs">
              {query ? (
                <div className="space-y-1.5">
                  <p>Press Enter to lookup:</p>
                  <button
                    onClick={() => handleDirectSearch(query)}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-primary text-primary-foreground font-mono text-xs hover:bg-primary/90 transition-colors"
                  >
                    <span>{query}</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
              ) : (
                "No results found."
              )}
            </CommandEmpty>

            {/* Direct Investigation */}
            {query.trim() && (
              <CommandGroup>
                <CommandGroupLabel>Direct Lookup</CommandGroupLabel>
                <CommandItem
                  onClick={() => handleDirectSearch(query)}
                  className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-accent cursor-pointer"
                >
                  <div className="flex items-center gap-2">
                    <Search className="w-3.5 h-3.5 text-primary" />
                    <span className="font-mono text-xs text-foreground">
                      Investigate <strong className="text-primary">{query}</strong>
                    </span>
                  </div>
                  <span className="text-[10px] text-muted-foreground font-mono">
                    Jump →
                  </span>
                </CommandItem>
              </CommandGroup>
            )}

            {/* Pages Navigation */}
            <CommandGroup>
              <CommandGroupLabel>Pages</CommandGroupLabel>
              <CommandItem
                onClick={() => handleSelect(() => router.push("/overview"))}
                className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-accent cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <LayoutDashboard className="w-3.5 h-3.5 text-muted-foreground" />
                  <span className="font-normal text-foreground">Home / Overview</span>
                </div>
                <span className="text-[10px] font-mono text-muted-foreground">/overview</span>
              </CommandItem>

              <CommandItem
                onClick={() => handleSelect(() => router.push("/analytics/dns"))}
                className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-accent cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <BarChart3 className="w-3.5 h-3.5 text-muted-foreground" />
                  <span className="font-normal text-foreground">DNS Analytics</span>
                </div>
                <span className="text-[10px] font-mono text-muted-foreground">/analytics/dns</span>
              </CommandItem>

              <CommandItem
                onClick={() => handleSelect(() => router.push("/analytics/threats"))}
                className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-accent cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-3.5 h-3.5 text-red-500" />
                  <span className="font-normal text-foreground">Threat Analytics</span>
                </div>
                <span className="text-[10px] font-mono text-muted-foreground">/analytics/threats</span>
              </CommandItem>

              <CommandItem
                onClick={() => handleSelect(() => router.push("/investigate/domains"))}
                className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-accent cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <Globe className="w-3.5 h-3.5 text-muted-foreground" />
                  <span className="font-normal text-foreground">Investigate Domains</span>
                </div>
                <span className="text-[10px] font-mono text-muted-foreground">/investigate/domains</span>
              </CommandItem>

              <CommandItem
                onClick={() => handleSelect(() => router.push("/investigate/clients"))}
                className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-accent cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <Users className="w-3.5 h-3.5 text-muted-foreground" />
                  <span className="font-normal text-foreground">Investigate Clients</span>
                </div>
                <span className="text-[10px] font-mono text-muted-foreground">/investigate/clients</span>
              </CommandItem>

              <CommandItem
                onClick={() => handleSelect(() => router.push("/reports"))}
                className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-accent cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <Radio className="w-3.5 h-3.5 text-muted-foreground" />
                  <span className="font-normal text-foreground">Reports</span>
                </div>
                <span className="text-[10px] font-mono text-muted-foreground">/reports</span>
              </CommandItem>

              <CommandItem
                onClick={() => handleSelect(() => router.push("/settings"))}
                className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-accent cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <Settings className="w-3.5 h-3.5 text-muted-foreground" />
                  <span className="font-normal text-foreground">Settings</span>
                </div>
                <span className="text-[10px] font-mono text-muted-foreground">/settings</span>
              </CommandItem>
            </CommandGroup>

            <CommandSeparator className="my-1 border-border" />

            {/* Quick Actions */}
            <CommandGroup>
              <CommandGroupLabel>Actions</CommandGroupLabel>
              <CommandItem
                onClick={() => handleSelect(() => triggerRefresh())}
                className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-accent cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <RefreshCw className="w-3.5 h-3.5 text-primary" />
                  <span className="font-normal text-foreground">Refresh Telemetry</span>
                </div>
                <span className="text-[10px] font-mono text-muted-foreground">Sync</span>
              </CommandItem>
            </CommandGroup>
          </CommandList>
        </Command>
      </CommandDialogPopup>
    </CommandDialog>
  );
};

export default GlobalSearchDialog;
