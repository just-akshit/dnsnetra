"use client";

import React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Star,
  History,
  Activity,
  Shield,
  Globe2,
  UsersRound,
  FileSearch,
  Bell,
  ListFilter,
  Radar,
  Database,
  FileBarChart,
  Settings2,
  ArrowRight,
  Sparkles,
} from "lucide-react";
import {
  MAIN_NAV_SECTIONS,
  SETTINGS_SECTION,
  usePinnedPages,
  useRecentPages,
} from "@/lib/navigation";
import { useAuth } from "@/context/AuthContext";

export const HomePage: React.FC = () => {
  const router = useRouter();
  const { user } = useAuth();
  const { pinnedItems, togglePin, isPinned } = usePinnedPages();
  const { recentItems, clearRecents } = useRecentPages();

  const allSections = [...MAIN_NAV_SECTIONS, SETTINGS_SECTION];

  return (
    <div className="space-y-8 max-w-[1400px]">
      {/* Welcome Banner */}
      <div className="p-6 rounded-xl border border-border/60 bg-gradient-to-r from-card to-secondary/30 shadow-xs">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Sparkles className="w-4 h-4 text-primary" />
              <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground">
                Command Hub
              </span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-foreground">
              Welcome back, {user?.name || "Security Operator"}
            </h1>
            <p className="text-xs text-muted-foreground mt-1">
              Quick access to pinned destinations, recent investigations, and SOC modules.
            </p>
          </div>
          <Link
            href="/overview"
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-xs font-medium hover:opacity-90 transition-opacity shadow-xs cursor-pointer"
          >
            <span>Open Overview Dashboard</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>

      {/* Grid: Favorites & Recents */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Favorites Card */}
        <div className="p-5 rounded-xl border border-border bg-card shadow-xs">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-border/50">
            <div className="flex items-center gap-2">
              <Star className="w-4 h-4 text-amber-500 fill-amber-500" />
              <h2 className="text-sm font-semibold text-foreground">Favorites</h2>
              <span className="text-[11px] px-1.5 py-0.2 rounded-full bg-amber-500/15 text-amber-600 dark:text-amber-400 font-mono">
                {pinnedItems.length}
              </span>
            </div>
            <span className="text-[11px] text-muted-foreground">Pinned pages</span>
          </div>

          {pinnedItems.length === 0 ? (
            <div className="py-8 text-center text-xs text-muted-foreground">
              No pages pinned yet. Hover over any navigation item in the sidebar to pin it.
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {pinnedItems.map((item) => {
                const ItemIcon = item.icon;
                return (
                  <div
                    key={item.id}
                    onClick={() => router.push(item.path)}
                    className="flex items-center justify-between p-2.5 rounded-lg border border-border/50 bg-secondary/30 hover:bg-secondary/70 hover:border-primary/40 transition-all cursor-pointer group"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <div className="p-1.5 rounded-md bg-background text-muted-foreground group-hover:text-primary transition-colors">
                        <ItemIcon className="w-3.5 h-3.5" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-xs font-medium text-foreground truncate">
                          {item.label}
                        </p>
                        <p className="text-[10px] text-muted-foreground truncate">
                          {item.sectionLabel}
                        </p>
                      </div>
                    </div>
                    <button
                      type="button"
                      aria-label={`Unpin ${item.label}`}
                      onClick={(e) => {
                        e.stopPropagation();
                        togglePin(item.id);
                      }}
                      className="p-1 text-muted-foreground hover:text-amber-500 transition-colors"
                      title="Unpin page"
                    >
                      <Star className="w-3.5 h-3.5 fill-amber-500 text-amber-500" />
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Recents Card */}
        <div className="p-5 rounded-xl border border-border bg-card shadow-xs">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-border/50">
            <div className="flex items-center gap-2">
              <History className="w-4 h-4 text-blue-500" />
              <h2 className="text-sm font-semibold text-foreground">Recently Visited</h2>
              <span className="text-[11px] px-1.5 py-0.2 rounded-full bg-blue-500/15 text-blue-600 dark:text-blue-400 font-mono">
                {recentItems.length}
              </span>
            </div>
            {recentItems.length > 0 && (
              <button
                type="button"
                onClick={clearRecents}
                className="text-[11px] text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
              >
                Clear
              </button>
            )}
          </div>

          {recentItems.length === 0 ? (
            <div className="py-8 text-center text-xs text-muted-foreground">
              No recent visits recorded. Navigate through the platform to build your history.
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {recentItems.map((item) => {
                const ItemIcon = item.icon;
                return (
                  <div
                    key={`rec-${item.id}`}
                    onClick={() => router.push(item.path)}
                    className="flex items-center justify-between p-2.5 rounded-lg border border-border/50 bg-secondary/30 hover:bg-secondary/70 hover:border-primary/40 transition-all cursor-pointer group"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <div className="p-1.5 rounded-md bg-background text-muted-foreground group-hover:text-primary transition-colors">
                        <ItemIcon className="w-3.5 h-3.5" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-xs font-medium text-foreground truncate">
                          {item.label}
                        </p>
                        <p className="text-[10px] text-muted-foreground truncate">
                          {item.sectionLabel}
                        </p>
                      </div>
                    </div>
                    <ArrowRight className="w-3.5 h-3.5 text-muted-foreground group-hover:text-foreground group-hover:translate-x-0.5 transition-all" />
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* All Navigation Modules */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold tracking-tight text-foreground">
            All Navigation Modules
          </h2>
          <span className="text-xs text-muted-foreground">
            {allSections.reduce((acc, s) => acc + s.items.length, 0)} available pages
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {allSections.map((section) => {
            const SectionIcon = section.icon;
            return (
              <div
                key={section.id}
                className="p-4 rounded-xl border border-border bg-card shadow-xs flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center gap-2 pb-2.5 mb-2.5 border-b border-border/40">
                    <div className="p-1.5 rounded-md bg-secondary text-foreground">
                      <SectionIcon className="w-4 h-4" />
                    </div>
                    <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider">
                      {section.label}
                    </h3>
                  </div>

                  <div className="space-y-1">
                    {section.items.map((item) => (
                      <Link
                        key={item.id}
                        href={item.path}
                        className="flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs text-muted-foreground hover:text-foreground hover:bg-secondary/60 transition-colors"
                      >
                        <span className="truncate">{item.label}</span>
                        <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                      </Link>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default HomePage;
