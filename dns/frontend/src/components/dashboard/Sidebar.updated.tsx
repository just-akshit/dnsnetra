"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Bell,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  FileBarChart,
  FileSearch,
  History,
  Home,
  LayoutDashboard,
  MoreHorizontal,
  PanelLeftClose,
  PanelLeftOpen,
  Pin,
  Radar,
  Search,
  Settings2,
  Star,
  UserRound,
  X,
} from "lucide-react";
import {
  MAIN_NAV_SECTIONS,
  SETTINGS_SECTION,
  usePinnedPages,
  useRecentPages,
} from "@/lib/navigation";
import { cn } from "@/lib/utils";

export type SidebarTheme = "dark" | "light";

export interface SidebarProps {
  workspaceName?: string;
  activeItemId?: string;
  activeSectionId?: string;
  theme?: SidebarTheme;
  user?: {
    name?: string;
    subtitle?: string;
    avatarUrl?: string;
  };
  onNavigate?: (path: string) => void;
  onSearch?: (query: string) => void;
  onAccountClick?: () => void;
  onSidebarCollapse?: (collapsed: boolean) => void;
  className?: string;
}

/* -------------------------------------------------------------------------- */
/* Rail Section Configurations (Home, Overview, Analytics, Investigate,       */
/* Operations, Intelligence, Reports, Settings)                               */
/* -------------------------------------------------------------------------- */

interface RailSectionItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string; strokeWidth?: number }>;
}

const RAIL_SECTIONS: RailSectionItem[] = [
  { id: "home", label: "Home", icon: Home },
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "analytics", label: "Analytics", icon: Activity },
  { id: "investigate", label: "Investigate", icon: FileSearch },
  { id: "operations", label: "Operations", icon: Bell },
  { id: "intelligence", label: "Intelligence", icon: Radar },
  { id: "reports", label: "Reports", icon: FileBarChart },
];

/* -------------------------------------------------------------------------- */
/* Resizing Constants & Initial State                                         */
/* -------------------------------------------------------------------------- */

const MIN_WIDTH = 280;
const DEFAULT_WIDTH = 340;
const MAX_WIDTH = 580;
const STORAGE_KEY = "dns-threat-detection-sidebar-width";

function initialOpenState(): Record<string, boolean> {
  return Object.fromEntries(
    [...MAIN_NAV_SECTIONS, SETTINGS_SECTION].map((section) => [
      section.id,
      section.defaultOpen !== false,
    ]),
  );
}

export default function Sidebar({
  workspaceName = "DNS Threat Detection",
  activeItemId = "dashboard",
  activeSectionId,
  theme,
  user = { name: "Security Operator", subtitle: "admin@soc.local" },
  onNavigate,
  onAccountClick,
  onSidebarCollapse,
  className = "",
}: SidebarProps) {
  const { isPinned, togglePin, pinnedItems } = usePinnedPages();
  const { recentItems, clearRecents } = useRecentPages();

  // Selected Section controls what is displayed in the Expanded Sidebar panel:
  // "home" | "overview" | "analytics" | "investigate" | "operations" | "intelligence" | "reports" | "settings"
  const [selectedSection, setSelectedSection] = useState<string>(() => {
    return activeSectionId || "overview";
  });

  const [collapsed, setCollapsed] = useState<boolean>(false);
  const [favoritesOpen, setFavoritesOpen] = useState<boolean>(true);
  const [recentsOpen, setRecentsOpen] = useState<boolean>(true);
  const [allNavOpen, setAllNavOpen] = useState<boolean>(true);
  const [query, setQuery] = useState<string>("");
  const [openSections, setOpenSections] = useState<Record<string, boolean>>(initialOpenState);



  /* ------------------------------------------------------------------------ */
  /* Sidebar Width & Drag-to-Resize State                                     */
  /* ------------------------------------------------------------------------ */

  const [sidebarWidth, setSidebarWidth] = useState<number>(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const parsed = parseInt(saved, 10);
        if (!isNaN(parsed) && parsed >= MIN_WIDTH && parsed <= MAX_WIDTH) {
          return parsed;
        }
      }
    }
    return DEFAULT_WIDTH;
  });

  const [isDragging, setIsDragging] = useState(false);
  const startPosRef = useRef<{ startX: number; startWidth: number }>({
    startX: 0,
    startWidth: DEFAULT_WIDTH,
  });

  const handlePointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    if (e.button !== 0 && e.pointerType === "mouse") return;
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
    startPosRef.current = {
      startX: e.clientX,
      startWidth: sidebarWidth,
    };
    try {
      e.currentTarget.setPointerCapture(e.pointerId);
    } catch {
      // ignore
    }
  };

  const handlePointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!isDragging) return;
    const delta = e.clientX - startPosRef.current.startX;
    const nextWidth = Math.min(
      MAX_WIDTH,
      Math.max(MIN_WIDTH, Math.round(startPosRef.current.startWidth + delta)),
    );
    setSidebarWidth(nextWidth);
    if (typeof window !== "undefined") {
      localStorage.setItem(STORAGE_KEY, nextWidth.toString());
    }
  };

  const handlePointerUp = (e: React.PointerEvent<HTMLDivElement>) => {
    if (isDragging) {
      setIsDragging(false);
      try {
        e.currentTarget.releasePointerCapture(e.pointerId);
      } catch {
        // ignore
      }
    }
  };

  const handlePointerCancel = (e: React.PointerEvent<HTMLDivElement>) => {
    if (isDragging) {
      setIsDragging(false);
      try {
        e.currentTarget.releasePointerCapture(e.pointerId);
      } catch {
        // ignore
      }
    }
  };

  const handleDoubleClick = (e: React.MouseEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setSidebarWidth(DEFAULT_WIDTH);
    if (typeof window !== "undefined") {
      localStorage.setItem(STORAGE_KEY, DEFAULT_WIDTH.toString());
    }
  };

  useEffect(() => {
    if (isDragging) {
      document.body.style.userSelect = "none";
      document.body.style.cursor = "col-resize";
    } else {
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
    }
    return () => {
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
    };
  }, [isDragging]);

  /* ------------------------------------------------------------------------ */
  /* Rail Icon Click: ONLY selects section & expands sidebar (NO navigation!) */
  /* ------------------------------------------------------------------------ */

  const handleRailSelect = (sectionId: string) => {
    setCollapsed(false);
    setSelectedSection(sectionId);
    setQuery("");
  };

  const handleSidebarCollapseToggle = () => {
    const next = !collapsed;
    setCollapsed(next);
    onSidebarCollapse?.(next);
  };

  const toggleSection = (sectionId: string) => {
    setOpenSections((current) => ({
      ...current,
      [sectionId]: !current[sectionId],
    }));
  };

  // Find the single section to display if a specific section is selected
  const currentSectionConfig = useMemo(() => {
    if (selectedSection === "settings") return SETTINGS_SECTION;
    return MAIN_NAV_SECTIONS.find((s) => s.id === selectedSection);
  }, [selectedSection]);

  // Filtered items when searching
  const filteredAllSections = useMemo(() => {
    if (!query.trim()) return MAIN_NAV_SECTIONS;
    const q = query.toLowerCase();
    return MAIN_NAV_SECTIONS.map((sec) => {
      const matchesSection = sec.label.toLowerCase().includes(q);
      const filteredItems = sec.items.filter((it) =>
        it.label.toLowerCase().includes(q),
      );
      if (matchesSection) return sec;
      return { ...sec, items: filteredItems };
    }).filter((sec) => sec.items.length > 0);
  }, [query]);

  /* ------------------------------------------------------------------------ */
  /* Collapsed Rail Only (64px)                                               */
  /* ------------------------------------------------------------------------ */

  if (collapsed) {
    return (
      <aside
        className={cn(
          "relative flex h-full w-[64px] min-w-[64px] shrink-0 flex-col overflow-hidden",
          "rounded-[16px] border shadow-2xl transition-all duration-200 select-none",
          "bg-white text-[#18181B] border-neutral-200 dark:bg-[#050505] dark:text-white dark:border-white/10",
          className
        )}
      >
        <div className="flex h-full flex-col items-center py-3 bg-[#F7F7F7] dark:bg-[#080808]">
          {/* Expand sidebar button (top) */}
          <button
            type="button"
            title="Expand sidebar"
            aria-label="Expand sidebar"
            onClick={handleSidebarCollapseToggle}
            className={cn(
              "mb-3 flex h-[38px] w-[38px] items-center justify-center rounded-[10px] transition-all cursor-pointer",
              "text-neutral-500 hover:text-neutral-900 hover:bg-neutral-200/70 dark:text-white/60 dark:hover:text-white dark:hover:bg-white/[0.08]"
            )}
          >
            <PanelLeftOpen className="h-[18px] w-[18px]" strokeWidth={1.75} />
          </button>

          {/* Section shortcuts on Rail */}
          <div className="flex flex-col items-center gap-1.5 w-full px-2">
            {RAIL_SECTIONS.map((section) => {
              const Icon = section.icon;
              const isSectionActive = selectedSection === section.id;

              return (
                <button
                  key={section.id}
                  type="button"
                  title={section.label}
                  aria-label={section.label}
                  aria-current={isSectionActive}
                  onClick={() => handleRailSelect(section.id)}
                  className={cn(
                    "flex h-[40px] w-[40px] items-center justify-center rounded-[10px] transition-all duration-150 cursor-pointer",
                    isSectionActive
                      ? "bg-neutral-200 text-neutral-950 ring-1 ring-neutral-300 font-medium dark:bg-white/[0.12] dark:text-white dark:ring-white/15 dark:shadow-xs"
                      : "text-neutral-500 hover:text-neutral-900 hover:bg-neutral-200/60 dark:text-white/50 dark:hover:text-white dark:hover:bg-white/[0.07]"
                  )}
                >
                  <Icon className="h-[18px] w-[18px]" strokeWidth={1.7} />
                </button>
              );
            })}
          </div>

          {/* Bottom Settings & Account */}
          <div className="mt-auto flex flex-col items-center gap-1.5 w-full px-2">
            <button
              type="button"
              title="Settings"
              aria-label="Settings"
              aria-current={selectedSection === "settings"}
              onClick={() => handleRailSelect("settings")}
              className={cn(
                "flex h-[40px] w-[40px] items-center justify-center rounded-[10px] transition-all duration-150 cursor-pointer",
                selectedSection === "settings"
                  ? "bg-neutral-200 text-neutral-950 ring-1 ring-neutral-300 font-medium dark:bg-white/[0.12] dark:text-white dark:ring-white/15"
                  : "text-neutral-500 hover:text-neutral-900 hover:bg-neutral-200/60 dark:text-white/50 dark:hover:text-white dark:hover:bg-white/[0.07]"
              )}
            >
              <Settings2 className="h-[18px] w-[18px]" strokeWidth={1.7} />
            </button>

            <button
              type="button"
              onClick={onAccountClick}
              title={user.name ?? "Account / Workspace"}
              aria-label={user.name ?? "Account / Workspace"}
              className={cn(
                "flex h-[38px] w-[38px] items-center justify-center rounded-full border transition-all cursor-pointer",
                "border-neutral-200 bg-neutral-100 text-neutral-700 hover:bg-neutral-200 dark:border-white/15 dark:bg-white/[0.05] dark:text-white/70 dark:hover:text-white dark:hover:bg-white/[0.1]"
              )}
            >
              {user.avatarUrl ? (
                <img
                  src={user.avatarUrl}
                  alt={user.name ?? "Account"}
                  className="h-full w-full rounded-full object-cover"
                />
              ) : (
                <UserRound className="h-[16px] w-[16px]" strokeWidth={1.7} />
              )}
            </button>
          </div>
        </div>
      </aside>
    );
  }

  /* ------------------------------------------------------------------------ */
  /* Expanded Sidebar (Left Rail + Section Navigation Panel)                  */
  /* ------------------------------------------------------------------------ */

  const sectionHeading = currentSectionConfig?.label || (selectedSection === "home" ? "Home" : "Overview");

  return (
    <aside
      style={{ width: `${sidebarWidth}px` }}
      className={cn(
        "relative flex h-full min-h-0 shrink-0 select-none",
        "rounded-[16px] border shadow-2xl transition-all duration-150 overflow-hidden",
        "bg-white text-[#18181B] border-neutral-200 dark:bg-[#050505] dark:text-white dark:border-white/10",
        className
      )}
    >
      <div className="flex h-full w-full min-w-0 overflow-hidden">
        {/* ================================================================== */}
        {/* 1. LEFTMOST ICON RAIL (Section Selector Only)                      */}
        {/* ================================================================== */}
        <div
          className={cn(
            "flex w-[64px] shrink-0 flex-col items-center border-r py-3.5",
            "bg-[#F7F7F7] border-neutral-200 dark:bg-[#080808] dark:border-white/10"
          )}
        >
          {/* Collapse sidebar button (top) */}
          <button
            type="button"
            title="Collapse sidebar"
            aria-label="Collapse sidebar"
            onClick={handleSidebarCollapseToggle}
            className={cn(
              "mb-3.5 flex h-[38px] w-[38px] items-center justify-center rounded-[10px] transition-all cursor-pointer",
              "text-neutral-500 hover:text-neutral-900 hover:bg-neutral-200/70 dark:text-white/60 dark:hover:text-white dark:hover:bg-white/[0.08]"
            )}
          >
            <PanelLeftClose className="h-[18px] w-[18px]" strokeWidth={1.75} />
          </button>

          {/* Section buttons on Rail */}
          <div className="flex flex-col items-center gap-1.5 w-full px-2">
            {RAIL_SECTIONS.map((section) => {
              const Icon = section.icon;
              const isSectionActive = selectedSection === section.id;

              return (
                <button
                  key={section.id}
                  type="button"
                  title={section.label}
                  aria-label={section.label}
                  aria-current={isSectionActive}
                  onClick={() => handleRailSelect(section.id)}
                  className={cn(
                    "flex h-[40px] w-[40px] items-center justify-center rounded-[10px] transition-all duration-150 cursor-pointer",
                    isSectionActive
                      ? "bg-neutral-200 text-neutral-950 ring-1 ring-neutral-300 font-medium dark:bg-white/[0.12] dark:text-white dark:ring-white/15 dark:shadow-xs"
                      : "text-neutral-500 hover:text-neutral-900 hover:bg-neutral-200/60 dark:text-white/50 dark:hover:text-white dark:hover:bg-white/[0.07]"
                  )}
                >
                  <Icon className="h-[18px] w-[18px]" strokeWidth={1.7} />
                </button>
              );
            })}
          </div>

          {/* Bottom Settings & Account */}
          <div className="mt-auto flex flex-col items-center gap-1.5 w-full px-2">
            <button
              type="button"
              title="Settings"
              aria-label="Settings"
              aria-current={selectedSection === "settings"}
              onClick={() => handleRailSelect("settings")}
              className={cn(
                "flex h-[40px] w-[40px] items-center justify-center rounded-[10px] transition-all duration-150 cursor-pointer",
                selectedSection === "settings"
                  ? "bg-neutral-200 text-neutral-950 ring-1 ring-neutral-300 font-medium dark:bg-white/[0.12] dark:text-white dark:ring-white/15"
                  : "text-neutral-500 hover:text-neutral-900 hover:bg-neutral-200/60 dark:text-white/50 dark:hover:text-white dark:hover:bg-white/[0.07]"
              )}
            >
              <Settings2 className="h-[18px] w-[18px]" strokeWidth={1.7} />
            </button>

            <button
              type="button"
              onClick={onAccountClick}
              title={user.name ?? "Account / Workspace"}
              aria-label={user.name ?? "Account / Workspace"}
              className={cn(
                "flex h-[38px] w-[38px] items-center justify-center rounded-full border transition-all cursor-pointer",
                "border-neutral-200 bg-neutral-100 text-neutral-700 hover:bg-neutral-200 dark:border-white/15 dark:bg-white/[0.05] dark:text-white/70 dark:hover:text-white dark:hover:bg-white/[0.1]"
              )}
            >
              {user.avatarUrl ? (
                <img
                  src={user.avatarUrl}
                  alt={user.name ?? "Account"}
                  className="h-full w-full rounded-full object-cover"
                />
              ) : (
                <UserRound className="h-[16px] w-[16px]" strokeWidth={1.7} />
              )}
            </button>
          </div>
        </div>

        {/* ================================================================== */}
        {/* 2. EXPANDED SIDEBAR NAVIGATION PANEL                               */}
        {/* ================================================================== */}
        <div className="flex min-w-0 flex-1 flex-col overflow-hidden bg-white dark:bg-[#050505] text-[#18181B] dark:text-white">
          {/* TOP HEADER: Brand / Workspace row + Section Title (Matching video) */}
          <div className="px-4 pt-3.5 pb-2.5 flex flex-col gap-2 border-b border-neutral-200 dark:border-white/[0.08] bg-white dark:bg-[#050505]">
            {/* Brand / App Title */}
            <div className="flex items-center gap-2 text-neutral-500 dark:text-white/50">
              <div className="h-4 w-4 rounded-[4px] bg-neutral-200 dark:bg-white/[0.1] flex items-center justify-center">
                <div className="h-1.5 w-2 rounded-xs bg-neutral-700 dark:bg-white/70" />
              </div>
              <span className="text-[11px] font-semibold tracking-wider uppercase truncate">
                {workspaceName}
              </span>
            </div>

            {/* Main Section Header with chevron */}
            <div className="flex items-center justify-between">
              <h2 className="text-[16px] font-semibold tracking-tight text-[#18181B] dark:text-white">
                {sectionHeading}
              </h2>
              <ChevronRight className="h-4 w-4 text-neutral-400 dark:text-white/40" />
            </div>

            {/* Search Input Bar (Matching video pill design) */}
            <div className="relative mt-1">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-neutral-400 dark:text-white/40" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search..."
                className={cn(
                  "w-full h-8 pl-8 pr-7 text-[12px] rounded-[7px] border transition-colors outline-none",
                  "bg-neutral-100 border-neutral-200 text-neutral-900 placeholder:text-neutral-400 focus:bg-white focus:border-neutral-400",
                  "dark:bg-white/[0.03] dark:border-white/10 dark:text-white/90 dark:placeholder:text-white/35 dark:focus:border-white/25 dark:focus:bg-white/[0.06]"
                )}
              />
              {query && (
                <button
                  type="button"
                  onClick={() => setQuery("")}
                  className="absolute right-2 top-1/2 -translate-y-1/2 p-0.5 text-neutral-400 hover:text-neutral-700 dark:text-white/40 dark:hover:text-white cursor-pointer"
                >
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>
          </div>

          {/* SCROLLABLE NAVIGATION CONTENT */}
          <div className="flex-1 overflow-y-auto px-3 py-3 space-y-4 bg-white dark:bg-[#050505]">
            {/* ============================================================== */}
            {/* VIEW 1: HOME (Favorites + Recents + All Navigation inside Home)*/}
            {/* ============================================================== */}
            {selectedSection === "home" && (
              <>
                {/* FAVORITES (Collapsible) */}
                {!query.trim() && (
                  <section className="space-y-1">
                    <div
                      onClick={() => setFavoritesOpen((prev) => !prev)}
                      className="flex items-center justify-between px-2 py-1.5 rounded-[6px] hover:bg-neutral-100 dark:hover:bg-white/[0.04] text-[11px] font-semibold tracking-wider text-neutral-500 dark:text-white/45 uppercase cursor-pointer select-none transition-colors"
                    >
                      <div className="flex items-center gap-1.5">
                        <Star className="h-3 w-3 text-amber-500 fill-amber-500" />
                        <span>Favorites</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-amber-500/15 text-amber-600 dark:text-amber-400 font-medium">
                          {pinnedItems.length}
                        </span>
                      </div>

                      <button
                        type="button"
                        aria-label={favoritesOpen ? "Collapse Favorites" : "Expand Favorites"}
                        onClick={(e) => {
                          e.stopPropagation();
                          setFavoritesOpen((prev) => !prev);
                        }}
                        className="p-0.5 text-neutral-400 hover:text-neutral-800 dark:text-white/40 dark:hover:text-white transition-colors cursor-pointer"
                      >
                        {favoritesOpen ? (
                          <ChevronUp className="h-3.5 w-3.5" strokeWidth={1.75} />
                        ) : (
                          <ChevronDown className="h-3.5 w-3.5" strokeWidth={1.75} />
                        )}
                      </button>
                    </div>

                    {favoritesOpen && (
                      <div className="space-y-0.5">
                        {pinnedItems.length === 0 ? (
                          <p className="px-3 py-1.5 text-[11px] text-neutral-400 dark:text-white/35 italic">
                            No pinned pages
                          </p>
                        ) : (
                          pinnedItems.map((item) => {
                            const ItemIcon = item.icon;
                            const active = activeItemId === item.id;

                            return (
                              <div
                                key={`fav-${item.id}`}
                                onClick={() => onNavigate?.(item.path)}
                                className={cn(
                                  "group/fav flex min-h-[34px] w-full items-center justify-between rounded-[7px] px-2.5",
                                  "transition-all duration-150 cursor-pointer text-[13px]",
                                  active
                                    ? "bg-neutral-100 text-neutral-950 font-medium ring-1 ring-neutral-200 dark:bg-white/[0.12] dark:text-white dark:ring-white/10 dark:shadow-xs"
                                    : "text-neutral-700 hover:text-neutral-950 hover:bg-neutral-100 dark:text-white/70 dark:hover:text-white dark:hover:bg-white/[0.05]"
                                )}
                              >
                                <div className="flex items-center gap-2.5 min-w-0 flex-1">
                                  {ItemIcon && (
                                    <ItemIcon
                                      className={cn(
                                        "h-3.5 w-3.5 shrink-0",
                                        active
                                          ? "text-neutral-900 dark:text-white"
                                          : "text-neutral-500 dark:text-white/50"
                                      )}
                                      strokeWidth={1.7}
                                    />
                                  )}
                                  <span className="truncate">{item.label}</span>
                                </div>

                                <button
                                  type="button"
                                  title={`Unpin ${item.label}`}
                                  aria-label={`Unpin ${item.label}`}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    togglePin(item.id);
                                  }}
                                  className="opacity-70 group-hover/fav:opacity-100 p-1 text-amber-500 hover:text-amber-600 dark:hover:text-amber-400 transition-all cursor-pointer"
                                >
                                  <Pin className="h-3 w-3 fill-amber-500 stroke-amber-500" />
                                </button>
                              </div>
                            );
                          })
                        )}
                      </div>
                    )}
                  </section>
                )}

                {/* RECENTS (Collapsible, strictly NO timestamps/metadata) */}
                {!query.trim() && (
                  <section className="space-y-1">
                    <div
                      onClick={() => setRecentsOpen((prev) => !prev)}
                      className="flex items-center justify-between px-2 py-1.5 rounded-[6px] hover:bg-neutral-100 dark:hover:bg-white/[0.04] text-[11px] font-semibold tracking-wider text-neutral-500 dark:text-white/45 uppercase cursor-pointer select-none transition-colors"
                    >
                      <div className="flex items-center gap-1.5">
                        <History className="h-3 w-3 text-[#2F6FED]" />
                        <span>Recents</span>
                        {recentItems.length > 0 && (
                          <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-blue-500/15 text-blue-600 dark:text-blue-400 font-medium">
                            {recentItems.length}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-1.5">
                        {recentItems.length > 0 && (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              clearRecents();
                            }}
                            className="text-[10px] font-normal lowercase tracking-normal text-neutral-400 hover:text-red-500 dark:text-white/40 dark:hover:text-red-400 transition-colors px-1 cursor-pointer"
                          >
                            clear
                          </button>
                        )}
                        <button
                          type="button"
                          aria-label={recentsOpen ? "Collapse Recents" : "Expand Recents"}
                          onClick={(e) => {
                            e.stopPropagation();
                            setRecentsOpen((prev) => !prev);
                          }}
                          className="p-0.5 text-neutral-400 hover:text-neutral-800 dark:text-white/40 dark:hover:text-white transition-colors cursor-pointer"
                        >
                          {recentsOpen ? (
                            <ChevronUp className="h-3.5 w-3.5" strokeWidth={1.75} />
                          ) : (
                            <ChevronDown className="h-3.5 w-3.5" strokeWidth={1.75} />
                          )}
                        </button>
                      </div>
                    </div>

                    {recentsOpen && (
                      <div className="space-y-0.5">
                        {recentItems.length === 0 ? (
                          <p className="px-3 py-1.5 text-[11px] text-neutral-400 dark:text-white/35 italic">
                            No recently visited pages.
                          </p>
                        ) : (
                          recentItems.map((item) => {
                            const ItemIcon = item.icon;
                            const active = activeItemId === item.id;
                            const pinned = isPinned(item.id);

                            return (
                              <div
                                key={`recent-${item.id}`}
                                onClick={() => onNavigate?.(item.path)}
                                className={cn(
                                  "group/rec flex min-h-[34px] w-full items-center justify-between rounded-[7px] px-2.5",
                                  "transition-all duration-150 cursor-pointer text-[13px]",
                                  active
                                    ? "bg-neutral-100 text-neutral-950 font-medium ring-1 ring-neutral-200 dark:bg-white/[0.12] dark:text-white dark:ring-white/10 dark:shadow-xs"
                                    : "text-neutral-700 hover:text-neutral-950 hover:bg-neutral-100 dark:text-white/70 dark:hover:text-white dark:hover:bg-white/[0.05]"
                                )}
                              >
                                <div className="flex items-center gap-2.5 min-w-0 flex-1">
                                  {ItemIcon && (
                                    <ItemIcon
                                      className={cn(
                                        "h-3.5 w-3.5 shrink-0",
                                        active
                                          ? "text-neutral-900 dark:text-white"
                                          : "text-neutral-500 dark:text-white/50"
                                      )}
                                      strokeWidth={1.7}
                                    />
                                  )}
                                  <span className="truncate">{item.label}</span>
                                </div>

                                <button
                                  type="button"
                                  title={pinned ? `Unpin ${item.label}` : `Pin ${item.label}`}
                                  aria-label={pinned ? `Unpin ${item.label}` : `Pin ${item.label}`}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    togglePin(item.id);
                                  }}
                                  className={cn(
                                    "p-1 rounded transition-all cursor-pointer",
                                    pinned
                                      ? "opacity-100 text-amber-500"
                                      : "opacity-0 group-hover/rec:opacity-100 text-neutral-400 hover:text-amber-500 dark:text-white/40 dark:hover:text-amber-400"
                                  )}
                                >
                                  <Pin
                                    className={cn(
                                      "h-3 w-3",
                                      pinned ? "fill-amber-500 stroke-amber-500" : "stroke-current"
                                    )}
                                  />
                                </button>
                              </div>
                            );
                          })
                        )}
                      </div>
                    )}
                  </section>
                )}

                {/* ALL NAVIGATION (Inside Home) */}
                <section className="space-y-1 pt-1">
                  <div
                    onClick={() => setAllNavOpen((prev) => !prev)}
                    className="flex items-center justify-between px-2 py-1.5 rounded-[6px] hover:bg-neutral-100 dark:hover:bg-white/[0.04] text-[11px] font-semibold tracking-wider text-neutral-500 dark:text-white/45 uppercase cursor-pointer select-none transition-colors"
                  >
                    <span>All Navigation</span>
                    <button
                      type="button"
                      aria-label={allNavOpen ? "Collapse All Navigation" : "Expand All Navigation"}
                      onClick={(e) => {
                        e.stopPropagation();
                        setAllNavOpen((prev) => !prev);
                      }}
                      className="p-0.5 text-neutral-400 hover:text-neutral-800 dark:text-white/40 dark:hover:text-white transition-colors cursor-pointer"
                    >
                      {allNavOpen ? (
                        <ChevronUp className="h-3.5 w-3.5" strokeWidth={1.75} />
                      ) : (
                        <ChevronDown className="h-3.5 w-3.5" strokeWidth={1.75} />
                      )}
                    </button>
                  </div>

                  {allNavOpen && (
                    <div className="space-y-1">
                      {filteredAllSections.map((section) => {
                        const Icon = section.icon;
                        const open = openSections[section.id];

                        return (
                          <div key={`all-${section.id}`} className="space-y-0.5">
                            {/* Section header accordion row */}
                            <button
                              type="button"
                              onClick={() => toggleSection(section.id)}
                              aria-expanded={open}
                              className={cn(
                                "flex min-h-[34px] w-full items-center justify-between rounded-[7px] px-2.5 text-left transition-colors cursor-pointer",
                                "text-[13px] font-medium text-neutral-800 hover:text-neutral-950 hover:bg-neutral-100 dark:text-white/85 dark:hover:text-white dark:hover:bg-white/[0.05]"
                              )}
                            >
                              <div className="flex items-center gap-2.5 min-w-0">
                                <Icon className="h-3.5 w-3.5 text-neutral-500 dark:text-white/50 shrink-0" strokeWidth={1.7} />
                                <span className="truncate">{section.label}</span>
                              </div>

                              {open ? (
                                <ChevronUp className="h-3.5 w-3.5 text-neutral-400 dark:text-white/40 shrink-0" strokeWidth={1.75} />
                              ) : (
                                <ChevronDown className="h-3.5 w-3.5 text-neutral-400 dark:text-white/40 shrink-0" strokeWidth={1.75} />
                              )}
                            </button>

                            {/* Section child items indented underneath */}
                            {open && (
                              <div className="pl-6 space-y-0.5">
                                {section.items.map((item) => {
                                  const active = activeItemId === item.id;
                                  const pinned = isPinned(item.id);

                                  return (
                                    <div
                                      key={item.id}
                                      onClick={() => onNavigate?.(item.path)}
                                      className={cn(
                                        "group/sub flex min-h-[32px] w-full items-center justify-between rounded-[7px] px-2.5",
                                        "transition-all duration-150 cursor-pointer text-[13px]",
                                        active
                                          ? "bg-neutral-100 text-neutral-950 font-medium ring-1 ring-neutral-200 dark:bg-white/[0.12] dark:text-white dark:ring-white/10 dark:shadow-xs"
                                          : "text-neutral-600 hover:text-neutral-900 hover:bg-neutral-100 dark:text-white/70 dark:hover:text-white dark:hover:bg-white/[0.05]"
                                      )}
                                    >
                                      <span className="truncate">{item.label}</span>

                                      <button
                                        type="button"
                                        title={pinned ? `Unpin ${item.label}` : `Pin ${item.label}`}
                                        aria-label={pinned ? `Unpin ${item.label}` : `Pin ${item.label}`}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          togglePin(item.id);
                                        }}
                                        className={cn(
                                          "p-1 rounded transition-all cursor-pointer",
                                          pinned
                                            ? "opacity-100 text-amber-500"
                                            : "opacity-0 group-hover/sub:opacity-100 text-neutral-400 hover:text-amber-500 dark:text-white/40 dark:hover:text-amber-400"
                                        )}
                                      >
                                        <Pin
                                          className={cn(
                                            "h-3 w-3",
                                            pinned ? "fill-amber-500 stroke-amber-500" : "stroke-current"
                                          )}
                                        />
                                      </button>
                                    </div>
                                  );
                                })}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </section>
              </>
            )}

            {/* ============================================================== */}
            {/* VIEW 2: SPECIFIC SECTION (Overview, Analytics, Investigate...) */}
            {/* ============================================================== */}
            {selectedSection !== "home" && currentSectionConfig && (
              <div className="space-y-1">
                {/* Category label */}
                <div className="px-2 pt-1 pb-1 text-[11px] font-semibold tracking-wider text-neutral-500 dark:text-white/45 uppercase">
                  {currentSectionConfig.label}
                </div>

                {/* Direct child items list */}
                <div className="space-y-0.5">
                  {currentSectionConfig.items
                    .filter((item) => {
                      if (!query.trim()) return true;
                      return item.label.toLowerCase().includes(query.toLowerCase());
                    })
                    .map((item) => {
                      const ItemIcon = item.icon;
                      const active = activeItemId === item.id;
                      const pinned = isPinned(item.id);

                      return (
                        <div
                          key={item.id}
                          onClick={() => onNavigate?.(item.path)}
                          className={cn(
                            "group/item flex min-h-[36px] w-full items-center justify-between rounded-[7px] px-2.5",
                            "transition-all duration-150 cursor-pointer text-[13px]",
                            active
                              ? "bg-neutral-100 text-neutral-950 font-medium ring-1 ring-neutral-200 dark:bg-white/[0.12] dark:text-white dark:ring-white/10 dark:shadow-xs"
                              : "text-neutral-700 hover:text-neutral-950 hover:bg-neutral-100 dark:text-white/75 dark:hover:text-white dark:hover:bg-white/[0.05]"
                          )}
                        >
                          <div className="flex items-center gap-2.5 min-w-0 flex-1">
                            {ItemIcon && (
                              <ItemIcon
                                className={cn(
                                  "h-3.5 w-3.5 shrink-0",
                                  active
                                    ? "text-neutral-950 dark:text-white"
                                    : "text-neutral-500 dark:text-white/50"
                                )}
                                strokeWidth={1.7}
                              />
                            )}
                            <span className="truncate">{item.label}</span>
                          </div>

                          <button
                            type="button"
                            title={pinned ? `Unpin ${item.label}` : `Pin ${item.label}`}
                            aria-label={pinned ? `Unpin ${item.label}` : `Pin ${item.label}`}
                            onClick={(e) => {
                              e.stopPropagation();
                              togglePin(item.id);
                            }}
                            className={cn(
                              "p-1 rounded transition-all cursor-pointer",
                              pinned
                                ? "opacity-100 text-amber-500"
                                : "opacity-0 group-hover/item:opacity-100 text-neutral-400 hover:text-amber-500 dark:text-white/40 dark:hover:text-amber-400"
                            )}
                          >
                            <Pin
                              className={cn(
                                "h-3 w-3",
                                pinned ? "fill-amber-500 stroke-amber-500" : "stroke-current"
                              )}
                            />
                          </button>
                        </div>
                      );
                    })}
                </div>
              </div>
            )}
          </div>

          {/* ================================================================ */}
          {/* 3. SIDEBAR FOOTER: User Account Bar (Matching video footer row)  */}
          {/* ================================================================ */}
          <div className="mt-auto border-t border-neutral-200 dark:border-white/[0.08] px-3 py-2.5 flex items-center justify-between bg-white dark:bg-[#050505]">
            <button
              type="button"
              onClick={onAccountClick}
              className="flex items-center gap-2.5 min-w-0 flex-1 text-left hover:opacity-80 transition-opacity cursor-pointer"
            >
              <div className="h-7 w-7 rounded-full bg-neutral-100 border border-neutral-200 dark:bg-white/[0.08] dark:border-white/15 flex items-center justify-center shrink-0">
                {user.avatarUrl ? (
                  <img
                    src={user.avatarUrl}
                    alt={user.name ?? "User"}
                    className="h-full w-full rounded-full object-cover"
                  />
                ) : (
                  <UserRound className="h-3.5 w-3.5 text-neutral-700 dark:text-white/80" strokeWidth={1.7} />
                )}
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-[13px] font-medium text-neutral-900 dark:text-white/90 truncate leading-tight">
                  {user.name || "Security Operator"}
                </p>
                {user.subtitle && (
                  <p className="text-[11px] text-neutral-500 dark:text-white/40 truncate leading-tight">
                    {user.subtitle}
                  </p>
                )}
              </div>
            </button>

            <button
              type="button"
              onClick={onAccountClick}
              title="Account Options"
              aria-label="Account Options"
              className="p-1 text-neutral-400 hover:text-neutral-800 dark:text-white/40 dark:hover:text-white transition-colors cursor-pointer"
            >
              <MoreHorizontal className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {/* DRAGGABLE RESIZE HANDLE */}
      <div
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerCancel={handlePointerCancel}
        onDoubleClick={handleDoubleClick}
        title="Drag to resize sidebar (double-click to reset)"
        className="group/resize absolute -right-1 top-0 bottom-0 z-50 w-2.5 cursor-col-resize touch-none flex items-center justify-center"
      >
        <div
          className={cn(
            "h-8 w-1 rounded-full transition-all duration-150",
            isDragging
              ? "bg-[#2F6FED] scale-y-125 w-1.5 opacity-100"
              : "bg-neutral-300 dark:bg-white/20 opacity-0 group-hover/resize:opacity-100 group-hover/resize:bg-[#2F6FED]"
          )}
        />
      </div>
    </aside>
  );
}
