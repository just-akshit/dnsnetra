import React, { useState, useEffect, useCallback } from "react";
import {
  LayoutDashboard,
  Waves,
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
  UserRound,
  SlidersHorizontal,
  CircleGauge,
} from "lucide-react";

export interface NavItemConfig {
  id: string;
  label: string;
  path: string;
  sectionId: string;
  sectionLabel: string;
  icon: React.ComponentType<{ className?: string; strokeWidth?: number }>;
}

export interface NavSectionConfig {
  id: string;
  label: string;
  path: string;
  icon: React.ComponentType<{ className?: string; strokeWidth?: number }>;
  defaultOpen?: boolean;
  items: NavItemConfig[];
}

export const MAIN_NAV_SECTIONS: NavSectionConfig[] = [
  {
    id: "overview",
    label: "Home",
    path: "/overview",
    icon: LayoutDashboard,
    defaultOpen: true,
    items: [
      {
        id: "dashboard",
        label: "Overview Dashboard",
        path: "/overview",
        sectionId: "overview",
        sectionLabel: "Home",
        icon: LayoutDashboard,
      },
    ],
  },
  {
    id: "analytics",
    label: "Analytics",
    path: "/analytics",
    icon: Activity,
    defaultOpen: true,
    items: [
      {
        id: "threat-analytics",
        label: "Threat Analytics",
        path: "/analytics/threats",
        sectionId: "analytics",
        sectionLabel: "Analytics",
        icon: Shield,
      },
    ],
  },
  {
    id: "investigate",
    label: "Investigate",
    path: "/investigate",
    icon: FileSearch,
    defaultOpen: true,
    items: [
      {
        id: "investigate-domains",
        label: "Domains",
        path: "/investigate/domains",
        sectionId: "investigate",
        sectionLabel: "Investigate",
        icon: Globe2,
      },
      {
        id: "investigate-clients",
        label: "Clients",
        path: "/investigate/clients",
        sectionId: "investigate",
        sectionLabel: "Investigate",
        icon: UsersRound,
      },
      {
        id: "investigate-queries",
        label: "Queries",
        path: "/investigate/queries",
        sectionId: "investigate",
        sectionLabel: "Investigate",
        icon: FileSearch,
      },
    ],
  },
  {
    id: "operations",
    label: "Operations",
    path: "/operations",
    icon: Bell,
    defaultOpen: true,
    items: [
      {
        id: "alerts",
        label: "Alerts",
        path: "/operations/alerts",
        sectionId: "operations",
        sectionLabel: "Operations",
        icon: Bell,
      },
      {
        id: "cases",
        label: "Cases",
        path: "/operations/cases",
        sectionId: "operations",
        sectionLabel: "Operations",
        icon: ListFilter,
      },
    ],
  },
  {
    id: "reports",
    label: "Reports",
    path: "/reports",
    icon: FileBarChart,
    defaultOpen: true,
    items: [
      {
        id: "reports-overview",
        label: "Reports",
        path: "/reports",
        sectionId: "reports",
        sectionLabel: "Reports",
        icon: FileBarChart,
      },
    ],
  },
];

export const SETTINGS_SECTION: NavSectionConfig = {
  id: "settings",
  label: "Settings",
  path: "/settings",
  icon: Settings2,
  defaultOpen: true,
  items: [
    { id: "profile", label: "Profile", path: "/settings", sectionId: "settings", sectionLabel: "Settings", icon: UserRound },
    { id: "preferences", label: "Preferences", path: "/settings?tab=preferences", sectionId: "settings", sectionLabel: "Settings", icon: SlidersHorizontal },
    { id: "notifications", label: "Notifications", path: "/settings?tab=notifications", sectionId: "settings", sectionLabel: "Settings", icon: Bell },
    { id: "detection-rules", label: "Detection Rules", path: "/settings?tab=detection-rules", sectionId: "settings", sectionLabel: "Settings", icon: ListFilter },
    { id: "risk-scoring", label: "Risk Scoring", path: "/settings?tab=risk-scoring", sectionId: "settings", sectionLabel: "Settings", icon: CircleGauge },
    { id: "allowlist-denylist", label: "Allowlist / Denylist", path: "/settings?tab=allowlist-denylist", sectionId: "settings", sectionLabel: "Settings", icon: Shield },
    { id: "intelligence-sources", label: "Intelligence Sources", path: "/settings?tab=intelligence-sources", sectionId: "settings", sectionLabel: "Settings", icon: Database },
    { id: "lookup-configuration", label: "Lookup Configuration", path: "/settings?tab=lookup-configuration", sectionId: "settings", sectionLabel: "Settings", icon: SlidersHorizontal },
    { id: "alert-policies", label: "Alert Policies", path: "/settings?tab=alert-policies", sectionId: "settings", sectionLabel: "Settings", icon: Bell },
    { id: "report-preferences", label: "Report Preferences", path: "/settings?tab=report-preferences", sectionId: "settings", sectionLabel: "Settings", icon: FileBarChart },
    { id: "data-retention", label: "Data Retention", path: "/settings?tab=data-retention", sectionId: "settings", sectionLabel: "Settings", icon: Database },
  ],
};

const ALL_ITEMS = [
  ...MAIN_NAV_SECTIONS.flatMap((s) => s.items),
  ...SETTINGS_SECTION.items,
];

export function findNavItemById(id: string): NavItemConfig | undefined {
  return ALL_ITEMS.find((item) => item.id === id);
}

export function findNavItemByPath(path: string): NavItemConfig | undefined {
  return ALL_ITEMS.find((item) => item.path === path);
}

export function getActiveSectionId(pathname: string): string {
  if (pathname === "/home" || pathname.startsWith("/home")) {
    return "overview";
  }
  if (pathname === "/" || pathname === "/overview" || pathname.startsWith("/overview")) {
    return "overview";
  }
  if (pathname.startsWith("/analytics") || pathname === "/dns" || pathname === "/threats") {
    return "analytics";
  }
  if (pathname.startsWith("/investigate") || pathname.startsWith("/domains") || pathname.startsWith("/clients")) {
    return "investigate";
  }
  if (pathname.startsWith("/operations")) {
    return "operations";
  }
  if (pathname.startsWith("/reports")) {
    return "reports";
  }
  if (pathname.startsWith("/settings") || pathname === "/system") {
    return "settings";
  }
  return "overview";
}

export function getActiveNavItemId(pathname: string, search?: string): string {
  if (pathname === "/home" || pathname.startsWith("/home")) {
    return "dashboard";
  }
  if (pathname === "/" || pathname === "/overview" || pathname.startsWith("/overview")) {
    return "dashboard";
  }
  if (pathname === "/analytics/threats" || pathname === "/threats" || pathname === "/analytics") {
    return "threat-analytics";
  }
  if (pathname.startsWith("/investigate/domains") || pathname.startsWith("/domains")) {
    return "investigate-domains";
  }
  if (pathname.startsWith("/investigate/clients") || pathname.startsWith("/clients")) {
    return "investigate-clients";
  }
  if (pathname.startsWith("/investigate/queries")) {
    return "investigate-queries";
  }
  if (pathname === "/investigate") {
    return "investigate-domains";
  }
  if (pathname.startsWith("/operations/cases")) {
    return "cases";
  }
  if (pathname.startsWith("/operations")) {
    return "alerts";
  }
  if (pathname.startsWith("/reports")) {
    return "reports-overview";
  }
  if (pathname.startsWith("/settings") || pathname === "/system") {
    if (search && search.includes("tab=")) {
      const match = search.match(/tab=([^&]+)/);
      if (match && match[1]) {
        const tabItem = SETTINGS_SECTION.items.find(
          (item) => item.path.includes(`tab=${match[1]}`) || item.id === match[1]
        );
        if (tabItem) return tabItem.id;
      }
    }
    return "profile";
  }
  return "dashboard";
}

/* -------------------------------------------------------------------------- */
/* Favorites / Pinned Pages Management                                        */
/* -------------------------------------------------------------------------- */

export const PINNED_PAGES_STORAGE_KEY = "dns-threat-detection:pinned-pages";
export const LEGACY_PINNED_PAGES_STORAGE_KEY = "dns-threat-detection-pinned-pages";
export const PINNED_PAGES_EVENT = "dns-pinned-pages-changed";

export function getStoredPinnedIds(): string[] {
  if (typeof window === "undefined") return [];
  try {
    let raw = localStorage.getItem(PINNED_PAGES_STORAGE_KEY);
    if (!raw) {
      raw = localStorage.getItem(LEGACY_PINNED_PAGES_STORAGE_KEY);
    }
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      // Validate IDs against real nav items and deduplicate
      const sanitized = parsed.filter(
        (id, index, self) =>
          typeof id === "string" &&
          Boolean(findNavItemById(id)) &&
          self.indexOf(id) === index
      );
      return sanitized;
    }
    return [];
  } catch {
    return [];
  }
}

export function setStoredPinnedIds(ids: string[]): void {
  if (typeof window === "undefined") return;
  try {
    const sanitized = ids.filter(
      (id, index, self) =>
        typeof id === "string" &&
        Boolean(findNavItemById(id)) &&
        self.indexOf(id) === index
    );
    localStorage.setItem(PINNED_PAGES_STORAGE_KEY, JSON.stringify(sanitized));
    window.dispatchEvent(new Event(PINNED_PAGES_EVENT));
  } catch {
    // ignore
  }
}

export function togglePinnedId(id: string): void {
  if (!id || !findNavItemById(id)) return;
  const current = getStoredPinnedIds();
  const next = current.includes(id)
    ? current.filter((item) => item !== id)
    : [...current, id];
  setStoredPinnedIds(next);
}

export function usePinnedPages() {
  const [pinnedIds, setPinnedIds] = useState<string[]>(getStoredPinnedIds);

  useEffect(() => {
    const handleUpdate = () => {
      setPinnedIds(getStoredPinnedIds());
    };
    window.addEventListener(PINNED_PAGES_EVENT, handleUpdate);
    window.addEventListener("storage", handleUpdate);
    return () => {
      window.removeEventListener(PINNED_PAGES_EVENT, handleUpdate);
      window.removeEventListener("storage", handleUpdate);
    };
  }, []);

  const toggle = useCallback((id: string) => {
    togglePinnedId(id);
  }, []);

  const pinnedItems = React.useMemo(() => {
    return pinnedIds
      .map((id) => findNavItemById(id))
      .filter((item): item is NavItemConfig => Boolean(item));
  }, [pinnedIds]);

  return {
    pinnedIds,
    pinnedItems,
    togglePin: toggle,
    isPinned: useCallback((id: string) => pinnedIds.includes(id), [pinnedIds]),
  };
}

/* -------------------------------------------------------------------------- */
/* Recents / Recently Visited Pages Management                                */
/* -------------------------------------------------------------------------- */

export const RECENT_PAGES_STORAGE_KEY = "dns-threat-detection:recent-pages";
export const LEGACY_RECENT_PAGES_STORAGE_KEY = "dns-threat-detection-recent-pages";
export const RECENT_PAGES_EVENT = "dns-recent-pages-changed";
export const MAX_RECENT_PAGES = 8;

export function getStoredRecentIds(): string[] {
  if (typeof window === "undefined") return [];
  try {
    let raw = localStorage.getItem(RECENT_PAGES_STORAGE_KEY);
    if (!raw) {
      raw = localStorage.getItem(LEGACY_RECENT_PAGES_STORAGE_KEY);
    }
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      const sanitized = parsed
        .filter(
          (id, index, self) =>
            typeof id === "string" &&
            Boolean(findNavItemById(id)) &&
            self.indexOf(id) === index
        )
        .slice(0, MAX_RECENT_PAGES);
      return sanitized;
    }
    return [];
  } catch {
    return [];
  }
}

export function setStoredRecentIds(ids: string[]): void {
  if (typeof window === "undefined") return;
  try {
    const sanitized = ids
      .filter(
        (id, index, self) =>
          typeof id === "string" &&
          Boolean(findNavItemById(id)) &&
          self.indexOf(id) === index
      )
      .slice(0, MAX_RECENT_PAGES);
    localStorage.setItem(RECENT_PAGES_STORAGE_KEY, JSON.stringify(sanitized));
    window.dispatchEvent(new Event(RECENT_PAGES_EVENT));
  } catch {
    // ignore
  }
}

export function recordRecentVisit(id: string): void {
  if (!id || !findNavItemById(id)) return;
  const current = getStoredRecentIds();
  const filtered = current.filter((item) => item !== id);
  const next = [id, ...filtered].slice(0, MAX_RECENT_PAGES);
  setStoredRecentIds(next);
}

export function clearRecentPages(): void {
  setStoredRecentIds([]);
}

export function useRecentPages() {
  const [recentIds, setRecentIds] = useState<string[]>(getStoredRecentIds);

  useEffect(() => {
    const handleUpdate = () => {
      setRecentIds(getStoredRecentIds());
    };
    window.addEventListener(RECENT_PAGES_EVENT, handleUpdate);
    window.addEventListener("storage", handleUpdate);
    return () => {
      window.removeEventListener(RECENT_PAGES_EVENT, handleUpdate);
      window.removeEventListener("storage", handleUpdate);
    };
  }, []);

  const clear = useCallback(() => {
    clearRecentPages();
  }, []);

  const recentItems = React.useMemo(() => {
    return recentIds
      .map((id) => findNavItemById(id))
      .filter((item): item is NavItemConfig => Boolean(item));
  }, [recentIds]);

  return {
    recentIds,
    recentItems,
    clearRecents: clear,
    recordVisit: recordRecentVisit,
  };
}
