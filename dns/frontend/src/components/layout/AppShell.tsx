"use client";

import React, { useState, useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { AppSidebar } from "@/components/layout/AppSidebar";
import { ControlTopBar } from "@/components/layout/ControlTopBar";
import { GlobalSearchDialog } from "./GlobalSearchDialog";
import { useAuth } from "@/context/AuthContext";
import {
  findNavItemById,
  getActiveNavItemId,
  getActiveSectionId,
  MAIN_NAV_SECTIONS,
  recordRecentVisit,
} from "@/lib/navigation";

export const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [searchOpen, setSearchOpen] = useState(false);
  const pathname = usePathname() || "";
  const router = useRouter();
  const { user } = useAuth();

  const activeItemId = getActiveNavItemId(pathname, "");
  const activeSectionId = getActiveSectionId(pathname);

  // Track recent page visits
  useEffect(() => {
    if (activeItemId && activeItemId !== "home") {
      recordRecentVisit(activeItemId);
    }
  }, [activeItemId]);

  return (
    <div className="flex h-screen w-full overflow-hidden bg-[#FAFAFA] dark:bg-[#07090E] text-[#1A1A1A] dark:text-[#F3F4F6] p-2 gap-2">
      {/* 1. Dual-Pane Rail Sidebar */}
      <AppSidebar
        workspaceName="DNS THREAT DETECTION"
        activeItemId={activeItemId}
        activeSectionId={activeSectionId}
        user={{
          name: user?.name || user?.email?.split("@")[0] || "Security Operator",
          subtitle: user?.email || "admin@soc.local",
        }}
        onNavigate={(dest) => {
          if (dest.startsWith("/")) {
            router.push(dest);
            return;
          }
          const item = findNavItemById(dest);
          if (item) {
            router.push(item.path);
            return;
          }
          const section = MAIN_NAV_SECTIONS.find((s) => s.id === dest);
          if (section?.path) {
            router.push(section.path);
            return;
          }
          if (dest === "home") {
            router.push("/home");
            return;
          }
          if (dest === "overview") {
            router.push("/overview");
            return;
          }
          if (dest === "settings") {
            router.push("/settings");
            return;
          }
          router.push(`/${dest}`);
        }}
        onSearch={() => {
          setSearchOpen(true);
        }}
        onAccountClick={() => {
          router.push("/settings");
        }}
        className="shrink-0 h-full"
      />

      {/* 2. Main Inset Container */}
      <div className="flex flex-col min-w-0 flex-1 h-full overflow-hidden rounded-[16px] border border-[#EBEBEB] dark:border-white/10 bg-white dark:bg-[#0C0F17] shadow-xl">
        {/* Top Bar (56px) */}
        <ControlTopBar onOpenSearch={() => setSearchOpen(true)} />

        {/* Main Content Area */}
        <main className="flex-1 overflow-y-auto px-8 py-6">
          <div className="max-w-[2100px] mx-auto w-full">
            {children}
          </div>
        </main>
      </div>

      {/* 3. Global ⌘K Command Dialog */}
      <GlobalSearchDialog open={searchOpen} onOpenChange={setSearchOpen} />
    </div>
  );
};

export default AppShell;
