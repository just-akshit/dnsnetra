"use client";

import React, { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/context/AuthContext";
import AppShell from "@/components/layout/AppShell";
import { TimeRangeProvider } from "@/context/TimeRangeContext";
import { FilterProvider } from "@/context/FilterContext";

function DashboardGuard({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) {
      router.replace("/login");
    }
  }, [user, loading, router]);

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center text-xs text-muted-foreground bg-background">
        <div className="flex items-center gap-2">
          <div className="w-3.5 h-3.5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          <span>Loading...</span>
        </div>
      </div>
    );
  }

  if (!user) {
    // Still loading or redirecting
    return (
      <div className="flex h-screen items-center justify-center text-xs text-muted-foreground bg-background">
        <div className="flex items-center gap-2">
          <div className="w-3.5 h-3.5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          <span>Redirecting...</span>
        </div>
      </div>
    );
  }

  return (
    <TimeRangeProvider>
      <FilterProvider>
        <AppShell>{children}</AppShell>
      </FilterProvider>
    </TimeRangeProvider>
  );
}

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <DashboardGuard>{children}</DashboardGuard>;
}
