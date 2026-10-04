"use client"

import { usePathname } from "next/navigation"

import { Separator } from "@/components/ui/separator"
import { SidebarTrigger } from "@/components/ui/sidebar"
import { ThemeToggle } from "@/components/theme-toggle"
import { GlobalIntelligenceSearch } from "@/components/global-intelligence-search"

const pageTitles: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/reports": "Reports",
  "/clients": "Clients",
  "/domains": "Domains",
  "/queries": "Queries",
  "/domain-intelligence": "Domain Intelligence",
  "/daily-review": "Daily Review",
  "/analytics": "Analytics",
  "/settings": "Settings",
}

function getHeaderTitle(pathname: string): string {
  if (pageTitles[pathname]) return pageTitles[pathname]
  if (pathname.startsWith("/domains/")) return "Domain Profile"
  if (pathname.startsWith("/clients/")) return "Client Profile"
  if (pathname.startsWith("/queries/")) return "Query Telemetry"
  return "DNSNetra"
}

export function SiteHeader() {
  const pathname = usePathname()
  const title = getHeaderTitle(pathname)

  return (
    <header className="flex h-(--header-height) shrink-0 items-center gap-2 border-b transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-(--header-height)">
      <div className="flex w-full items-center gap-2 px-3 sm:px-4 lg:gap-3 lg:px-6">
        <SidebarTrigger className="-ml-1" />
        <Separator
          orientation="vertical"
          className="mx-1 h-4 data-vertical:self-auto hidden sm:block"
        />
        <h1 className="text-sm font-semibold tracking-tight text-foreground truncate shrink-0 sm:text-base">
          {title}
        </h1>

        {/* Global DNSNetra Intelligence Search */}
        <div className="flex-1 flex items-center justify-center max-w-sm md:max-w-md lg:max-w-lg mx-auto px-1 sm:px-2">
          <GlobalIntelligenceSearch />
        </div>

        {/* Existing header controls */}
        <div className="ml-auto flex items-center gap-2 shrink-0">
          <ThemeToggle />
        </div>
      </div>
    </header>
  )
}
