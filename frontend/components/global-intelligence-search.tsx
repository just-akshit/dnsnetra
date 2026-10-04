"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import {
  SearchIcon,
  GlobeIcon,
  UsersIcon,
  TerminalIcon,
  XIcon,
  CornerDownLeftIcon,
  AlertCircleIcon,
  RefreshCwIcon,
  Loader2Icon,
  SearchXIcon,
  ShieldIcon,
  LaptopIcon,
} from "lucide-react"
import {
  dnsnetraApi,
  type DomainItem,
  type ClientItem,
  type QueryItem,
  type GlobalSearchResult,
} from "@/lib/data-table/api-client"
import {
  formatDnsnetraTimestamp,
  formatNumber,
} from "@/lib/data-table/formatters"
import { DataTableStatus } from "@/components/data-table/data-table-status"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
} from "@/components/ui/dialog"
import { cn } from "cn"

export type FlatSearchItem =
  | { type: "domain"; id: string; data: DomainItem }
  | { type: "client"; id: string; data: ClientItem }
  | { type: "query"; id: string; data: QueryItem }

function isIpLike(query: string): boolean {
  const trimmed = query.trim()
  return /^[0-9.:]+$/.test(trimmed) && trimmed.length > 0
}

function useIsMac() {
  return React.useSyncExternalStore(
    () => () => {},
    () =>
      typeof navigator !== "undefined"
        ? /(Mac|iPhone|iPod|iPad)/i.test(navigator.userAgent)
        : false,
    () => false
  )
}

export function GlobalIntelligenceSearch() {
  const router = useRouter()
  const [open, setOpen] = React.useState(false)
  const [query, setQuery] = React.useState("")
  const [loading, setLoading] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [results, setResults] = React.useState<GlobalSearchResult>({
    domains: [],
    clients: [],
    queries: [],
  })
  const [selectedIndex, setSelectedIndex] = React.useState(0)
  const isMac = useIsMac()

  const inputRef = React.useRef<HTMLInputElement | null>(null)
  const activeItemRef = React.useRef<HTMLDivElement | null>(null)

  const handleOpenChange = React.useCallback((nextOpen: boolean) => {
    setOpen(nextOpen)
    if (!nextOpen) {
      setQuery("")
      setResults({ domains: [], clients: [], queries: [] })
      setError(null)
      setSelectedIndex(0)
    }
  }, [])

  // Listen for Global Cmd+K / Ctrl+K keyboard shortcut
  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault()
        handleOpenChange(!open)
      }
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [open, handleOpenChange])

  // Focus input when dialog opens
  React.useEffect(() => {
    if (open) {
      const timer = setTimeout(() => {
        inputRef.current?.focus()
      }, 50)
      return () => clearTimeout(timer)
    }
  }, [open])

  // Debounced search query
  React.useEffect(() => {
    const trimmed = query.trim()
    if (!trimmed) {
      return
    }

    const timeout = setTimeout(async () => {
      try {
        const res = await dnsnetraApi.searchIntelligence(trimmed, 5)
        setResults(res)
        setError(null)
        setSelectedIndex(0)
      } catch {
        setError("Unable to search DNS intelligence. Try again.")
      } finally {
        setLoading(false)
      }
    }, 250)

    return () => clearTimeout(timeout)
  }, [query])

  const handleRetry = React.useCallback(async () => {
    const trimmed = query.trim()
    if (!trimmed) return
    setLoading(true)
    setError(null)
    try {
      const res = await dnsnetraApi.searchIntelligence(trimmed, 5)
      setResults(res)
      setError(null)
      setSelectedIndex(0)
    } catch {
      setError("Unable to search DNS intelligence. Try again.")
    } finally {
      setLoading(false)
    }
  }, [query])

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value
    setQuery(val)
    if (!val.trim()) {
      setResults({ domains: [], clients: [], queries: [] })
      setLoading(false)
      setError(null)
      setSelectedIndex(0)
    } else {
      setLoading(true)
      setError(null)
    }
  }

  const handleClear = () => {
    setQuery("")
    setResults({ domains: [], clients: [], queries: [] })
    setError(null)
    setSelectedIndex(0)
    inputRef.current?.focus()
  }

  // Flatten results according to query heuristic (IP-like shows clients first)
  const isIpQuery = isIpLike(query)
  const flatItems = React.useMemo<FlatSearchItem[]>(() => {
    const items: FlatSearchItem[] = []
    if (isIpQuery) {
      results.clients.forEach((c) =>
        items.push({ type: "client", id: `client-${c.client_ip}`, data: c })
      )
      results.domains.forEach((d) =>
        items.push({ type: "domain", id: `domain-${d.domain}`, data: d })
      )
    } else {
      results.domains.forEach((d) =>
        items.push({ type: "domain", id: `domain-${d.domain}`, data: d })
      )
      results.clients.forEach((c) =>
        items.push({ type: "client", id: `client-${c.client_ip}`, data: c })
      )
    }
    results.queries.forEach((q) =>
      items.push({ type: "query", id: `query-${q.id}`, data: q })
    )
    return items
  }, [results, isIpQuery])

  const safeSelectedIndex =
    flatItems.length > 0
      ? Math.min(Math.max(0, selectedIndex), flatItems.length - 1)
      : 0

  // Scroll active item into view
  React.useEffect(() => {
    if (activeItemRef.current) {
      activeItemRef.current.scrollIntoView({ block: "nearest" })
    }
  }, [safeSelectedIndex])

  // Navigate when selecting a result
  const handleSelect = React.useCallback(
    (item: FlatSearchItem) => {
      handleOpenChange(false)
      switch (item.type) {
        case "domain":
          router.push(`/domains/${encodeURIComponent(item.data.domain)}`)
          break
        case "client":
          router.push(`/clients/${encodeURIComponent(item.data.client_ip)}`)
          break
        case "query":
          router.push(
            `/queries?search=${encodeURIComponent(item.data.domain)}&id=${encodeURIComponent(
              String(item.data.id)
            )}`
          )
          break
      }
    },
    [router, handleOpenChange]
  )

  // Keyboard navigation within the dialog
  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault()
      if (flatItems.length > 0) {
        setSelectedIndex((prev) => (prev + 1) % flatItems.length)
      }
    } else if (e.key === "ArrowUp") {
      e.preventDefault()
      if (flatItems.length > 0) {
        setSelectedIndex((prev) => (prev - 1 + flatItems.length) % flatItems.length)
      }
    } else if (e.key === "Enter") {
      e.preventDefault()
      if (flatItems[safeSelectedIndex]) {
        handleSelect(flatItems[safeSelectedIndex])
      }
    } else if (e.key === "Escape") {
      e.preventDefault()
      handleOpenChange(false)
    }
  }

  const hasResults = flatItems.length > 0
  const hasSearched = query.trim().length > 0 && !loading

  return (
    <>
      {/* 1. Header Trigger Controls */}
      <div className="flex items-center">
        {/* Desktop trigger */}
        <button
          type="button"
          onClick={() => setOpen(true)}
          className={cn(
            "hidden sm:flex items-center justify-between",
            "h-8 w-60 md:w-72 lg:w-84 px-2.5 rounded-md",
            "border border-border/70 bg-muted/30 hover:bg-muted/60 hover:border-border",
            "text-xs text-muted-foreground transition-all duration-150 cursor-pointer select-none",
            "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary"
          )}
          aria-label="Search DNSNetra Intelligence"
        >
          <div className="flex items-center gap-2 truncate">
            <SearchIcon className="size-3.5 shrink-0 text-muted-foreground" />
            <span className="truncate">Search domain, client, query...</span>
          </div>
          <kbd className="pointer-events-none inline-flex h-4.5 select-none items-center gap-0.5 rounded border border-border/80 bg-background/80 px-1.5 font-mono text-[10px] font-medium text-muted-foreground">
            {isMac ? "⌘K" : "Ctrl K"}
          </kbd>
        </button>

        {/* Mobile trigger */}
        <Button
          variant="outline"
          size="icon"
          onClick={() => setOpen(true)}
          className="flex sm:hidden size-8 border-border/70 bg-muted/30 hover:bg-muted/60"
          aria-label="Search DNSNetra Intelligence"
        >
          <SearchIcon className="size-4 text-muted-foreground" />
        </Button>
      </div>

      {/* 2. Global Command Palette Dialog */}
      <Dialog open={open} onOpenChange={handleOpenChange}>
        <DialogContent
          showCloseButton={false}
          className={cn(
            "w-[calc(100vw-2rem)] sm:max-w-2xl max-h-[85vh] p-0 flex flex-col gap-0",
            "border border-border/90 bg-card text-card-foreground shadow-2xl overflow-hidden rounded-lg"
          )}
        >
          {/* Top Search Bar */}
          <div className="relative flex items-center border-b border-border/80 px-3 py-1 bg-muted/20">
            <SearchIcon className="size-4 shrink-0 text-muted-foreground mr-2.5" />
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={handleInputChange}
              onKeyDown={handleKeyDown}
              placeholder="Search domain, client, query..."
              className={cn(
                "h-11 w-full bg-transparent text-sm text-foreground",
                "placeholder:text-muted-foreground focus:outline-none font-sans"
              )}
            />
            {loading && (
              <Loader2Icon className="size-4 shrink-0 animate-spin text-primary mr-2" />
            )}
            {query.length > 0 && !loading && (
              <button
                type="button"
                onClick={handleClear}
                className="p-1 rounded-sm text-muted-foreground hover:text-foreground mr-1.5 cursor-pointer"
                aria-label="Clear search query"
              >
                <XIcon className="size-3.5" />
              </button>
            )}
            <kbd className="hidden sm:inline-flex h-5 select-none items-center rounded border border-border bg-background px-1.5 font-mono text-[10px] font-medium text-muted-foreground">
              ESC
            </kbd>
          </div>

          {/* Body Content Area */}
          <div className="flex-1 overflow-y-auto max-h-[60vh] divide-y divide-border/40">
            {/* Loading State */}
            {loading && !hasResults && (
              <div className="flex flex-col items-center justify-center p-10 text-center gap-2.5">
                <Loader2Icon className="size-5 animate-spin text-primary" />
                <span className="text-xs text-muted-foreground font-mono">
                  Searching DNS intelligence...
                </span>
              </div>
            )}

            {/* Error State */}
            {error && !loading && (
              <div className="flex flex-col items-center justify-center p-8 text-center gap-3">
                <div className="flex size-9 items-center justify-center rounded-full bg-destructive/10 text-destructive">
                  <AlertCircleIcon className="size-4.5" />
                </div>
                <div className="text-xs font-semibold text-destructive">
                  Unable to search DNS intelligence
                </div>
                <p className="text-xs text-muted-foreground">
                  An error occurred while querying backend telemetry feeds.
                </p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleRetry}
                  className="h-7 text-xs gap-1.5"
                >
                  <RefreshCwIcon className="size-3" />
                  Try again
                </Button>
              </div>
            )}

            {/* No Results Empty State */}
            {!loading && !error && hasSearched && !hasResults && (
              <div className="flex flex-col items-center justify-center p-10 text-center">
                <div className="flex size-10 items-center justify-center rounded-full bg-muted/60 text-muted-foreground mb-3">
                  <SearchXIcon className="size-5" />
                </div>
                <div className="text-sm font-semibold text-foreground">
                  No intelligence found
                </div>
                <p className="text-xs text-muted-foreground mt-1 max-w-sm">
                  No domain, client, or query matched{" "}
                  <span className="font-mono text-foreground font-medium">
                    &ldquo;{query}&rdquo;
                  </span>
                </p>
              </div>
            )}

            {/* Idle Initial State */}
            {!loading && !error && query.trim().length === 0 && (
              <div className="p-5 flex flex-col gap-3.5 text-xs text-muted-foreground">
                <div className="flex items-center gap-2 text-foreground font-medium">
                  <ShieldIcon className="size-4 text-primary" />
                  <span>Global DNSNetra SOC Intelligence</span>
                </div>
                <p className="text-xs leading-relaxed text-muted-foreground">
                  Cross-sectional threat detection search across authoritative DNS profiles, monitored client IP endpoints, and event telemetry.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1">
                  <div className="rounded-md border border-border/60 bg-muted/20 p-2.5 flex flex-col gap-1">
                    <span className="font-mono font-medium text-foreground text-[11px] flex items-center gap-1.5">
                      <GlobeIcon className="size-3 text-blue-400" />
                      Domain
                    </span>
                    <span className="text-[11px] text-muted-foreground font-mono truncate">
                      google.com, iclousd.life
                    </span>
                  </div>
                  <div className="rounded-md border border-border/60 bg-muted/20 p-2.5 flex flex-col gap-1">
                    <span className="font-mono font-medium text-foreground text-[11px] flex items-center gap-1.5">
                      <LaptopIcon className="size-3 text-purple-400" />
                      Client IP
                    </span>
                    <span className="text-[11px] text-muted-foreground font-mono truncate">
                      192.168.1.111, 10.0.0.5
                    </span>
                  </div>
                  <div className="rounded-md border border-border/60 bg-muted/20 p-2.5 flex flex-col gap-1">
                    <span className="font-mono font-medium text-foreground text-[11px] flex items-center gap-1.5">
                      <TerminalIcon className="size-3 text-amber-400" />
                      DNS Query
                    </span>
                    <span className="text-[11px] text-muted-foreground font-mono truncate">
                      Telemetry log events
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Categorized Results */}
            {hasResults && (
              <div className="flex flex-col py-1.5">
                {/* 1. DOMAINS GROUP (if not IP-like) */}
                {!isIpQuery && results.domains.length > 0 && (
                  <div className="flex flex-col">
                    <div className="flex items-center justify-between px-3 py-1.5 bg-muted/30 border-y border-border/40 text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                      <span className="flex items-center gap-1.5 font-semibold text-foreground/80">
                        <GlobeIcon className="size-3 text-blue-400" />
                        Domains
                      </span>
                      <span>{results.domains.length} matched</span>
                    </div>
                    <div className="flex flex-col py-1">
                      {results.domains.map((dom) => {
                        const idx = flatItems.findIndex(
                          (it) => it.type === "domain" && it.id === `domain-${dom.domain}`
                        )
                        const isActive = idx === safeSelectedIndex
                        return (
                          <div
                            key={dom.domain}
                            ref={isActive ? activeItemRef : null}
                            onClick={() =>
                              handleSelect({
                                type: "domain",
                                id: `domain-${dom.domain}`,
                                data: dom,
                              })
                            }
                            onMouseEnter={() => setSelectedIndex(idx)}
                            className={cn(
                              "group flex items-center justify-between mx-1.5 px-2.5 py-2 rounded-md cursor-pointer transition-colors text-xs",
                              isActive
                                ? "bg-accent text-accent-foreground"
                                : "hover:bg-muted/40 text-foreground"
                            )}
                          >
                            <div className="flex items-center gap-2.5 min-w-0">
                              <Badge
                                variant="outline"
                                className="font-mono text-[9px] uppercase tracking-wider px-1.5 py-0 bg-blue-500/10 text-blue-400 border-blue-500/20 shrink-0"
                              >
                                DOMAIN
                              </Badge>
                              <div className="flex flex-col min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono font-medium text-foreground truncate text-xs">
                                    {dom.domain}
                                  </span>
                                  {dom.latest_verdict && (
                                    <DataTableStatus
                                      status={dom.latest_verdict}
                                      showIcon={false}
                                      className="text-[10px] py-0 px-1.5 h-4"
                                    />
                                  )}
                                </div>
                                <span className="text-[11px] text-muted-foreground font-sans truncate">
                                  {formatNumber(dom.total_queries)} queries · {formatNumber(dom.unique_clients)} clients · Last seen: {formatDnsnetraTimestamp(dom.last_seen)}
                                </span>
                              </div>
                            </div>

                            {isActive && (
                              <div className="hidden sm:flex items-center gap-1 text-[11px] font-mono text-muted-foreground shrink-0 ml-2">
                                <span>Inspect</span>
                                <CornerDownLeftIcon className="size-3" />
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}

                {/* 2. CLIENTS GROUP */}
                {results.clients.length > 0 && (
                  <div className="flex flex-col">
                    <div className="flex items-center justify-between px-3 py-1.5 bg-muted/30 border-y border-border/40 text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                      <span className="flex items-center gap-1.5 font-semibold text-foreground/80">
                        <UsersIcon className="size-3 text-purple-400" />
                        Clients
                      </span>
                      <span>{results.clients.length} matched</span>
                    </div>
                    <div className="flex flex-col py-1">
                      {results.clients.map((cli) => {
                        const idx = flatItems.findIndex(
                          (it) => it.type === "client" && it.id === `client-${cli.client_ip}`
                        )
                        const isActive = idx === safeSelectedIndex
                        return (
                          <div
                            key={cli.client_ip}
                            ref={isActive ? activeItemRef : null}
                            onClick={() =>
                              handleSelect({
                                type: "client",
                                id: `client-${cli.client_ip}`,
                                data: cli,
                              })
                            }
                            onMouseEnter={() => setSelectedIndex(idx)}
                            className={cn(
                              "group flex items-center justify-between mx-1.5 px-2.5 py-2 rounded-md cursor-pointer transition-colors text-xs",
                              isActive
                                ? "bg-accent text-accent-foreground"
                                : "hover:bg-muted/40 text-foreground"
                            )}
                          >
                            <div className="flex items-center gap-2.5 min-w-0">
                              <Badge
                                variant="outline"
                                className="font-mono text-[9px] uppercase tracking-wider px-1.5 py-0 bg-purple-500/10 text-purple-400 border-purple-500/20 shrink-0"
                              >
                                CLIENT
                              </Badge>
                              <div className="flex flex-col min-w-0">
                                <span className="font-mono font-medium text-foreground truncate text-xs">
                                  {cli.client_ip}
                                </span>
                                <span className="text-[11px] text-muted-foreground font-sans truncate">
                                  {formatNumber(cli.total_queries)} queries · {formatNumber(cli.unique_domains)} domains · Last seen: {formatDnsnetraTimestamp(cli.last_seen)}
                                </span>
                              </div>
                            </div>

                            {isActive && (
                              <div className="hidden sm:flex items-center gap-1 text-[11px] font-mono text-muted-foreground shrink-0 ml-2">
                                <span>Inspect</span>
                                <CornerDownLeftIcon className="size-3" />
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}

                {/* 1B. DOMAINS GROUP (if IP-like was rendered first) */}
                {isIpQuery && results.domains.length > 0 && (
                  <div className="flex flex-col">
                    <div className="flex items-center justify-between px-3 py-1.5 bg-muted/30 border-y border-border/40 text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                      <span className="flex items-center gap-1.5 font-semibold text-foreground/80">
                        <GlobeIcon className="size-3 text-blue-400" />
                        Domains
                      </span>
                      <span>{results.domains.length} matched</span>
                    </div>
                    <div className="flex flex-col py-1">
                      {results.domains.map((dom) => {
                        const idx = flatItems.findIndex(
                          (it) => it.type === "domain" && it.id === `domain-${dom.domain}`
                        )
                        const isActive = idx === safeSelectedIndex
                        return (
                          <div
                            key={dom.domain}
                            ref={isActive ? activeItemRef : null}
                            onClick={() =>
                              handleSelect({
                                type: "domain",
                                id: `domain-${dom.domain}`,
                                data: dom,
                              })
                            }
                            onMouseEnter={() => setSelectedIndex(idx)}
                            className={cn(
                              "group flex items-center justify-between mx-1.5 px-2.5 py-2 rounded-md cursor-pointer transition-colors text-xs",
                              isActive
                                ? "bg-accent text-accent-foreground"
                                : "hover:bg-muted/40 text-foreground"
                            )}
                          >
                            <div className="flex items-center gap-2.5 min-w-0">
                              <Badge
                                variant="outline"
                                className="font-mono text-[9px] uppercase tracking-wider px-1.5 py-0 bg-blue-500/10 text-blue-400 border-blue-500/20 shrink-0"
                              >
                                DOMAIN
                              </Badge>
                              <div className="flex flex-col min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono font-medium text-foreground truncate text-xs">
                                    {dom.domain}
                                  </span>
                                  {dom.latest_verdict && (
                                    <DataTableStatus
                                      status={dom.latest_verdict}
                                      showIcon={false}
                                      className="text-[10px] py-0 px-1.5 h-4"
                                    />
                                  )}
                                </div>
                                <span className="text-[11px] text-muted-foreground font-sans truncate">
                                  {formatNumber(dom.total_queries)} queries · {formatNumber(dom.unique_clients)} clients · Last seen: {formatDnsnetraTimestamp(dom.last_seen)}
                                </span>
                              </div>
                            </div>

                            {isActive && (
                              <div className="hidden sm:flex items-center gap-1 text-[11px] font-mono text-muted-foreground shrink-0 ml-2">
                                <span>Inspect</span>
                                <CornerDownLeftIcon className="size-3" />
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}

                {/* 3. QUERIES GROUP */}
                {results.queries.length > 0 && (
                  <div className="flex flex-col">
                    <div className="flex items-center justify-between px-3 py-1.5 bg-muted/30 border-y border-border/40 text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                      <span className="flex items-center gap-1.5 font-semibold text-foreground/80">
                        <TerminalIcon className="size-3 text-amber-400" />
                        Queries
                      </span>
                      <span>{results.queries.length} matched</span>
                    </div>
                    <div className="flex flex-col py-1">
                      {results.queries.map((qry) => {
                        const idx = flatItems.findIndex(
                          (it) => it.type === "query" && it.id === `query-${qry.id}`
                        )
                        const isActive = idx === safeSelectedIndex
                        return (
                          <div
                            key={qry.id}
                            ref={isActive ? activeItemRef : null}
                            onClick={() =>
                              handleSelect({
                                type: "query",
                                id: `query-${qry.id}`,
                                data: qry,
                              })
                            }
                            onMouseEnter={() => setSelectedIndex(idx)}
                            className={cn(
                              "group flex items-center justify-between mx-1.5 px-2.5 py-2 rounded-md cursor-pointer transition-colors text-xs",
                              isActive
                                ? "bg-accent text-accent-foreground"
                                : "hover:bg-muted/40 text-foreground"
                            )}
                          >
                            <div className="flex items-center gap-2.5 min-w-0">
                              <Badge
                                variant="outline"
                                className="font-mono text-[9px] uppercase tracking-wider px-1.5 py-0 bg-amber-500/10 text-amber-400 border-amber-500/20 shrink-0"
                              >
                                QUERY
                              </Badge>
                              <div className="flex flex-col min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono font-medium text-foreground truncate text-xs">
                                    {qry.domain}
                                  </span>
                                  <Badge
                                    variant="outline"
                                    className="font-mono text-[9px] px-1 py-0 h-3.5 text-muted-foreground"
                                  >
                                    {qry.query_type}
                                  </Badge>
                                  {qry.final_label && (
                                    <DataTableStatus
                                      status={qry.final_label}
                                      showIcon={false}
                                      className="text-[10px] py-0 px-1.5 h-4"
                                    />
                                  )}
                                </div>
                                <span className="text-[11px] text-muted-foreground font-sans truncate">
                                  Client: <span className="font-mono text-foreground/80">{qry.client_ip}</span> · {formatDnsnetraTimestamp(qry.timestamp)}
                                </span>
                              </div>
                            </div>

                            {isActive && (
                              <div className="hidden sm:flex items-center gap-1 text-[11px] font-mono text-muted-foreground shrink-0 ml-2">
                                <span>Inspect</span>
                                <CornerDownLeftIcon className="size-3" />
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Footer Bar with Keyboard Shortcuts */}
          <div className="flex items-center justify-between px-3.5 py-2 border-t border-border/80 bg-muted/20 text-[11px] text-muted-foreground select-none">
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1">
                <kbd className="font-mono text-[9px] px-1 py-0.5 rounded bg-background border border-border">↑</kbd>
                <kbd className="font-mono text-[9px] px-1 py-0.5 rounded bg-background border border-border">↓</kbd>
                <span className="hidden sm:inline">Navigate</span>
              </span>
              <span className="flex items-center gap-1">
                <kbd className="font-mono text-[9px] px-1 py-0.5 rounded bg-background border border-border">↵</kbd>
                <span className="hidden sm:inline">Select</span>
              </span>
              <span className="flex items-center gap-1">
                <kbd className="font-mono text-[9px] px-1 py-0.5 rounded bg-background border border-border">ESC</kbd>
                <span className="hidden sm:inline">Close</span>
              </span>
            </div>

            <div className="font-mono text-[10px] text-muted-foreground/70 hidden sm:block">
              DNSNetra Intelligence Feed
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  )
}
