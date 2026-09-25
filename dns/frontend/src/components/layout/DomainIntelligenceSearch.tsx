"use client";

import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { Search, ArrowRight, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { validateDomainSearchInput } from "@/lib/domain-utils";

export interface DomainIntelligenceSearchProps {
  onOpenDialog?: () => void;
  className?: string;
}

export const DomainIntelligenceSearch: React.FC<DomainIntelligenceSearchProps> = ({
  onOpenDialog,
  className,
}) => {
  const [query, setQuery] = useState("");
  const [isFocused, setIsFocused] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const router = useRouter();
  const isSearchingRef = useRef(false);

  const [isMac, setIsMac] = useState(false);

  useEffect(() => {
    if (typeof window !== "undefined") {
      setIsMac(/Mac|iPod|iPhone|iPad/.test(window.navigator.userAgent));
    }
  }, []);

  // Shared handler for both Enter key and button click
  const handleExecuteSearch = (searchTerm: string) => {
    if (isSearchingRef.current) return; // prevent duplicate submissions

    const result = validateDomainSearchInput(searchTerm);

    if (!result.valid) {
      setValidationError(result.error || "Please enter a valid domain.");
      return;
    }

    setValidationError(null);
    isSearchingRef.current = true;

    if (result.isIp) {
      router.push(`/investigate/clients/${encodeURIComponent(result.normalized)}`);
    } else {
      router.push(`/investigate/domains/${encodeURIComponent(result.normalized)}`);
    }

    // Reset after navigation is queued
    setTimeout(() => { isSearchingRef.current = false; }, 300);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleExecuteSearch(query);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setQuery(e.target.value);
    if (validationError) setValidationError(null); // clear on edit
  };

  return (
    <div className={cn("w-full max-w-[680px] min-w-0", className)}>
      <div
        className={cn(
          "relative flex items-center w-full h-9 rounded-[8px] transition-all duration-150",
          "bg-[#F7F8FA] dark:bg-[#121826]/90",
          "border",
          validationError
            ? "border-red-400 dark:border-red-500 ring-2 ring-red-400/15"
            : isFocused
            ? "border-[#2F6FED] ring-2 ring-[#2F6FED]/15 dark:ring-[#2F6FED]/25 bg-white dark:bg-[#121826] shadow-2xs"
            : "border-[#E5E7EB] dark:border-[#1E283D] hover:border-[#D1D5DB] dark:hover:border-[#2D3A54]"
        )}
      >
        {/* Search Icon */}
        <div className="pl-3 pr-1.5 flex items-center justify-center pointer-events-none">
          <Search className={cn("w-3.5 h-3.5", validationError ? "text-red-400" : "text-[#2F6FED]")} />
        </div>

        {/* Search Input Field */}
        <input
          type="text"
          value={query}
          onChange={handleChange}
          onFocus={() => setIsFocused(true)}
          onBlur={() => setIsFocused(false)}
          onKeyDown={handleKeyDown}
          placeholder="Search domain, IP, FQDN, or threat indicator..."
          aria-invalid={!!validationError}
          aria-describedby={validationError ? "domain-search-error" : undefined}
          className="flex-1 py-1 px-1.5 bg-transparent text-[13px] text-[#1A1A1A] dark:text-[#F3F4F6] placeholder:text-[#9C9C9C] dark:placeholder:text-[#6B7280] outline-none font-sans min-w-0"
        />

        {/* Inline validation error */}
        {validationError && (
          <span
            id="domain-search-error"
            className="text-[10px] text-red-500 dark:text-red-400 whitespace-nowrap px-1.5 shrink-0"
          >
            {validationError}
          </span>
        )}

        {/* Clear query button */}
        {query && (
          <button
            type="button"
            onClick={() => { setQuery(""); setValidationError(null); }}
            className="p-1 mr-1 text-[#9C9C9C] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6] rounded transition-colors cursor-pointer"
            title="Clear search"
          >
            <X className="w-3 h-3" />
          </button>
        )}

        {/* Right side controls */}
        <div className="pr-2.5 flex items-center gap-1.5 shrink-0">
          {query.trim() ? (
            <button
              type="button"
              onClick={() => handleExecuteSearch(query)}
              className="flex items-center gap-1 px-2.5 py-1 bg-[#2F6FED] hover:bg-[#255ED4] text-white text-[11px] font-medium rounded-[5px] shadow-2xs transition-colors cursor-pointer"
            >
              <span>Investigate</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          ) : (
            <div className="flex items-center gap-1.5">
              <span className="text-[10px] text-[#9C9C9C] dark:text-[#6B7280] hidden lg:inline font-medium tracking-tight">
                Domain Intelligence
              </span>
              <button
                type="button"
                onClick={onOpenDialog}
                className="px-1.5 py-0.5 text-[10px] font-mono font-medium text-[#6B6B6B] dark:text-[#9CA3AF] bg-[#EBEBEB] dark:bg-[#1C2438] border border-[#D9D9D9] dark:border-[#2D3A54] rounded-[4px] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6] transition-colors cursor-pointer"
                title="Global Command Palette"
              >
                {isMac ? "⌘K" : "Ctrl K"}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DomainIntelligenceSearch;
