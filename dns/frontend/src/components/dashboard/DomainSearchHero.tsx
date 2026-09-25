"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { Search, ArrowRight, Globe, Cpu, X } from "lucide-react";
import { cn } from "@/lib/utils";

export interface DomainSearchHeroProps {
  onSearch?: (query: string) => void;
  className?: string;
}

export const DomainSearchHero: React.FC<DomainSearchHeroProps> = ({
  onSearch,
  className,
}) => {
  const [query, setQuery] = useState("");
  const [isFocused, setIsFocused] = useState(false);
  const router = useRouter();

  const handleExecuteSearch = (searchTerm: string) => {
    const clean = searchTerm.trim();
    if (!clean) return;

    if (onSearch) {
      onSearch(clean);
    }

    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(clean) || clean.includes(":");
    if (isIp) {
      router.push(`/investigate/clients/${encodeURIComponent(clean)}`);
    } else {
      router.push(`/investigate/domains/${encodeURIComponent(clean)}`);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleExecuteSearch(query);
    }
  };

  const quickSamples = [
    { label: "c2-tracker.relay.net", type: "domain" },
    { label: "192.168.1.104", type: "ip" },
    { label: "phish-verify.auth-live.cc", type: "domain" },
    { label: "10.0.4.88", type: "ip" },
  ];

  return (
    <div className={cn("w-full", className)}>
      <div
        className={cn(
          "relative flex items-center w-full rounded-[12px] transition-all duration-200",
          "bg-white dark:bg-[#121826]",
          "border shadow-2xs",
          isFocused
            ? "border-[#2F6FED] ring-2 ring-[#2F6FED]/20 dark:ring-[#2F6FED]/30 shadow-xs"
            : "border-[#EBEBEB] dark:border-[#1E283D] hover:border-[#D9D9D9] dark:hover:border-[#2D3A54]"
        )}
      >
        {/* Search Icon */}
        <div className="pl-4 pr-2 text-[#6B6B6B] dark:text-[#9CA3AF] flex items-center justify-center pointer-events-none">
          <Search className="w-4 h-4 text-[#2F6FED]" />
        </div>

        {/* Input */}
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onFocus={() => setIsFocused(true)}
          onBlur={() => setIsFocused(false)}
          onKeyDown={handleKeyDown}
          placeholder="Search domain, IP, FQDN, or threat indicator..."
          className="flex-1 py-3.5 px-2 bg-transparent text-[14px] text-[#1A1A1A] dark:text-[#F3F4F6] placeholder:text-[#9C9C9C] dark:placeholder:text-[#6B7280] outline-none font-sans"
        />

        {/* Clear query button */}
        {query && (
          <button
            type="button"
            onClick={() => setQuery("")}
            className="p-1.5 mr-1 text-[#9C9C9C] hover:text-[#1A1A1A] dark:hover:text-[#F3F4F6] rounded-md transition-colors cursor-pointer"
            title="Clear search"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}

        {/* Right side controls: Action trigger + ⌘K badge */}
        <div className="pr-3 flex items-center gap-2">
          {query.trim() ? (
            <button
              type="button"
              onClick={() => handleExecuteSearch(query)}
              className="flex items-center gap-1 px-3 py-1.5 bg-[#2F6FED] hover:bg-[#255ED4] text-white text-[12px] font-medium rounded-[6px] shadow-2xs transition-colors cursor-pointer"
            >
              <span>Investigate</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          ) : (
            <div className="hidden sm:flex items-center gap-1.5">
              <span className="text-[11px] text-[#9C9C9C] dark:text-[#6B7280] hidden md:inline">
                Domain Intelligence
              </span>
              <kbd className="px-2 py-0.5 text-[10px] font-mono font-medium text-[#6B6B6B] dark:text-[#9CA3AF] bg-[#F2F2F2] dark:bg-[#1C2438] border border-[#EBEBEB] dark:border-[#2D3A54] rounded-[4px]">
                ⌘K
              </kbd>
            </div>
          )}
        </div>
      </div>

      {/* Quick sample chips under search for rapid SOC investigation */}
      <div className="mt-2 flex flex-wrap items-center gap-2 px-1 text-[11px] text-[#9C9C9C] dark:text-[#6B7280]">
        <span className="font-medium text-[#6B6B6B] dark:text-[#9CA3AF]">Quick lookup:</span>
        {quickSamples.map((sample) => (
          <button
            key={sample.label}
            type="button"
            onClick={() => {
              setQuery(sample.label);
              handleExecuteSearch(sample.label);
            }}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-[4px] bg-[#F2F2F2] dark:bg-[#1C2438] text-[#1A1A1A] dark:text-[#D1D5DB] hover:bg-[#E5E7EB] dark:hover:bg-[#28354E] hover:text-[#2F6FED] dark:hover:text-[#60A5FA] border border-[#E5E7EB] dark:border-[#1E283D] font-mono text-[11px] transition-colors cursor-pointer"
          >
            {sample.type === "domain" ? (
              <Globe className="w-2.5 h-2.5 text-[#2F6FED]" />
            ) : (
              <Cpu className="w-2.5 h-2.5 text-amber-500" />
            )}
            <span>{sample.label}</span>
          </button>
        ))}
      </div>
    </div>
  );
};

export default DomainSearchHero;
