"use client";

import React, { useState } from "react";
import { Plus, X, ChevronRight, Check } from "lucide-react";
import { Popover, PopoverTrigger, PopoverPopup } from "@/components/ui/popover";
import { useFilters, ActiveFilter } from "@/context/FilterContext";
import { cn } from "@/lib/utils";

const FILTER_CATEGORIES: {
  key: ActiveFilter["category"];
  label: string;
  options: { label: string; value: string }[];
}[] = [
  {
    key: "verdict",
    label: "Verdict",
    options: [
      { label: "Malicious", value: "malicious" },
      { label: "Suspicious", value: "suspicious" },
      { label: "Clean", value: "clean" },
      { label: "Unknown", value: "unknown" },
    ],
  },
  {
    key: "severity",
    label: "Severity",
    options: [
      { label: "Critical", value: "critical" },
      { label: "High", value: "high" },
      { label: "Medium", value: "medium" },
      { label: "Low", value: "low" },
    ],
  },
  {
    key: "source",
    label: "Source",
    options: [
      { label: "URLhaus", value: "urlhaus" },
      { label: "Tranco", value: "tranco" },
      { label: "VirusTotal", value: "virustotal" },
      { label: "AlienVault", value: "otx" },
    ],
  },
  {
    key: "queryType",
    label: "Query Type",
    options: [
      { label: "A", value: "A" },
      { label: "AAAA", value: "AAAA" },
      { label: "MX", value: "MX" },
      { label: "TXT", value: "TXT" },
      { label: "CNAME", value: "CNAME" },
    ],
  },
];

export const GlobalFilterBar: React.FC<{ className?: string }> = ({ className }) => {
  const { filters, addFilter, removeFilter, clearFilters, hasFilters } = useFilters();
  const [open, setOpen] = useState(false);
  const [selectedCategoryKey, setSelectedCategoryKey] = useState<ActiveFilter["category"]>("verdict");

  const activeCategory =
    FILTER_CATEGORIES.find((c) => c.key === selectedCategoryKey) || FILTER_CATEGORIES[0];

  const handleSelectOption = (category: ActiveFilter["category"], label: string, value: string) => {
    addFilter(category, label, value);
    setOpen(false);
  };

  return (
    <div className={cn("flex flex-wrap items-center gap-1.5 text-xs", className)}>
      {/* Add Filter Button */}
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger
          render={
            <button
              className={cn(
                "inline-flex items-center gap-1.5 px-2.5 py-1 rounded border border-border/80 bg-background hover:bg-accent text-xs font-medium text-foreground transition-colors cursor-pointer",
                open && "border-ring"
              )}
            />
          }
        >
          <Plus className="w-3.5 h-3.5 text-muted-foreground" />
          <span>Add filter</span>
        </PopoverTrigger>

        <PopoverPopup
          align="start"
          sideOffset={4}
          className="w-72 p-0 bg-popover border border-border rounded-lg shadow-lg overflow-hidden z-50 text-foreground"
        >
          <div className="grid grid-cols-[110px_1fr] divide-x divide-border">
            {/* Category column */}
            <div className="py-1 bg-muted/20">
              {FILTER_CATEGORIES.map((cat) => (
                <button
                  key={cat.key}
                  onClick={() => setSelectedCategoryKey(cat.key)}
                  className={cn(
                    "w-full flex items-center justify-between px-2.5 py-1.5 text-xs text-left transition-colors cursor-pointer",
                    selectedCategoryKey === cat.key
                      ? "bg-accent font-medium text-foreground"
                      : "text-muted-foreground hover:text-foreground"
                  )}
                >
                  <span className="truncate">{cat.label}</span>
                  <ChevronRight className="w-3 h-3 opacity-60" />
                </button>
              ))}
            </div>

            {/* Options column */}
            <div className="py-1 max-h-48 overflow-y-auto">
              {activeCategory.options.map((opt) => {
                const isSelected = filters.some(
                  (f: ActiveFilter) => f.category === activeCategory.key && f.value === opt.value
                );
                return (
                  <button
                    key={opt.value}
                    onClick={() => handleSelectOption(activeCategory.key, opt.label, opt.value)}
                    className={cn(
                      "w-full flex items-center justify-between px-2.5 py-1.5 text-xs text-left transition-colors hover:bg-accent cursor-pointer",
                      isSelected ? "text-primary font-medium bg-primary/10" : "text-foreground"
                    )}
                  >
                    <span>{opt.label}</span>
                    {isSelected && <Check className="w-3.5 h-3.5 text-primary" />}
                  </button>
                );
              })}
            </div>
          </div>
        </PopoverPopup>
      </Popover>

      {/* Render Active Filter Chips */}
      {filters.map((filter: ActiveFilter) => {
        const cat = FILTER_CATEGORIES.find((c) => c.key === filter.category);
        const catLabel = cat ? cat.label : filter.category;
        return (
          <div
            key={filter.id}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-border bg-secondary text-foreground text-xs font-normal"
          >
            <span className="text-muted-foreground">{catLabel}:</span>
            <span className="font-medium">{filter.label}</span>
            <button
              onClick={() => removeFilter(filter.id)}
              className="ml-0.5 hover:text-foreground p-0.5 text-muted-foreground transition-colors cursor-pointer"
              title="Remove filter"
            >
              <X className="w-3 h-3" />
            </button>
          </div>
        );
      })}

      {/* Clear All */}
      {hasFilters && (
        <button
          onClick={clearFilters}
          className="text-xs text-muted-foreground hover:text-foreground transition-colors ml-1 cursor-pointer"
        >
          Clear all
        </button>
      )}
    </div>
  );
};

export default GlobalFilterBar;
