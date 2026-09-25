"use client";

import React, { createContext, useContext, useState, useCallback, useMemo } from "react";

export interface ActiveFilter {
  id: string;
  category: "verdict" | "severity" | "source" | "domain" | "client" | "queryType";
  label: string;
  value: string;
}

export interface FilterContextType {
  filters: ActiveFilter[];
  addFilter: (category: ActiveFilter["category"], label: string, value: string) => void;
  removeFilter: (id: string) => void;
  clearFilters: () => void;
  hasFilters: boolean;
  filterCount: number;
  getFilterValue: (category: ActiveFilter["category"]) => string | undefined;
}

const FilterContext = createContext<FilterContextType | null>(null);

export const FilterProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [filters, setFilters] = useState<ActiveFilter[]>([]);

  const addFilter = useCallback(
    (category: ActiveFilter["category"], label: string, value: string) => {
      setFilters((prev) => {
        const filtered = prev.filter((f) => f.category !== category);
        return [
          ...filtered,
          {
            id: `${category}-${value}`,
            category,
            label,
            value,
          },
        ];
      });
    },
    []
  );

  const removeFilter = useCallback((id: string) => {
    setFilters((prev) => prev.filter((f) => f.id !== id));
  }, []);

  const clearFilters = useCallback(() => {
    setFilters([]);
  }, []);

  const getFilterValue = useCallback(
    (category: ActiveFilter["category"]) => {
      const match = filters.find((f) => f.category === category);
      return match?.value;
    },
    [filters]
  );

  const contextValue = useMemo<FilterContextType>(() => ({
    filters,
    addFilter,
    removeFilter,
    clearFilters,
    hasFilters: filters.length > 0,
    filterCount: filters.length,
    getFilterValue,
  }), [filters, addFilter, removeFilter, clearFilters, getFilterValue]);

  return (
    <FilterContext.Provider value={contextValue}>
      {children}
    </FilterContext.Provider>
  );
};

export const useFilters = (): FilterContextType => {
  const ctx = useContext(FilterContext);
  if (!ctx) {
    throw new Error("useFilters must be used within a FilterProvider");
  }
  return ctx;
};
