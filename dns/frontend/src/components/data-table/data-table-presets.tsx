"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import type { TablePreset } from "@/types/data-table";

interface DataTablePresetsProps<TData> {
  presets: TablePreset<TData>[];
  activePresetId: string | null;
  onSelectPreset: (preset: TablePreset<TData>) => void;
  className?: string;
}

export function DataTablePresets<TData>({
  presets,
  activePresetId,
  onSelectPreset,
  className,
}: DataTablePresetsProps<TData>) {
  if (!presets.length) return null;

  return (
    <div
      className={cn(
        "flex items-center gap-1 overflow-x-auto py-1 scrollbar-none",
        className,
      )}
    >
      {presets.map((preset) => {
        const isActive = activePresetId === preset.id;
        const Icon = preset.icon;

        return (
          <button
            key={preset.id}
            type="button"
            onClick={() => onSelectPreset(preset)}
            className={cn(
              "inline-flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-md font-medium transition-colors cursor-pointer shrink-0 border",
              isActive
                ? "bg-primary text-primary-foreground border-primary shadow-xs"
                : "bg-background text-muted-foreground hover:text-foreground hover:bg-accent border-border/70",
            )}
          >
            {Icon && <Icon className="size-3 shrink-0" />}
            <span>{preset.label}</span>
          </button>
        );
      })}
    </div>
  );
}
