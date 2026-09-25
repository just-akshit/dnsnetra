"use client";

import { Check, Rows3 } from "lucide-react";
import * as React from "react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";
import type { TableDensity } from "@/types/data-table";

interface DataTableDensityProps {
  density: TableDensity;
  onDensityChange: (density: TableDensity) => void;
  className?: string;
}

const DENSITY_OPTIONS: { label: string; value: TableDensity; description: string }[] = [
  { label: "Compact", value: "compact", description: "Condensed row height for high data density" },
  { label: "Default", value: "default", description: "Standard balanced spacing" },
  { label: "Comfortable", value: "comfortable", description: "Spacious row height with extra padding" },
];

export function DataTableDensity({
  density,
  onDensityChange,
  className,
}: DataTableDensityProps) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        className={cn(
          "inline-flex h-8 items-center gap-1.5 rounded-md border border-border/80 bg-background px-2.5 text-xs font-normal text-foreground hover:bg-accent hover:text-foreground cursor-pointer transition-colors focus:outline-none focus:ring-1 focus:ring-ring",
          className,
        )}
      >
        <Rows3 className="size-3.5 text-muted-foreground" />
        <span className="hidden sm:inline capitalize">{density}</span>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-44 text-xs">
        {DENSITY_OPTIONS.map((opt) => (
          <DropdownMenuItem
            key={opt.value}
            onClick={() => onDensityChange(opt.value)}
            className="flex items-center justify-between cursor-pointer py-1.5"
          >
            <div>
              <p className="font-medium text-foreground">{opt.label}</p>
            </div>
            {density === opt.value && <Check className="size-3.5 text-primary" />}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
