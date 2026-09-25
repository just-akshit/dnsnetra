import React from "react";
import {
  MoreHorizontal,
  Clock,
  Settings2,
  Copy,
  Trash2,
  Check,
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubTrigger,
  DropdownMenuSubContent,
} from "@/components/ui/dropdown-menu";
import { TimeRangeConfig } from "@/types/chart-config";
import { cn } from "@/lib/utils";

export interface ChartMenuProps {
  timeRange: TimeRangeConfig;
  onTimeRangeChange: (mode: "global" | "custom", customRange?: string) => void;
  onConfigure: () => void;
  onDuplicate: () => void;
  onRemove: () => void;
  className?: string;
}

const TIME_RANGE_OPTIONS: { id: string; label: string; range?: string; mode: "global" | "custom" }[] = [
  { id: "global", label: "Dashboard (Global)", mode: "global" },
  { id: "5m", label: "5 minutes", range: "5m", mode: "custom" },
  { id: "15m", label: "15 minutes", range: "15m", mode: "custom" },
  { id: "1h", label: "1 hour", range: "1h", mode: "custom" },
  { id: "6h", label: "6 hours", range: "6h", mode: "custom" },
  { id: "24h", label: "24 hours", range: "24h", mode: "custom" },
  { id: "7d", label: "7 days", range: "7d", mode: "custom" },
];

export const ChartMenu: React.FC<ChartMenuProps> = ({
  timeRange,
  onTimeRangeChange,
  onConfigure,
  onDuplicate,
  onRemove,
  className,
}) => {
  const isGlobal = timeRange.mode === "global";
  const activeCustom = timeRange.customRange || "24h";

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        className={cn(
          "w-7 h-7 flex items-center justify-center rounded-[6px]",
          "text-[#6B6B6B] hover:text-[#1A1A1A] dark:text-[#9CA3AF] dark:hover:text-[#F3F4F6]",
          "hover:bg-[#F2F2F2] dark:hover:bg-[#1C2438] transition-colors cursor-pointer",
          "focus:outline-hidden",
          className
        )}
        title="Chart actions"
      >
        <MoreHorizontal className="w-4 h-4" />
      </DropdownMenuTrigger>

      <DropdownMenuContent
        align="end"
        sideOffset={6}
        className="w-48 p-1 bg-white dark:bg-[#121826] border border-[#EBEBEB] dark:border-[#1E283D] rounded-[8px] shadow-lg text-[13px]"
      >
        {/* Time range submenu */}
        <DropdownMenuSub>
          <DropdownMenuSubTrigger className="flex items-center gap-2 px-2.5 py-1.5 rounded-[4px] cursor-pointer hover:bg-neutral-100 dark:hover:bg-[#1C2438] text-[#1A1A1A] dark:text-[#F3F4F6]">
            <Clock className="w-3.5 h-3.5 text-[#6B6B6B] dark:text-[#9CA3AF]" />
            <span>Time range</span>
          </DropdownMenuSubTrigger>

          <DropdownMenuSubContent
            sideOffset={4}
            className="w-44 p-1 bg-white dark:bg-[#121826] border border-[#EBEBEB] dark:border-[#1E283D] rounded-[8px] shadow-lg text-[12px]"
          >
            {TIME_RANGE_OPTIONS.map((opt) => {
              const isSelected =
                (opt.mode === "global" && isGlobal) ||
                (opt.mode === "custom" && !isGlobal && activeCustom === opt.range);

              return (
                <DropdownMenuItem
                  key={opt.id}
                  onClick={() => onTimeRangeChange(opt.mode, opt.range)}
                  className="flex items-center justify-between px-2.5 py-1.5 rounded-[4px] cursor-pointer hover:bg-neutral-100 dark:hover:bg-[#1C2438] text-[#1A1A1A] dark:text-[#F3F4F6]"
                >
                  <span className={cn(isSelected && "font-semibold text-[#2F6FED] dark:text-[#60A5FA]")}>
                    {opt.label}
                  </span>
                  {isSelected && <Check className="w-3.5 h-3.5 text-[#2F6FED] dark:text-[#60A5FA]" />}
                </DropdownMenuItem>
              );
            })}
          </DropdownMenuSubContent>
        </DropdownMenuSub>

        {/* Configure */}
        <DropdownMenuItem
          onClick={onConfigure}
          className="flex items-center gap-2 px-2.5 py-1.5 rounded-[4px] cursor-pointer hover:bg-neutral-100 dark:hover:bg-[#1C2438] text-[#1A1A1A] dark:text-[#F3F4F6]"
        >
          <Settings2 className="w-3.5 h-3.5 text-[#6B6B6B] dark:text-[#9CA3AF]" />
          <span>Configure</span>
        </DropdownMenuItem>

        {/* Duplicate */}
        <DropdownMenuItem
          onClick={onDuplicate}
          className="flex items-center gap-2 px-2.5 py-1.5 rounded-[4px] cursor-pointer hover:bg-neutral-100 dark:hover:bg-[#1C2438] text-[#1A1A1A] dark:text-[#F3F4F6]"
        >
          <Copy className="w-3.5 h-3.5 text-[#6B6B6B] dark:text-[#9CA3AF]" />
          <span>Duplicate</span>
        </DropdownMenuItem>

        <DropdownMenuSeparator className="my-1 border-t border-[#EBEBEB] dark:border-[#1E283D]" />

        {/* Remove */}
        <DropdownMenuItem
          onClick={onRemove}
          variant="destructive"
          className="flex items-center gap-2 px-2.5 py-1.5 rounded-[4px] cursor-pointer hover:bg-red-50 dark:hover:bg-red-950/40 text-red-600 dark:text-red-400"
        >
          <Trash2 className="w-3.5 h-3.5 text-red-500" />
          <span>Remove</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};

export default ChartMenu;
