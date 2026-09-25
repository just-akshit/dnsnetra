import React from "react";
import { cn } from "@/lib/utils";

export interface EmptyStatePillProps {
  label?: string;
  className?: string;
}

export const EmptyStatePill: React.FC<EmptyStatePillProps> = ({
  label = "No data",
  className = "",
}) => {
  return (
    <div
      className={cn(
        "inline-flex items-center justify-center px-3 py-1 bg-[#F2F2F2] dark:bg-[#1C2438] text-[#9C9C9C] dark:text-[#6B7280] text-xs font-medium rounded-full select-none",
        className
      )}
    >
      {label}
    </div>
  );
};

export default EmptyStatePill;
