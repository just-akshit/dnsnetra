import React from "react";
import { FolderOpen } from "lucide-react";

interface EmptyStateProps {
  title?: string;
  message?: string;
  icon?: React.ElementType;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title = "No records found",
  message = "No data matching your current filters or query.",
  icon: Icon = FolderOpen,
}) => {
  return (
    <div className="flex flex-col items-center justify-center text-center p-12 space-y-3">
      <div className="p-3 bg-secondary rounded-full text-slate-500">
        <Icon className="w-8 h-8 opacity-60" />
      </div>
      <div>
        <h4 className="text-base font-medium text-foreground">{title}</h4>
        <p className="text-sm text-slate-400 max-w-sm mt-1">{message}</p>
      </div>
    </div>
  );
};

export default EmptyState;
