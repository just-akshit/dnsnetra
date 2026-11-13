"use client"

import * as React from "react"
import { MoreHorizontalIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

export interface DataTableRowActionItem {
  id: string
  label: string
  icon?: React.ReactNode
  onClick: () => void
  disabled?: boolean
  separator?: boolean
  destructive?: boolean
}

export interface DataTableRowActionsProps {
  actions: DataTableRowActionItem[]
}

export function DataTableRowActions({ actions }: DataTableRowActionsProps) {
  if (!actions || actions.length === 0) return null

  return (
    <div className="flex items-center justify-end" onClick={(e) => e.stopPropagation()}>
      <DropdownMenu>
        <DropdownMenuTrigger
          render={
            <Button
              variant="ghost"
              size="icon"
              className="size-7 text-muted-foreground hover:text-foreground"
            />
          }
        >
          <MoreHorizontalIcon className="size-3.5" />
          <span className="sr-only">Row actions</span>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-36">
          {actions.map((item, idx) => (
            <React.Fragment key={item.id ?? idx}>
              {item.separator && <DropdownMenuSeparator />}
              <DropdownMenuItem
                onClick={item.onClick}
                disabled={item.disabled}
                className={
                  item.destructive
                    ? "text-destructive focus:text-destructive text-xs gap-2"
                    : "text-xs gap-2"
                }
              >
                {item.icon && <span className="size-3.5">{item.icon}</span>}
                <span>{item.label}</span>
              </DropdownMenuItem>
            </React.Fragment>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  )
}
