"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  SidebarGroup,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
} from "@/components/ui/sidebar";
import { ChevronRightIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export function NavMain({
  items,
}: {
  items: {
    title: string;
    url: string;
    icon?: React.ComponentType<{ className?: string }>;
    isActive?: boolean;
    items?: {
      title: string;
      url: string;
    }[];
  }[];
}) {
  const pathname = usePathname() || "";

  return (
    <SidebarGroup>
      <SidebarMenu className="gap-0.5">
        {items.map((item) => {
          const Icon = item.icon;
          const isItemDirectActive =
            item.url === "/overview"
              ? pathname === "/" || pathname === "/overview"
              : pathname === item.url;

          // If item has sub-items, render collapsible
          if (item.items && item.items.length > 0) {
            return (
              <Collapsible
                key={item.title}
                defaultOpen={item.isActive}
                className="group/collapsible"
                render={<SidebarMenuItem />}
              >
                <CollapsibleTrigger
                  render={
                    <SidebarMenuButton
                      tooltip={item.title}
                      isActive={item.isActive}
                      className={cn(
                        "text-[13px] font-normal transition-colors",
                        item.isActive && "bg-sidebar-accent font-medium text-sidebar-primary"
                      )}
                    />
                  }
                >
                  {Icon && <Icon className="size-4 shrink-0" />}
                  <span>{item.title}</span>
                  <ChevronRightIcon className="ml-auto size-3.5 transition-transform duration-200 group-data-open/collapsible:rotate-90 text-muted-foreground" />
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <SidebarMenuSub className="my-0.5">
                    {item.items.map((subItem) => {
                      const isSubActive = pathname === subItem.url;
                      return (
                        <SidebarMenuSubItem key={subItem.title}>
                          <SidebarMenuSubButton
                            isActive={isSubActive}
                            render={<Link href={subItem.url} />}
                            className={cn(
                              "text-xs transition-colors",
                              isSubActive && "font-medium text-primary"
                            )}
                          >
                            <span>{subItem.title}</span>
                          </SidebarMenuSubButton>
                        </SidebarMenuSubItem>
                      );
                    })}
                  </SidebarMenuSub>
                </CollapsibleContent>
              </Collapsible>
            );
          }

          // Single menu item
          return (
            <SidebarMenuItem key={item.title}>
              <SidebarMenuButton
                isActive={isItemDirectActive}
                tooltip={item.title}
                render={<Link href={item.url} />}
                className={cn(
                  "text-[13px] font-normal transition-colors",
                  isItemDirectActive && "bg-sidebar-accent font-medium text-sidebar-primary"
                )}
              >
                {Icon && <Icon className="size-4 shrink-0" />}
                <span>{item.title}</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          );
        })}
      </SidebarMenu>
    </SidebarGroup>
  );
}

export default NavMain;
