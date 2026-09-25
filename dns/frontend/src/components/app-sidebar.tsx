"use client";

import * as React from "react";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Radio,
  Globe,
  Users,
  ShieldAlert,
  BarChart3,
  Settings,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { NavMain } from "@/components/nav-main";
import { NavUser } from "@/components/nav-user";
import { TeamSwitcher } from "@/components/team-switcher";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarRail,
} from "@/components/ui/sidebar";
import { useAuth } from "@/context/AuthContext";

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const { user, logout } = useAuth();
  const pathname = usePathname() || "";

  const teams = [
    {
      name: user?.email ? `${user.email.split("@")[0]}'s SOC` : "SOC Perimeter",
      logo: ShieldCheck,
      plan: "Enterprise",
    },
    {
      name: "Secondary Perimeter",
      logo: Zap,
      plan: "Production",
    },
  ];

  const navMain = [
    {
      title: "Overview",
      url: "/overview",
      icon: LayoutDashboard,
      isActive: pathname === "/" || pathname === "/overview",
    },
    {
      title: "DNS",
      url: "/analytics/dns",
      icon: Radio,
      isActive: pathname.startsWith("/analytics/dns") || pathname.startsWith("/dns"),
      items: [
        {
          title: "Activity",
          url: "/analytics/dns",
        },
        {
          title: "Timeline",
          url: "/analytics",
        },
      ],
    },
    {
      title: "Domains",
      url: "/investigate/domains",
      icon: Globe,
      isActive: pathname.startsWith("/investigate/domains") || pathname.startsWith("/domains"),
      items: [
        {
          title: "Directory",
          url: "/investigate/domains",
        },
        {
          title: "Malicious",
          url: "/investigate/domains?label=malicious",
        },
      ],
    },
    {
      title: "Clients",
      url: "/investigate/clients",
      icon: Users,
      isActive: pathname.startsWith("/investigate/clients") || pathname.startsWith("/clients"),
    },
    {
      title: "Threats",
      url: "/analytics/threats",
      icon: ShieldAlert,
      isActive: pathname.startsWith("/analytics/threats") || pathname.startsWith("/threats"),
    },
    {
      title: "Analytics",
      url: "/analytics",
      icon: BarChart3,
      isActive: pathname === "/analytics",
    },
    {
      title: "Settings",
      url: "/settings",
      icon: Settings,
      isActive: pathname.startsWith("/settings"),
    },
  ];

  const userData = {
    name: user?.name || user?.email?.split("@")[0] || "Operator",
    email: user?.email || "admin@soc.local",
    avatar: "",
  };

  return (
    <Sidebar collapsible="icon" {...props}>
      <SidebarHeader>
        <TeamSwitcher teams={teams} />
      </SidebarHeader>
      <SidebarContent>
        <NavMain items={navMain} />
      </SidebarContent>
      <SidebarFooter>
        <NavUser user={userData} onLogout={logout} />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}

export default AppSidebar;
