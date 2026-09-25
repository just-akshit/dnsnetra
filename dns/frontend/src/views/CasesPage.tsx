"use client";

import React, { useState } from "react";
import { ListFilter, Plus, Search, ShieldAlert, FolderOpen, Clock } from "lucide-react";
import { MetricWidget } from "@/components/dashboard/MetricWidget";
import { DashboardWidget } from "@/components/dashboard/DashboardWidget";
import { GlobalFilterBar } from "@/components/layout/GlobalFilterBar";
import { GlobalTimeRangePicker } from "@/components/layout/GlobalTimeRangePicker";

export const CasesPage: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState("");

  const sampleCases = [
    {
      id: "CASE-1042",
      title: "Potential DGA Domain Generation Outbreak",
      status: "In Investigation",
      severity: "High",
      assignedTo: "Security Admin",
      updatedAt: "10 mins ago",
      indicatorsCount: 14,
    },
    {
      id: "CASE-1039",
      title: "Repeated NXDOMAIN Tunneling Sequence on Endpoint 192.168.1.105",
      status: "Triage",
      severity: "Critical",
      assignedTo: "SOC Tier 2",
      updatedAt: "1 hour ago",
      indicatorsCount: 38,
    },
    {
      id: "CASE-1031",
      title: "Suspicious Dynamic DNS Lookup Surge",
      status: "Resolved",
      severity: "Medium",
      assignedTo: "Analyst 1",
      updatedAt: "Yesterday",
      indicatorsCount: 5,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground font-sans">
            Incident Cases & Investigation Workflows
          </h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Security incident tracking, evidence collection, and collaborative case management.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <GlobalTimeRangePicker />
          <button
            type="button"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-primary text-primary-foreground text-xs font-medium hover:opacity-90 transition-opacity cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Create Case</span>
          </button>
        </div>
      </div>

      {/* Global Filters */}
      <GlobalFilterBar />

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <MetricWidget
          title="Open Cases"
          value="2"
          trend="Active investigations"
        />
        <MetricWidget
          title="Critical Incidents"
          value="1"
          trend="Immediate attention"
          isThreat={true}
        />
        <MetricWidget
          title="Avg Resolution Time"
          value="42m"
          trend="Past 7 days"
        />
      </div>

      {/* Cases List Card */}
      <DashboardWidget
        title="Active Incident Cases"
        description="Escalated security events and multi-stage investigation timelines"
      >
        <div className="space-y-3">
          {sampleCases.map((c) => (
            <div
              key={c.id}
              className="p-3.5 rounded-lg border border-border bg-secondary/20 hover:bg-secondary/50 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3"
            >
              <div className="flex items-start gap-3">
                <div className="p-2 rounded-md bg-secondary text-primary shrink-0 mt-0.5 sm:mt-0">
                  <FolderOpen className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-mono font-semibold text-primary">
                      {c.id}
                    </span>
                    <span
                      className={`text-[10px] px-2 py-0.2 rounded-full font-medium ${
                        c.severity === "Critical"
                          ? "bg-red-500/15 text-red-500"
                          : c.severity === "High"
                          ? "bg-orange-500/15 text-orange-500"
                          : "bg-blue-500/15 text-blue-500"
                      }`}
                    >
                      {c.severity}
                    </span>
                    <span className="text-[10px] px-2 py-0.2 rounded-full bg-secondary text-muted-foreground">
                      {c.status}
                    </span>
                  </div>
                  <p className="text-xs font-medium text-foreground mt-1">
                    {c.title}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-4 text-xs text-muted-foreground self-end sm:self-auto shrink-0">
                <div className="flex items-center gap-1">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>{c.indicatorsCount} IOCs</span>
                </div>
                <div className="flex items-center gap-1 font-mono text-[11px]">
                  <Clock className="w-3.5 h-3.5" />
                  <span>{c.updatedAt}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </DashboardWidget>
    </div>
  );
};

export default CasesPage;
