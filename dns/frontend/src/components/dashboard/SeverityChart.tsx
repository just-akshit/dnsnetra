"use client";

import React from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { ThreatCategory } from "../../types/api";

interface SeverityChartProps {
  categories?: ThreatCategory[];
}

const CATEGORY_COLORS = [
  "#EF4444", // Red
  "#F97316", // Orange
  "#F59E0B", // Amber
  "#3B82F6", // Blue
  "#10B981", // Emerald
  "#64748B", // Slate
];

const SeverityChart: React.FC<SeverityChartProps> = ({ categories = [] }) => {
  if (categories.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-xs font-mono text-slate-500">
        No threat category records available
      </div>
    );
  }

  const chartData = categories.slice(0, 7).map((cat) => ({
    name: cat.category,
    count: cat.count,
    pct: cat.pct,
  }));

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart
        data={chartData}
        margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
      >
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
        <XAxis
          dataKey="name"
          stroke="#475569"
          fontSize={10}
          tickLine={false}
          axisLine={false}
          tickFormatter={(val) => (val && val.length > 12 ? `${val.substring(0, 10)}...` : val)}
        />
        <YAxis
          stroke="#475569"
          fontSize={10}
          tickLine={false}
          axisLine={false}
        />
        <Tooltip
          contentStyle={{ backgroundColor: "#020617", borderColor: "#334155", fontSize: "12px" }}
          itemStyle={{ color: "#F8FAFC" }}
          cursor={{ fill: "#1E293B" }}
        />
        <Bar dataKey="count" fill="#3B82F6" radius={[4, 4, 0, 0]}>
          {chartData.map((_, index) => (
            <Cell
              key={`cell-${index}`}
              fill={CATEGORY_COLORS[index % CATEGORY_COLORS.length]}
            />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
};

export default SeverityChart;
