"use client";

import React from "react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { TimeseriesBucket } from "../../types/api";

interface ThreatActivityChartProps {
  data?: TimeseriesBucket[];
}

const ThreatActivityChart: React.FC<ThreatActivityChartProps> = ({ data = [] }) => {
  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-xs font-mono text-slate-500">
        No timeseries activity data available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart
        data={data}
        margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
      >
        <defs>
          <linearGradient id="colorTotalQueries" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="colorThreatQueries" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#EF4444" stopOpacity={0.4} />
            <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
        <XAxis
          dataKey="time_bucket"
          stroke="#475569"
          fontSize={10}
          tickLine={false}
          axisLine={false}
          tickFormatter={(val) => (val && val.length > 10 ? val.substring(11, 16) : val)}
        />
        <YAxis
          stroke="#475569"
          fontSize={10}
          tickLine={false}
          axisLine={false}
          tickFormatter={(value) => (value === 0 ? "0" : value)}
        />
        <Tooltip
          contentStyle={{ backgroundColor: "#020617", borderColor: "#334155", fontSize: "12px" }}
          itemStyle={{ color: "#F8FAFC" }}
        />
        <Area
          type="monotone"
          dataKey="total_queries"
          stroke="#3B82F6"
          fillOpacity={1}
          fill="url(#colorTotalQueries)"
          name="Total Queries"
        />
        <Area
          type="monotone"
          dataKey="threat_queries"
          stroke="#EF4444"
          fillOpacity={1}
          fill="url(#colorThreatQueries)"
          name="Threat Queries"
        />
      </AreaChart>
    </ResponsiveContainer>
  );
};

export default ThreatActivityChart;
