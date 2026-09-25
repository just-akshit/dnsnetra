export type ChartType =
  | "timeseries"
  | "bar"
  | "depth-bar"
  | "donut"
  | "stat"
  | "toplist"
  | "candlestick";

export type DatasetId =
  | "dnsAnalytics"
  | "threats"
  | "domains"
  | "clients";

export type AggregationType = "count" | "sum" | "avg" | "p50" | "p95" | "max";

export type FilterOperator = "=" | "!=" | ">" | "<" | "contains";

export interface ChartFilter {
  id: string;
  field: string;
  operator: FilterOperator;
  value: string;
}

export interface ChartSeries {
  id: string;
  name: string;
  metric: string;
  color?: string;
}

export interface TimeRangeConfig {
  mode: "global" | "custom";
  customRange?: string; // "5m" | "15m" | "1h" | "6h" | "24h" | "7d"
}

export interface DashboardChartConfig {
  id: string;
  title: string;
  subtitle?: string;
  chartType: ChartType;
  dataset: DatasetId;
  metric: string;
  aggregation?: AggregationType;
  dimension?: string;
  series?: ChartSeries[];
  filters?: ChartFilter[];
  timeRange: TimeRangeConfig;
  interval?: string; // "auto" | "1m" | "5m" | "15m" | "1h" | "1d"
  gridSpan: "full" | "half";
  height?: number;
}

export interface DatasetMeta {
  id: DatasetId;
  name: string;
  description: string;
  metrics: { id: string; name: string; type: "number" | "rate" | "time"; aggregations: AggregationType[] }[];
  dimensions: { id: string; name: string }[];
}

export const SUPPORTED_DATASETS: DatasetMeta[] = [
  {
    id: "dnsAnalytics",
    name: "DNS Analytics",
    description: "Query throughput, resolution latency, and protocol distribution",
    metrics: [
      { id: "total_queries", name: "Total Queries", type: "number", aggregations: ["count", "sum"] },
      { id: "queries_per_sec", name: "Queries / sec", type: "rate", aggregations: ["avg", "max", "p95"] },
      { id: "unique_domains", name: "Unique Domains", type: "number", aggregations: ["count"] },
      { id: "unique_clients", name: "Unique Clients", type: "number", aggregations: ["count"] },
      { id: "avg_resolution_time", name: "Resolution Latency", type: "time", aggregations: ["avg", "p50", "p95", "max"] },
    ],
    dimensions: [
      { id: "timestamp", name: "Time Bucket" },
      { id: "query_type", name: "Query Record Type (A, AAAA, TXT, CNAME)" },
      { id: "response_code", name: "Response Code (NOERROR, NXDOMAIN, SERVFAIL)" },
      { id: "protocol", name: "Transport Protocol (UDP, TCP, DoH)" },
    ],
  },
  {
    id: "threats",
    name: "Threat Telemetry",
    description: "Security events, IOC detections, and mitigation enforcement",
    metrics: [
      { id: "total_threats", name: "Total Threats", type: "number", aggregations: ["count", "sum"] },
      { id: "malicious_queries", name: "Malicious Queries", type: "number", aggregations: ["count", "sum"] },
      { id: "suspicious_queries", name: "Suspicious Queries", type: "number", aggregations: ["count", "sum"] },
      { id: "threat_rate", name: "Threat Rate (%)", type: "rate", aggregations: ["avg"] },
      { id: "blocked_queries", name: "Blocked Queries", type: "number", aggregations: ["count", "sum"] },
    ],
    dimensions: [
      { id: "category", name: "Threat Category (Malware, Phishing, C2, DGA)" },
      { id: "verdict", name: "Verdict (Malicious, Suspicious, Clean)" },
      { id: "ti_source", name: "Threat Intel Feed / Engine" },
      { id: "action", name: "Enforcement Action (Blocked, Sinkholed, Alerted)" },
    ],
  },
  {
    id: "domains",
    name: "Domain Intelligence",
    description: "Domain reputation, query volumes, and risk categorization",
    metrics: [
      { id: "query_count", name: "Domain Query Volume", type: "number", aggregations: ["count", "sum"] },
      { id: "threat_score", name: "Risk Score", type: "number", aggregations: ["avg", "max"] },
      { id: "client_count", name: "Client Endpoints", type: "number", aggregations: ["count"] },
    ],
    dimensions: [
      { id: "domain", name: "Domain FQDN" },
      { id: "label", name: "Security Label" },
      { id: "category", name: "Content Category" },
    ],
  },
  {
    id: "clients",
    name: "Client Endpoints",
    description: "Internal requester endpoints, VLANs, and compromised hosts",
    metrics: [
      { id: "query_count", name: "Client Query Volume", type: "number", aggregations: ["count", "sum"] },
      { id: "threat_count", name: "Detected Threats", type: "number", aggregations: ["count", "sum"] },
    ],
    dimensions: [
      { id: "client_ip", name: "Client IP Address" },
      { id: "vlan_segment", name: "VLAN / Network Segment" },
      { id: "status", name: "Incident Status (Critical, Warning, Clean)" },
    ],
  },
];

export const DATASET_REGISTRY = SUPPORTED_DATASETS;

export const CHART_TYPE_OPTIONS: { type: ChartType; label: string; description: string; iconName: string }[] = [
  { type: "depth-bar", label: "3D Depth Bar", description: "Bklit 3D perspective depth bars for clean/suspicious/malicious queries", iconName: "BarChart3" },
  { type: "timeseries", label: "Time Series", description: "Trends and patterns over time", iconName: "LineChart" },
  { type: "bar", label: "Vertical Bar", description: "Comparison between categories", iconName: "BarChart3" },
  { type: "donut", label: "Donut / Pie", description: "Proportions and classification distribution", iconName: "PieChart" },
  { type: "candlestick", label: "Candlestick", description: "OHLC threat activity and momentum over time", iconName: "CandlestickChart" },
  { type: "stat", label: "Stat / Metric", description: "Single high-impact numeric summary", iconName: "Hash" },
  { type: "toplist", label: "Top List", description: "Rankings and highest-frequency items", iconName: "ListOrdered" },
];

export const DEFAULT_OVERVIEW_CHARTS: DashboardChartConfig[] = [
  {
    id: "chart-queries-over-time",
    title: "Queries Over Time",
    subtitle: "DNS query and threat activity over time",
    chartType: "timeseries",
    dataset: "dnsAnalytics",
    metric: "total_queries",
    aggregation: "sum",
    series: [
      { id: "s1", name: "Total Queries", metric: "total_queries", color: "#2F6FED" },
      { id: "s2", name: "Threat Queries", metric: "total_threats", color: "#EF4444" },
    ],
    timeRange: { mode: "global" },
    interval: "auto",
    gridSpan: "full",
  },
  {
    id: "chart-dns-query-volume",
    title: "DNS Query Volume",
    subtitle: "Daily DNS queries over time",
    chartType: "depth-bar",
    dataset: "dnsAnalytics",
    metric: "total_queries",
    aggregation: "sum",
    timeRange: { mode: "global" },
    gridSpan: "half",
  },
  {
    id: "chart-query-distribution",
    title: "Query Distribution",
    subtitle: "Queries segmented by security verdict",
    chartType: "donut",
    dataset: "dnsAnalytics",
    metric: "total_queries",
    aggregation: "count",
    dimension: "verdict",
    timeRange: { mode: "global" },
    gridSpan: "half",
  },
  {
    id: "chart-threat-candlestick",
    title: "Candlestick Threat Activity",
    subtitle: "DNS threat activity and momentum over time",
    chartType: "candlestick",
    dataset: "threats",
    metric: "total_threats",
    aggregation: "count",
    timeRange: { mode: "global" },
    interval: "2h",
    gridSpan: "half",
  },
];
