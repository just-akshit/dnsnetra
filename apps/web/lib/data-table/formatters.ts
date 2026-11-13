/**
 * DNSNetra Formatting Utilities
 * Standardizes timestamps, metrics, numbers, and labels across all tables and drawers.
 */

/**
 * Strict DNSNetra timestamp formatter.
 * Always formats as `YYYY-MM-DD HH:mm:ss` (UTC/Standard).
 * Never displays GMT, local timezone suffixes, or browser locale variations.
 */
export function formatDnsnetraTimestamp(
  value: string | number | Date | null | undefined
): string {
  if (!value) return "—"

  try {
    const d = value instanceof Date ? value : new Date(value)
    if (isNaN(d.getTime())) return typeof value === "string" ? value : "—"

    const pad = (n: number) => n.toString().padStart(2, "0")

    const year = d.getUTCFullYear()
    const month = pad(d.getUTCMonth() + 1)
    const day = pad(d.getUTCDate())
    const hours = pad(d.getUTCHours())
    const minutes = pad(d.getUTCMinutes())
    const seconds = pad(d.getUTCSeconds())

    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`
  } catch {
    return "—"
  }
}

/**
 * Standard number formatting with digit grouping commas (e.g. 18,421).
 */
export function formatNumber(
  value: number | string | null | undefined
): string {
  if (value === null || value === undefined || value === "") return "—"
  const num = typeof value === "number" ? value : Number(value)
  if (isNaN(num)) return String(value)
  return num.toLocaleString("en-US")
}

/**
 * Standard score or float formatting.
 */
export function formatScore(
  value: number | string | null | undefined,
  digits = 1
): string {
  if (value === null || value === undefined || value === "") return "—"
  const num = typeof value === "number" ? value : Number(value)
  if (isNaN(num)) return String(value)
  return num.toFixed(digits)
}

/**
 * Standard percentage formatting (e.g. 98.4%).
 */
export function formatPercent(
  value: number | string | null | undefined,
  digits = 1
): string {
  if (value === null || value === undefined || value === "") return "—"
  const num = typeof value === "number" ? value : Number(value)
  if (isNaN(num)) return String(value)
  return `${num.toFixed(digits)}%`
}

/**
 * Truncate long domain or hash strings with ellipsis in the middle or end.
 */
export function truncateMiddle(text: string, maxLen = 32): string {
  if (!text || text.length <= maxLen) return text
  const half = Math.floor((maxLen - 3) / 2)
  return `${text.slice(0, half)}...${text.slice(-half)}`
}
