export function formatDate(
  date: Date | string | number | null | undefined,
  opts?: Intl.DateTimeFormatOptions,
): string {
  if (!date) return "-";
  return formatTimestampParts(date).date;
}

/**
 * Standard timestamp formatter: YYYY-MM-DD HH:mm:ss
 * Strictly canonical, preserving API representations with NO timezone shift,
 * NO timezone suffixes (no GMT, no UTC, no LOC), and NO relative timestamps.
 */
export function formatDateTime(
  date: Date | string | number | null | undefined,
): string {
  return formatFullTimestamp(date);
}

/**
 * Full-precision timestamp formatter: YYYY-MM-DD HH:mm:ss
 * Presentation-only, string-preserving, with NO timezone suffixes (no GMT, no UTC, no relative time).
 */
export function formatFullTimestamp(
  date: Date | string | number | null | undefined,
): string {
  if (!date) return "-";
  return formatTimestampParts(date).full;
}

/**
 * Returns separated date and time strings for structured table cells: YYYY-MM-DD HH:mm:ss
 * Never converts through the browser's local timezone.
 */
export function formatTimestampParts(
  date: Date | string | number | null | undefined,
): { date: string; time: string; full: string } {
  if (!date) return { date: "-", time: "-", full: "-" };
  try {
    const rawStr =
      typeof date === "string"
        ? date.trim()
        : date instanceof Date
          ? date.toISOString()
          : typeof date === "number"
            ? new Date(date).toISOString()
            : String(date).trim();

    // Match YYYY-MM-DD followed by T or space, then HH:mm and optional :ss
    const match = rawStr.match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})(?::(\d{2}))?/);
    if (match) {
      const dateStr = match[1];
      const hourMin = match[2];
      const secStr = match[3] ?? "00";
      const timeStr = `${hourMin}:${secStr}`;
      return { date: dateStr, time: timeStr, full: `${dateStr} ${timeStr}` };
    }

    // Fallback if rawStr does not match standard ISO (e.g. invalid date string)
    return { date: rawStr, time: "", full: rawStr };
  } catch {
    return { date: String(date), time: "", full: String(date) };
  }
}

/**
 * Standardized to always return absolute YYYY-MM-DD HH:mm:ss.
 * Relative timestamps (e.g. "just now", "2m ago") are strictly prohibited.
 */
export function formatRelativeTime(
  date: Date | string | number | null | undefined,
): string {
  return formatFullTimestamp(date);
}

export function formatNumber(
  value: number | null | undefined,
  opts?: Intl.NumberFormatOptions,
): string {
  if (value === null || value === undefined) return "-";
  return new Intl.NumberFormat("en-US", opts).format(value);
}

export function formatCompactNumber(
  value: number | null | undefined,
): string {
  if (value === null || value === undefined) return "-";
  return new Intl.NumberFormat("en-US", { notation: "compact" }).format(value);
}
