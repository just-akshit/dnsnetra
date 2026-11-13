/**
 * Normalizes free-text header search input into an investable entity.
 *
 * Accepts what analysts actually paste:
 *   https://Example.COM/login?x=1  -> example.com
 *   example.com.                   -> example.com
 *   192.168.1.10:53                -> 192.168.1.10
 *   [2001:db8::1]                  -> 2001:db8::1
 */

export type SearchEntity =
  | { kind: "domain"; value: string }
  | { kind: "ip"; value: string }
  | { kind: "invalid"; value: string; reason: string }

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/

const DOMAIN_RE =
  /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/

function isValidIpv6(value: string): boolean {
  if (!value.includes(":")) return false
  try {
    // The URL parser validates bracketless IPv6 literals for us.
    new URL(`http://[${value}]`)
    return true
  } catch {
    return false
  }
}

/**
 * Strips scheme, path, query, fragment, port, trailing dot, and casing.
 * Returns the raw host candidates for classification.
 */
function extractHost(raw: string): string {
  let value = raw.trim().toLowerCase()

  // Remove scheme (https://, dns://, etc.)
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, "")

  // Remove userinfo, then path/query/fragment.
  const at = value.lastIndexOf("@")
  if (at !== -1) value = value.slice(at + 1)
  value = value.split(/[/?#]/, 1)[0]

  // Bracketed IPv6 literal, optionally with a port.
  if (value.startsWith("[")) {
    const end = value.indexOf("]")
    if (end !== -1) return value.slice(1, end)
  }

  // IPv6 without brackets — never strip the colon segments as a port.
  if (value.includes(":")) {
    if (isValidIpv6(value)) return value
    // host:port for IPv4 or domain
    value = value.replace(/:\d+$/, "")
    return value
  }

  return value.replace(/\.+$/, "")
}

export function parseEntityQuery(raw: string): SearchEntity {
  const input = raw.trim()
  if (!input) {
    return { kind: "invalid", value: "", reason: "Enter a domain or IP address." }
  }

  const host = extractHost(input)

  if (!host) {
    return { kind: "invalid", value: input, reason: "Enter a domain or IP address." }
  }

  if (/\s/.test(host)) {
    return { kind: "invalid", value: input, reason: "Spaces are not valid in a domain or IP." }
  }

  if (IPV4_RE.test(host) || isValidIpv6(host)) {
    return { kind: "ip", value: host }
  }

  // Four dot-separated numeric labels are an attempted IPv4, not a domain.
  if (/^\d+(?:\.\d+){3}$/.test(host)) {
    return { kind: "invalid", value: input, reason: "Enter a valid IPv4 address." }
  }

  // A numeric TLD is never a valid domain name.
  if (/^\d+$/.test(host.split(".").pop() ?? "")) {
    return { kind: "invalid", value: input, reason: "Enter a valid domain name." }
  }

  if (DOMAIN_RE.test(host)) {
    return { kind: "domain", value: host }
  }

  return {
    kind: "invalid",
    value: input,
    reason: "Enter a valid domain (example.com) or IP address.",
  }
}

export function entityHref(entity: Extract<SearchEntity, { kind: "domain" | "ip" }>): string {
  return entity.kind === "ip"
    ? `/clients/${encodeURIComponent(entity.value)}`
    : `/domains/${encodeURIComponent(entity.value)}`
}
