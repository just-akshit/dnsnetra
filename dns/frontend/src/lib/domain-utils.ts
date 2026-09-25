/**
 * Domain & Search Input Normalization and Structural Validation Utilities.
 * Adheres strictly to RFC domain structure without a hardcoded TLD allowlist,
 * preserving support for internal domains (.internal, .local, .test), IDN/punycode,
 * and separating IP address indicators.
 */

export interface DomainValidationResult {
  valid: boolean;
  normalized: string;
  isIp: boolean;
  error?: string;
}

/**
 * Checks if a string is a structurally valid IPv4 address (each octet 0-255).
 */
export function isIpv4Address(input: string): boolean {
  const trimmed = input.trim();
  const parts = trimmed.split(".");
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    const num = Number(part);
    if (num < 0 || num > 255) return false;
    // Disallow leading zeros unless the octet is simply "0"
    if (part.length > 1 && part.startsWith("0")) return false;
  }
  return true;
}

/**
 * Checks if a string is a structurally valid IPv6 address.
 */
export function isIpv6Address(input: string): boolean {
  const trimmed = input.trim().replace(/^\[|\]$/g, "");
  // Simple & robust standard IPv6 structural pattern
  const ipv6Regex =
    /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/;
  return ipv6Regex.test(trimmed);
}

/**
 * Checks if input is an IPv4 or IPv6 address.
 */
export function isIpAddress(input: string): boolean {
  const cleaned = input.trim();
  return isIpv4Address(cleaned) || isIpv6Address(cleaned);
}

/**
 * Safely extracts and normalizes the host/domain from user input.
 * Handles whitespace, case, trailing FQDN dot, and URL-like schemes without brittle regexes.
 */
export function normalizeDomainInput(raw: string): string {
  if (!raw) return "";
  let target = raw.trim();

  // If URL scheme or leading slash is present, use URL parser safely
  if (target.includes("://") || target.startsWith("//")) {
    try {
      const url = new URL(target.startsWith("//") ? `http:${target}` : target);
      target = url.hostname;
    } catch {
      // Fallback: strip scheme and extract first path component
      target = target.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "");
      target = target.split("/")[0].split("?")[0].split("#")[0];
    }
  } else {
    // Strip any path, query, or hash if pasted like domain.com/path?query
    target = target.split("/")[0].split("?")[0].split("#")[0];
  }

  // Strip port if not an IPv6 address (e.g. example.com:8080 or 1.2.3.4:80)
  if (!target.startsWith("[") && target.includes(":") && !target.includes("::")) {
    const colonIdx = target.indexOf(":");
    // Only strip port if after colon is purely digits
    if (/^:\d+$/.test(target.slice(colonIdx))) {
      target = target.slice(0, colonIdx);
    }
  }

  // Strip trailing FQDN root dots: "google.com." -> "google.com"
  target = target.replace(/\.+$/, "");

  return target.toLowerCase();
}

/**
 * Validates domain syntax structurally per RFC specifications.
 * - 1 to 63 characters per label.
 * - Alphanumeric characters with internal hyphens (no leading/trailing hyphen per label).
 * - No empty labels (rejects consecutive dots).
 * - Overall length <= 253 characters.
 * - At least one dot (has at least 2 labels: apex + TLD/suffix).
 * - Does NOT enforce a hardcoded TLD list, preserving internal, testing, and punycode domains.
 */
export function isValidDomainStructure(domain: string): boolean {
  if (!domain || typeof domain !== "string") return false;
  const trimmed = domain.trim().toLowerCase();

  // Strip single root trailing dot if present before checking
  const cleaned = trimmed.endsWith(".") ? trimmed.slice(0, -1) : trimmed;

  if (cleaned.length === 0 || cleaned.length > 253) return false;

  // Domain must contain at least one dot to separate name from suffix/tld
  const labels = cleaned.split(".");
  if (labels.length < 2) return false;

  // Single-label or empty labels are invalid
  for (let i = 0; i < labels.length; i++) {
    const label = labels[i];
    // Label length 1–63 chars
    if (label.length === 0 || label.length > 63) return false;

    // Must not start or end with hyphen
    if (label.startsWith("-") || label.endsWith("-")) return false;

    // Punycode labels (e.g. xn--...) or standard labels: alphanumeric and hyphen
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(label)) {
      return false;
    }
  }

  // Last label (TLD/suffix) must not be purely numeric per RFC
  const tld = labels[labels.length - 1];
  if (/^\d+$/.test(tld)) {
    return false;
  }

  return true;
}

/**
 * Validates and normalizes analyst search input.
 * Differentiates valid domains, valid IP addresses, and invalid inputs.
 */
export function validateDomainSearchInput(rawInput: string): DomainValidationResult {
  const trimmed = (rawInput || "").trim();
  if (!trimmed) {
    return {
      valid: false,
      normalized: "",
      isIp: false,
      error: "Please enter a valid domain.",
    };
  }

  // Check if user input is an IP address
  if (isIpAddress(trimmed)) {
    return {
      valid: true,
      normalized: trimmed.replace(/^\[|\]$/g, ""),
      isIp: true,
    };
  }

  // Normalize candidate domain
  const normalized = normalizeDomainInput(trimmed);

  // If normalized turns out to be an IP (e.g. http://192.168.1.1:8080)
  if (isIpAddress(normalized)) {
    return {
      valid: true,
      normalized,
      isIp: true,
    };
  }

  if (isValidDomainStructure(normalized)) {
    return {
      valid: true,
      normalized,
      isIp: false,
    };
  }

  return {
    valid: false,
    normalized,
    isIp: false,
    error: "Please enter a valid domain.",
  };
}
