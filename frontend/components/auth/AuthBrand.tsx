import Link from "next/link"

/**
 * Brand slot. Typographic wordmark for now; replace the contents of this
 * component with the final logo and every auth screen picks it up.
 */
export function AuthBrand({ className = "" }: { className?: string }) {
  return (
    <Link
      href="/login"
      aria-label="DNSNetra"
      className={`auth-brand-font inline-block text-[1.75rem] leading-none font-semibold tracking-[-0.02em] text-[var(--auth-ink)] no-underline ${className}`}
    >
      DNSNetra
    </Link>
  )
}
