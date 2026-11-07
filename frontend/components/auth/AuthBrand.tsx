import Link from "next/link"

/**
 * Brand slot. Typographic wordmark for now; replace the contents of this
 * component with the final logo and every auth screen picks it up.
 */
export function AuthBrand({ className = "" }: { className?: string }) {
  return (
    <div className="flex justify-center text-center">
      <Link
        href="/login"
        aria-label="DNSNetra"
        className={`auth-brand-font text-[2.125rem] sm:text-[2.35rem] leading-none font-bold tracking-[-0.03em] text-[var(--auth-ink)] no-underline transition-opacity hover:opacity-90 ${className}`}
      >
        DNSNetra
      </Link>
    </div>
  )
}
