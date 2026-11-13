import Link from "next/link"

/**
 * DNSnetra wordmark in its own dedicated wide space above the form.
 * Uses Stardom Regular (--font-stardom) at 190px with regular (400) weight.
 */
export function AuthBrand({ className = "" }: { className?: string }) {
  return (
    <div className="flex w-full items-center justify-center text-center">
      <Link
        href="/login"
        aria-label="DNSnetra"
        className={`auth-brand-font text-[4.25rem] sm:text-[6.25rem] lg:text-[160px] leading-[0.88] font-normal not-italic tracking-[-0.02em] text-[#0b0f17] no-underline select-none whitespace-nowrap transition-opacity hover:opacity-90 ${className}`}
      >
        DNSnetra
      </Link>
    </div>
  )
}
