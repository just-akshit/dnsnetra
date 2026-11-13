import * as React from "react"

/**
 * Compact, refined soft-gray input boxes.
 * Uses Plus Jakarta Sans (--font-auth-sans).
 * 38px (h-9.5) height, 10px radius, 12px horizontal padding.
 */
export const authInput =
  "h-11 w-full rounded-[11px] border border-transparent bg-[#f3f4f6] px-3.5 text-[0.875rem] font-normal leading-normal text-[#0b0f17] placeholder:text-[#7b818f] transition-all duration-150 hover:bg-[#eceef2] focus-visible:border-[#437dbf] focus-visible:bg-white focus-visible:ring-3 focus-visible:ring-[#437dbf]/18 aria-invalid:border-[var(--auth-danger)] aria-invalid:bg-white aria-invalid:ring-[var(--auth-danger)]/15 md:text-[0.875rem]"

export const describedBy = (id: string, hint?: string, error?: string | null) =>
  [error ? `${id}-error` : null, hint ? `${id}-hint` : null].filter(Boolean).join(" ") || undefined

/** Label above, optional hint, inline error. Shared by every field. */
export function Field({
  id,
  label,
  hint,
  error,
  children,
}: {
  id: string
  label: string
  hint?: string
  error?: string | null
  children: React.ReactNode
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <label
        htmlFor={id}
        className="text-[0.8125rem] font-medium tracking-[-0.005em] text-[#262b36]"
      >
        {label}
      </label>
      {children}
      {hint && !error && (
        <p id={`${id}-hint`} className="text-[0.75rem] leading-snug text-[#68707c]">
          {hint}
        </p>
      )}
      {error && (
        <p id={`${id}-error`} className="auth-error-in text-[0.78125rem] font-medium text-[var(--auth-danger)]">
          {error}
        </p>
      )}
    </div>
  )
}
