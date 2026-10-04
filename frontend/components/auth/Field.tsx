import * as React from "react"

export const authInput =
  "h-11 rounded-[var(--auth-radius)] border-[var(--auth-line)] bg-white px-3.5 text-[0.9375rem] text-[var(--auth-ink)] placeholder:text-[var(--auth-muted)]/80 focus-visible:border-[var(--auth-accent)] focus-visible:ring-[var(--auth-accent)]/20 aria-invalid:border-[var(--auth-danger)] aria-invalid:ring-[var(--auth-danger)]/15 md:text-[0.9375rem]"

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
      <label htmlFor={id} className="text-sm font-medium text-[var(--auth-ink)]">
        {label}
      </label>
      {children}
      {hint && !error && (
        <p id={`${id}-hint`} className="text-[0.8125rem] text-[var(--auth-muted)]">
          {hint}
        </p>
      )}
      {error && (
        <p id={`${id}-error`} className="auth-error-in text-[0.8125rem] text-[var(--auth-danger)]">
          {error}
        </p>
      )}
    </div>
  )
}
