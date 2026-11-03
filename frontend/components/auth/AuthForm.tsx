import * as React from "react"

export function AuthForm({
  title,
  subtitle,
  onSubmit,
  children,
}: {
  title: string
  subtitle: string
  onSubmit: (e: React.FormEvent<HTMLFormElement>) => void
  children: React.ReactNode
}) {
  return (
    <div className="flex flex-col gap-7 w-full">
      <header className="flex flex-col items-center text-center gap-1.5">
        <h1 className="auth-brand-font text-[1.75rem] sm:text-[1.875rem] leading-[1.2] font-semibold tracking-[-0.025em] text-balance text-[var(--auth-ink)]">
          {title}
        </h1>
        <p className="text-[0.9375rem] text-[var(--auth-muted)] text-balance">
          {subtitle}
        </p>
      </header>
      <form noValidate onSubmit={onSubmit} className="flex flex-col gap-4.5 w-full">
        {children}
      </form>
    </div>
  )
}
