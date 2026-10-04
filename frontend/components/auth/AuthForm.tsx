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
    <div className="flex flex-col gap-8">
      <header className="flex flex-col gap-2">
        <h1 className="auth-brand-font text-[2rem] leading-[1.1] font-semibold tracking-[-0.02em] text-balance text-[var(--auth-ink)]">
          {title}
        </h1>
        <p className="text-[0.9375rem] text-[var(--auth-muted)]">{subtitle}</p>
      </header>
      <form noValidate onSubmit={onSubmit} className="flex flex-col gap-5">
        {children}
      </form>
    </div>
  )
}
