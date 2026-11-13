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
    <div className="flex flex-col gap-4 w-full">
      <header className="sr-only">
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </header>
      <form noValidate onSubmit={onSubmit} className="flex flex-col gap-3.5 w-full">
        {children}
      </form>
    </div>
  )
}
