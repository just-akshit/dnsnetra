import * as React from "react"
import { AuthBrand } from "./AuthBrand"
import { AuthVisual } from "./AuthVisual"

/**
 * Split card on desktop (visual | form). Below lg it is one column:
 * wordmark, form, then a small visual.
 */
export function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="auth-theme min-h-dvh p-3 lg:p-5">
      <div className="mx-auto grid min-h-[calc(100dvh-1.5rem)] max-w-[1280px] overflow-hidden rounded-[1.75rem] bg-[var(--auth-visual)] lg:min-h-[calc(100dvh-2.5rem)] lg:grid-cols-[1.05fr_1fr]">
        <div className="relative hidden lg:block">
          <AuthVisual />
          <p className="absolute bottom-8 left-9 text-sm text-[var(--auth-muted)]">
            Secure DNS intelligence platform
          </p>
        </div>

        <main className="m-1.5 flex flex-col rounded-[1.4rem] bg-[var(--auth-panel)] px-6 py-10 sm:px-12 lg:m-2">
          <div className="mx-auto flex w-full max-w-[22rem] flex-1 flex-col justify-center gap-9">
            <AuthBrand />
            {children}
          </div>
          <div className="mx-auto mt-10 h-36 w-full max-w-[22rem] overflow-hidden rounded-xl bg-[var(--auth-visual)] lg:hidden">
            <AuthVisual compact />
          </div>
        </main>
      </div>
    </div>
  )
}
