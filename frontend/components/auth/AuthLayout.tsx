import * as React from "react"
import { AuthBrand } from "./AuthBrand"
import { AuthVisual } from "./AuthVisual"

/**
 * Split card on desktop (visual | form). Below lg it is one column:
 * wordmark, form, then a small visual.
 */
export function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="auth-theme min-h-dvh flex items-center justify-center p-3 sm:p-5 lg:p-7">
      <div className="mx-auto grid min-h-[calc(100dvh-1.5rem)] w-full max-w-[1260px] overflow-hidden rounded-[2rem] bg-[var(--auth-visual)] lg:min-h-[calc(100dvh-3.5rem)] lg:grid-cols-[1.08fr_1fr] shadow-xs border border-[var(--auth-line)]/50">
        {/* Left: static artwork */}
        <div className="relative hidden overflow-hidden bg-[var(--auth-visual)] lg:block">
          <AuthVisual priority />
        </div>

        {/* Right: Centered Authentication Panel */}
        <main className="m-2 flex flex-col items-center justify-center rounded-[1.6rem] bg-[var(--auth-panel)] px-6 py-12 sm:px-10 lg:px-12">
          <div className="mx-auto flex w-full max-w-[24rem] flex-1 flex-col items-center justify-center gap-7 sm:gap-8 my-auto">
            <AuthBrand />
            {children}
          </div>
          <div className="relative mx-auto mt-8 h-36 w-full max-w-[22rem] overflow-hidden rounded-xl bg-[var(--auth-visual)] lg:hidden">
            <AuthVisual />
          </div>
        </main>
      </div>
    </div>
  )
}
