"use client"

import * as React from "react"
import { MotionConfig, motion } from "motion/react"
import { AuthBrand } from "./AuthBrand"
import { AuthVisual } from "./AuthVisual"

/**
 * Split-screen layout:
 * - Left: Edge-to-edge full-height RetroDither artwork taking 100% of the left side.
 * - Right: Separate wide display space for the 190px Stardom Regular `DNSnetra` title,
 *   followed by the compact, centered form skeleton below.
 */
export function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <MotionConfig transition={{ type: "spring", bounce: 0, duration: 0.4 }}>
      <div className="auth-theme min-h-dvh w-full bg-white lg:grid lg:grid-cols-[48%_52%] xl:grid-cols-[50%_50%]">
        {/* Left: Edge-to-edge full-screen RetroDither artwork panel */}
        <aside
          aria-label="Retro dither artwork"
          className="relative hidden lg:sticky lg:top-0 lg:block lg:h-dvh lg:w-full overflow-hidden bg-[#1a2b34]"
        >
          <AuthVisual />
        </aside>

        {/* Right: Separate wide space for 190px Stardom DNSnetra title + compact form skeleton */}
        <main className="relative flex min-h-dvh w-full flex-col items-center justify-center overflow-x-hidden bg-white px-4 py-8 sm:px-6 lg:px-8">
          {/* Separate unconstrained space for the 160px Stardom Regular DNSnetra title */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ type: "spring", bounce: 0, duration: 0.42 }}
            className="mb-[50px] flex w-full items-center justify-center"
          >
            <AuthBrand />
          </motion.div>

          {/* Balanced form skeleton column */}
          <motion.div
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ type: "spring", bounce: 0, duration: 0.36, delay: 0.055 }}
            className="mx-auto flex w-full max-w-[420px] flex-col"
          >
            {children}
          </motion.div>

          {/* Mobile compact dither banner below lg */}
          <div className="relative mx-auto mt-8 h-48 w-full max-w-[420px] overflow-hidden rounded-2xl lg:hidden">
            <AuthVisual />
          </div>
        </main>
      </div>
    </MotionConfig>
  )
}
