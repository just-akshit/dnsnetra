"use client"

import { RetroDither } from "@/components/canvasui/RetroDither"

/**
 * Edge-to-edge RetroDither (Bayer-only) artwork panel using the single
 * cloud-and-mountain photograph (/assets/dither-slide-2.jpg).
 */
export function AuthVisual() {
  return (
    <div className="relative size-full min-h-full select-none overflow-hidden bg-[#1a2b34]">
      <RetroDither
        className="size-full min-h-full"
        pattern="bayer"
        pixelSize={2}
        levels={4}
        radius={0.48}
        softness={0.9}
        darkColor={[0.04, 0.07, 0.09]}
        lightColor={[0.96, 0.78, 0.64]}
        colorize={0.18}
        contrast={0.62}
        brightness={0}
        strength={0.82}
        baseStrength={0.22}
        scanlines={0}
        trail={0.4}
        degauss={0.8}
        followSpeed={3.5}
      >
        <div className="relative size-full min-h-full overflow-hidden bg-[#1a2b34]">
          {/* eslint-disable-next-line @next/next/no-img-element -- direct <img> element so RetroDither canvas draws the image synchronously */}
          <img
            src="/assets/dither-slide-2.jpg"
            alt=""
            crossOrigin="anonymous"
            className="pointer-events-none absolute inset-0 size-full select-none object-cover object-center"
          />
        </div>
      </RetroDither>
    </div>
  )
}
