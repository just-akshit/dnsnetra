import Image from "next/image"

/**
 * Static print for the auth panel. The paper tone of the image is mirrored in
 * --auth-visual so the artwork bleeds into the card with no visible seam.
 * Swap /public/assets/dnsnetra-art.jpg (or this component) for brand art later.
 */
export function AuthVisual({ priority = false }: { priority?: boolean }) {
  return (
    <Image
      src="/assets/dnsnetra-art.jpg"
      alt=""
      fill
      priority={priority}
      sizes="(min-width: 1024px) 50vw, 100vw"
      className="select-none object-cover"
    />
  )
}
