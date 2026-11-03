import * as React from "react"
import { Button } from "@/components/ui/button"

export function AuthButton({
  pending,
  idle,
  busy,
}: {
  pending: boolean
  idle: string
  busy: string
}) {
  return (
    <Button
      type="submit"
      disabled={pending}
      aria-busy={pending}
      className="h-11 sm:h-11.5 w-full rounded-[var(--auth-radius)] bg-[var(--auth-ink)] text-[0.9375rem] font-medium text-white transition-colors hover:bg-[var(--auth-accent)] disabled:opacity-60 cursor-pointer shadow-xs"
    >
      {pending ? busy : idle}
    </Button>
  )
}
