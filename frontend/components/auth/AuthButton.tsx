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
      className="h-12 w-full rounded-full bg-[var(--auth-ink)] text-[0.9375rem] font-medium text-white transition-colors hover:bg-[var(--auth-accent)] disabled:opacity-70"
    >
      {pending ? busy : idle}
    </Button>
  )
}
