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
      className="auth-pressable mt-1.5 h-11 w-full rounded-[11px] bg-[#437dbf] text-[0.875rem] font-semibold tracking-[-0.01em] text-white shadow-xs hover:bg-[#366aa6] active:bg-[#2d5a8e] disabled:opacity-60 cursor-pointer"
    >
      {pending ? busy : idle}
    </Button>
  )
}
