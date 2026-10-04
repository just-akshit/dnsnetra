import { CircleAlertIcon } from "lucide-react"

export function AuthError({ message }: { message?: string | null }) {
  if (!message) return null
  return (
    <div
      role="alert"
      className="auth-error-in flex items-start gap-2 rounded-[var(--auth-radius)] border border-[var(--auth-danger)]/30 bg-[var(--auth-danger)]/[0.06] px-3.5 py-2.5 text-[0.875rem] text-[var(--auth-danger)]"
    >
      <CircleAlertIcon className="mt-0.5 size-4 shrink-0" />
      <span>{message}</span>
    </div>
  )
}
