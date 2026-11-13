"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import { AuthApiError, authApi, validatePassword, type AuthUser } from "@/lib/auth/api"
import { AuthLayout } from "@/components/auth/AuthLayout"
import { AuthForm } from "@/components/auth/AuthForm"
import { PasswordField } from "@/components/auth/PasswordField"
import { AuthButton } from "@/components/auth/AuthButton"
import { AuthError } from "@/components/auth/AuthError"

export default function ChangePasswordPage() {
  const router = useRouter()
  const [user, setUser] = React.useState<AuthUser | null>(null)
  const [current, setCurrent] = React.useState("")
  const [next, setNext] = React.useState("")
  const [confirm, setConfirm] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)
  const [pending, setPending] = React.useState(false)

  React.useEffect(() => {
    authApi
      .me()
      .then((u) => (u ? setUser(u) : router.replace("/login")))
      .catch(() => router.replace("/login"))
  }, [router])

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    if (!user) return
    const policy = validatePassword(next, user.username)
    if (policy) return setError(policy)
    if (next !== confirm) return setError("The new passwords do not match.")
    if (current === next) return setError("Choose a password different from your current one.")

    setPending(true)
    setError(null)
    try {
      await authApi.changePassword({
        current_password: current,
        new_password: next,
        confirm_password: confirm,
      })
      router.replace("/dashboard")
    } catch (err) {
      const e2 = err instanceof AuthApiError ? err : null
      setError(e2?.message ?? "Could not update your password. Please try again.")
      setPending(false)
    }
  }

  return (
    <AuthLayout>
      <AuthForm
        title="Set a new password"
        subtitle="Your administrator issued a temporary password. Replace it to continue."
        onSubmit={onSubmit}
      >
        <PasswordField
          id="current-password"
          label="Current password"
          value={current}
          onChange={setCurrent}
          autoComplete="current-password"
          disabled={pending}
        />
        <PasswordField
          id="new-password"
          label="New password"
          value={next}
          onChange={setNext}
          autoComplete="new-password"
          disabled={pending}
        />
        <PasswordField
          id="confirm-password"
          label="Confirm new password"
          value={confirm}
          onChange={setConfirm}
          autoComplete="new-password"
          disabled={pending}
        />
        <AuthError message={error} />
        <AuthButton pending={pending} idle="Update password" busy="Updating..." />
      </AuthForm>
    </AuthLayout>
  )
}
