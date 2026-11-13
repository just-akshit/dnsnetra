"use client"

import * as React from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { motion } from "motion/react"
import { toast } from "sonner"
import { AuthApiError, authApi } from "@/lib/auth/api"
import { useCaptcha } from "@/lib/auth/use-captcha"
import { AuthLayout } from "@/components/auth/AuthLayout"
import { AuthForm } from "@/components/auth/AuthForm"
import { UsernameField } from "@/components/auth/UsernameField"
import { PasswordField } from "@/components/auth/PasswordField"
import { CaptchaField } from "@/components/auth/CaptchaField"
import { AuthButton } from "@/components/auth/AuthButton"
import { AuthError } from "@/components/auth/AuthError"

export default function LoginPage() {
  const router = useRouter()
  const captcha = useCaptcha()
  const [username, setUsername] = React.useState("")
  const [password, setPassword] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)
  const [pending, setPending] = React.useState(false)
  const busy = React.useRef(false)

  // Already signed in: skip the form.
  React.useEffect(() => {
    authApi
      .me()
      .then((u) =>
        u && router.replace(u.must_change_password ? "/change-password" : "/dashboard")
      )
      .catch(() => {})
  }, [router])

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    if (busy.current) return
    if (!username.trim() || !password) return setError("Enter your username and password.")
    if (!captcha.challenge) return setError("Verification code could not be loaded. Please click refresh.")
    if (!captcha.answer.trim()) return setError("Enter the verification characters.")

    busy.current = true
    setPending(true)
    setError(null)
    try {
      const result = await authApi.login({
        username: username.trim(),
        password,
        captcha_id: captcha.challenge.captcha_id,
        captcha_answer: captcha.answer.trim(),
      })
      toast.success("Signed in", { id: "auth-login" })
      router.replace(result.user.must_change_password ? "/change-password" : "/dashboard")
    } catch (err) {
      const e2 = err instanceof AuthApiError ? err : null
      const msg = e2?.message ?? "Something went wrong. Please try again."
      setError(msg)
      toast.error(msg, { id: "auth-login" })
      if (!e2 || e2.needsNewCaptcha) captcha.refresh()
      if (e2?.kind === "credentials") setPassword("")
      busy.current = false
      setPending(false)
    }
  }

  const isCaptchaError = Boolean(
    error && (error.toLowerCase().includes("captcha") || error.toLowerCase().includes("verification"))
  )

  return (
    <AuthLayout>
      <AuthForm title="Welcome back" subtitle="Sign in to continue to DNSNetra" onSubmit={onSubmit}>
        <UsernameField value={username} onChange={setUsername} disabled={pending} />
        <PasswordField value={password} onChange={setPassword} disabled={pending} />
        <CaptchaField captcha={captcha} error={isCaptchaError ? error : undefined} disabled={pending} />
        <AuthError message={error} />
        <AuthButton pending={pending} idle="Log in" busy="Logging in..." />
      </AuthForm>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.3, delay: 0.11 }}
        className="mt-4 text-center"
      >
        <Link
          href="/reset-password"
          className="auth-pressable inline-block text-[0.8125rem] font-semibold text-[#181c24] no-underline hover:text-[#437dbf]"
        >
          Forgot password?
        </Link>
      </motion.div>
    </AuthLayout>
  )
}
