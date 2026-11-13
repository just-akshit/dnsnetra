"use client"

import * as React from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { AnimatePresence, motion } from "motion/react"
import { CheckCircle2Icon } from "lucide-react"
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
import { Field, authInput } from "@/components/auth/Field"
import { Input } from "@/components/ui/input"

export default function ResetPasswordPage() {
  const router = useRouter()
  const captcha = useCaptcha()
  const [username, setUsername] = React.useState("")
  const [code, setCode] = React.useState("")
  const [password, setPassword] = React.useState("")
  const [confirm, setConfirm] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)
  const [notice, setNotice] = React.useState<string | null>(null)
  const [pending, setPending] = React.useState(false)
  const busy = React.useRef(false)

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    if (busy.current) return
    if (!username.trim() || !code.trim()) return setError("Enter your username and reset code.")
    if (password !== confirm) return setError("Passwords do not match.")
    if (!captcha.challenge) return setError("Verification code could not be loaded. Please click refresh.")
    if (!captcha.answer.trim()) return setError("Enter the verification characters.")

    busy.current = true
    setPending(true)
    setError(null)
    try {
      const result = await authApi.resetPassword({
        username: username.trim(),
        code: code.trim(),
        new_password: password,
        confirm_password: confirm,
        captcha_id: captcha.challenge.captcha_id,
        captcha_answer: captcha.answer.trim(),
      })
      setNotice(result.message)
      toast.success(result.message, { id: "auth-reset" })
      window.setTimeout(() => router.replace("/login"), 1200)
    } catch (err) {
      const authError = err instanceof AuthApiError ? err : null
      const msg = authError?.message ?? "Something went wrong. Please try again."
      setError(msg)
      toast.error(msg, { id: "auth-reset" })
      if (!authError || authError.needsNewCaptcha) captcha.refresh()
      busy.current = false
      setPending(false)
    }
  }

  const isCaptchaError = Boolean(
    error && (error.toLowerCase().includes("captcha") || error.toLowerCase().includes("verification"))
  )

  return (
    <AuthLayout>
      <AuthForm
        title="Set a new password"
        subtitle="Enter the one-time code from your administrator"
        onSubmit={onSubmit}
      >
        <UsernameField value={username} onChange={setUsername} disabled={pending} />
        <Field id="reset-code" label="Reset code" hint="Expires 15 minutes after it was issued.">
          <Input
            id="reset-code"
            name="reset-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Paste your reset code"
            autoComplete="one-time-code"
            autoCapitalize="none"
            spellCheck={false}
            disabled={pending}
            className={`${authInput} font-mono tracking-[0.04em] placeholder:font-sans placeholder:tracking-normal`}
          />
        </Field>
        <PasswordField
          id="new-password"
          label="New password"
          value={password}
          onChange={setPassword}
          autoComplete="new-password"
          placeholder="Choose a new password"
          disabled={pending}
        />
        <PasswordField
          id="confirm-password"
          label="Confirm new password"
          value={confirm}
          onChange={setConfirm}
          autoComplete="new-password"
          placeholder="Repeat the new password"
          disabled={pending}
        />
        <CaptchaField
          captcha={captcha}
          error={isCaptchaError ? error : undefined}
          disabled={pending}
        />
        <AuthError message={error} />
        <AnimatePresence mode="popLayout" initial={false}>
          {notice && (
            <motion.p
              key={notice}
              role="status"
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ type: "spring", bounce: 0, duration: 0.24 }}
              className="flex items-center gap-2.5 rounded-[12px] border border-emerald-600/25 bg-emerald-500/10 px-4 py-3 text-sm font-medium text-emerald-800"
            >
              <CheckCircle2Icon className="size-4 shrink-0 text-emerald-700" />
              <span>{notice}</span>
            </motion.p>
          )}
        </AnimatePresence>
        <AuthButton pending={pending} idle="Set new password" busy="Saving..." />
      </AuthForm>

      <motion.div
        initial={{ opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ type: "spring", bounce: 0, duration: 0.34, delay: 0.11 }}
        className="mt-4 text-center"
      >
        <p className="text-[0.8125rem] text-[#68707c]">
          Remember It?
          <Link
            href="/login"
            className="ml-1.5 font-semibold text-[#181c24] underline-offset-4 hover:text-[#437dbf] hover:underline"
          >
            Back to sign in
          </Link>
        </p>
      </motion.div>
    </AuthLayout>
  )
}
