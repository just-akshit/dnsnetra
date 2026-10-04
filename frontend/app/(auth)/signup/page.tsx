"use client"

import * as React from "react"
import Link from "next/link"
import { AuthApiError, authApi, validatePassword, validateUsername } from "@/lib/auth/api"
import { useCaptcha } from "@/lib/auth/use-captcha"
import { AuthLayout } from "@/components/auth/AuthLayout"
import { AuthForm } from "@/components/auth/AuthForm"
import { UsernameField } from "@/components/auth/UsernameField"
import { PasswordField } from "@/components/auth/PasswordField"
import { ConfirmPasswordField } from "@/components/auth/ConfirmPasswordField"
import { CaptchaField } from "@/components/auth/CaptchaField"
import { AuthButton } from "@/components/auth/AuthButton"
import { AuthError } from "@/components/auth/AuthError"
import { AuthFooter } from "@/components/auth/AuthFooter"

type Errors = { username?: string; password?: string; confirm?: string; captcha?: string }

export default function SignupPage() {
  const captcha = useCaptcha()
  const [username, setUsername] = React.useState("")
  const [password, setPassword] = React.useState("")
  const [confirm, setConfirm] = React.useState("")
  const [errors, setErrors] = React.useState<Errors>({})
  const [error, setError] = React.useState<string | null>(null)
  const [pending, setPending] = React.useState(false)
  const [done, setDone] = React.useState(false)
  const busy = React.useRef(false)

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    if (busy.current) return
    const next: Errors = {
      username: validateUsername(username) ?? undefined,
      password: validatePassword(password, username) ?? undefined,
      confirm: !confirm ? "Re-enter your password" : confirm !== password ? "Passwords don't match" : undefined,
      captcha: !captcha.answer.trim() ? "Enter the CAPTCHA characters" : undefined,
    }
    setErrors(next)
    setError(null)
    if (Object.values(next).some(Boolean) || !captcha.challenge) return

    busy.current = true
    setPending(true)
    try {
      await authApi.signup({
        username: username.trim(),
        password,
        confirm_password: confirm,
        captcha_id: captcha.challenge.captcha_id,
        captcha_answer: captcha.answer.trim(),
      })
      setPassword("")
      setConfirm("")
      setDone(true)
    } catch (err) {
      const e2 = err instanceof AuthApiError ? err : null
      if (e2?.kind === "taken") setErrors({ username: e2.message })
      else setError(e2?.message ?? "Something went wrong. Please try again.")
      if (!e2 || e2.needsNewCaptcha) captcha.refresh()
      busy.current = false
      setPending(false)
    }
  }

  if (done) {
    return (
      <AuthLayout>
        <div className="flex flex-col gap-8" role="status">
          <header className="flex flex-col gap-3">
            <h1 className="auth-brand-font text-[2rem] leading-[1.1] font-semibold tracking-[-0.02em] text-[var(--auth-ink)]">
              Request submitted
            </h1>
            <p className="text-[0.9375rem] text-[var(--auth-ink)]">
              Your DNSNetra account has been created and is awaiting administrator approval.
            </p>
            <p className="text-[0.9375rem] text-[var(--auth-muted)]">
              You will be able to sign in after an administrator approves your account.
            </p>
          </header>
          <Link
            href="/login"
            className="flex h-12 w-full items-center justify-center rounded-full bg-[var(--auth-ink)] text-[0.9375rem] font-medium text-white no-underline transition-colors hover:bg-[var(--auth-accent)]"
          >
            Back to sign in
          </Link>
        </div>
      </AuthLayout>
    )
  }

  return (
    <AuthLayout>
      <AuthForm title="Create your DNSNetra account" subtitle="Request access to DNSNetra" onSubmit={onSubmit}>
        <UsernameField
          value={username}
          onChange={setUsername}
          error={errors.username}
          hint="3 to 50 characters: letters, numbers, dot, dash, underscore"
          disabled={pending}
        />
        <PasswordField
          value={password}
          onChange={setPassword}
          error={errors.password}
          hint="8 or more characters, with a letter and a number or symbol"
          autoComplete="new-password"
          placeholder="Create a password"
          disabled={pending}
        />
        <ConfirmPasswordField value={confirm} onChange={setConfirm} error={errors.confirm} disabled={pending} />
        <CaptchaField captcha={captcha} error={errors.captcha} disabled={pending} />
        <AuthError message={error} />
        <AuthButton pending={pending} idle="Create account" busy="Creating account..." />
      </AuthForm>
      <AuthFooter prompt="Already have an account?" label="Sign in" href="/login" />
    </AuthLayout>
  )
}
