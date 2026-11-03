/* eslint-disable @next/next/no-img-element -- backend returns a data: URL */
import { RefreshCwIcon } from "lucide-react"
import { Input } from "@/components/ui/input"
import type { CaptchaState } from "@/lib/auth/use-captcha"
import { Field, authInput, describedBy } from "./Field"

export function CaptchaField({
  captcha,
  error,
  disabled,
}: {
  captcha: CaptchaState
  error?: string | null
  disabled?: boolean
}) {
  const { challenge, loading, failed, answer, setAnswer, refresh } = captcha
  return (
    <div className="flex flex-col gap-2">
      <label htmlFor="captcha-answer" className="text-sm font-medium text-[var(--auth-ink)]">
        Verification
      </label>
      <div className="flex items-stretch gap-2 h-14">
        <div className="flex h-full flex-1 items-center justify-center overflow-hidden rounded-[var(--auth-radius)] border border-[var(--auth-line)] bg-white p-1">
          {challenge && !loading ? (
            <img src={challenge.image} alt="Verification: type the characters shown" className="h-full w-full object-contain" />
          ) : (
            <span className="text-[0.8125rem] text-[var(--auth-muted)]" role="status">
              {failed ? "Couldn't load verification" : "Loading..."}
            </span>
          )}
        </div>
        <button
          type="button"
          onClick={refresh}
          disabled={loading || disabled}
          aria-label="Request a new verification code"
          title="Get a new verification challenge"
          className="flex h-full w-14 shrink-0 aspect-square items-center justify-center rounded-[var(--auth-radius)] border border-[var(--auth-line)] bg-white text-[var(--auth-muted)] transition-colors hover:text-[var(--auth-ink)] hover:border-[var(--auth-ink)]/30 disabled:opacity-50 cursor-pointer"
        >
          <RefreshCwIcon className="size-4" />
        </button>
      </div>
      <div className="flex flex-col gap-1.5">
        <label htmlFor="captcha-answer" className="sr-only">
          CAPTCHA characters
        </label>
        <Input
          id="captcha-answer"
          name="captcha-answer"
          value={answer}
          onChange={(e) => setAnswer(e.target.value)}
          placeholder={failed ? "Verification unavailable" : loading ? "Loading verification..." : "Enter the characters shown"}
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          maxLength={20}
          disabled={disabled || loading || !challenge}
          aria-invalid={!!error}
          aria-describedby={describedBy("captcha-answer", undefined, error)}
          className={authInput}
        />
        {error && (
          <p id="captcha-answer-error" className="auth-error-in text-[0.8125rem] text-[var(--auth-danger)]">
            {error}
          </p>
        )}
      </div>
    </div>
  )
}
