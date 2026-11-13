/* eslint-disable @next/next/no-img-element -- backend returns a data: URL */
import { RefreshCwIcon } from "lucide-react"
import { Input } from "@/components/ui/input"
import type { CaptchaState } from "@/lib/auth/use-captcha"
import { authInput, describedBy } from "./Field"

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
    <div className="flex flex-col gap-1.5">
      <label
        htmlFor="captcha-answer"
        className="text-[0.8125rem] font-medium tracking-[-0.005em] text-[#262b36]"
      >
        Verification
      </label>
      <div className="flex items-stretch gap-2.5 h-14">
        <div className="relative flex h-full flex-1 items-center justify-center overflow-hidden rounded-[11px] border border-transparent bg-[#f3f4f6] p-0">
          {challenge && !loading ? (
            <img
              src={challenge.image}
              alt="Verification: type the characters shown"
              className="h-full w-full object-contain select-none"
            />
          ) : (
            <span
              className="font-mono text-[0.75rem] uppercase tracking-[0.08em] text-[#68707c]"
              role="status"
            >
              {failed ? "Verification unavailable" : "CAPTCHA"}
            </span>
          )}
        </div>
        <button
          type="button"
          onClick={refresh}
          disabled={loading || disabled}
          aria-label="Request a new verification code"
          title="Get a new verification challenge"
          className="auth-pressable flex h-full w-14 shrink-0 items-center justify-center rounded-[11px] border border-transparent bg-[#f3f4f6] text-[#525866] hover:bg-[#e8eaef] hover:text-[#0b0f17] disabled:opacity-50 cursor-pointer"
        >
          <RefreshCwIcon className={`size-4 ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>
      <div className="flex flex-col gap-1">
        <label htmlFor="captcha-answer" className="sr-only">
          CAPTCHA characters
        </label>
        <Input
          id="captcha-answer"
          name="captcha-answer"
          value={answer}
          onChange={(e) => setAnswer(e.target.value)}
          placeholder={
            failed
              ? "Verification unavailable"
              : loading
                ? "Loading verification..."
                : "Enter the characters shown"
          }
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          maxLength={20}
          disabled={disabled || loading || !challenge}
          aria-invalid={!!error}
          aria-describedby={describedBy("captcha-answer", undefined, error)}
          className={`${authInput} font-mono tracking-[0.04em] placeholder:font-sans placeholder:tracking-normal`}
        />
        {error && (
          <p
            id="captcha-answer-error"
            className="auth-error-in text-[0.75rem] font-medium text-[var(--auth-danger)]"
          >
            {error}
          </p>
        )}
      </div>
    </div>
  )
}
