"use client"

import * as React from "react"
import { EyeIcon, EyeOffIcon } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Field, authInput, describedBy } from "./Field"

export function PasswordField({
  id = "password",
  label = "Password",
  value,
  onChange,
  error,
  hint,
  autoComplete = "current-password",
  placeholder = "Enter your password",
  disabled,
}: {
  id?: string
  label?: string
  value: string
  onChange: (v: string) => void
  error?: string | null
  hint?: string
  autoComplete?: "current-password" | "new-password"
  placeholder?: string
  disabled?: boolean
}) {
  const [shown, setShown] = React.useState(false)
  return (
    <Field id={id} label={label} error={error} hint={hint}>
      <div className="relative">
        <Input
          id={id}
          name={id}
          type={shown ? "text" : "password"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          autoComplete={autoComplete}
          disabled={disabled}
          aria-invalid={!!error}
          aria-describedby={describedBy(id, hint, error)}
          className={`${authInput} pr-10`}
        />
        <button
          type="button"
          onClick={() => setShown((s) => !s)}
          aria-label={shown ? "Hide password" : "Show password"}
          aria-pressed={shown}
          className="auth-pressable absolute inset-y-0 right-0 flex w-10 items-center justify-center rounded-r-[11px] text-[#68707c] hover:text-[#0b0f17] cursor-pointer"
        >
          {shown ? <EyeOffIcon className="size-4" /> : <EyeIcon className="size-4" />}
        </button>
      </div>
    </Field>
  )
}
