import { Input } from "@/components/ui/input"
import { Field, authInput, describedBy } from "./Field"

export function UsernameField({
  value,
  onChange,
  error,
  hint,
  disabled,
}: {
  value: string
  onChange: (v: string) => void
  error?: string | null
  hint?: string
  disabled?: boolean
}) {
  return (
    <Field id="username" label="Username" error={error} hint={hint}>
      <Input
        id="username"
        name="username"
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Enter your username"
        autoComplete="username"
        autoCapitalize="none"
        spellCheck={false}
        disabled={disabled}
        aria-invalid={!!error}
        aria-describedby={describedBy("username", hint, error)}
        className={authInput}
      />
    </Field>
  )
}
