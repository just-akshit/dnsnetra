import { PasswordField } from "./PasswordField"

export function ConfirmPasswordField(props: {
  value: string
  onChange: (v: string) => void
  error?: string | null
  disabled?: boolean
}) {
  return (
    <PasswordField
      id="confirm-password"
      label="Confirm password"
      placeholder="Re-enter your password"
      autoComplete="new-password"
      {...props}
    />
  )
}
