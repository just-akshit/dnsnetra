import * as React from "react"
import { render, screen, fireEvent, waitFor } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"
import ResetPasswordPage from "@/app/(auth)/reset-password/page"

const { mockResetPassword, mockReplace } = vi.hoisted(() => ({
  mockResetPassword: vi.fn(),
  mockReplace: vi.fn(),
}))

vi.mock("@/lib/auth/api", () => ({
  authApi: {
    resetPassword: (...args: unknown[]) => mockResetPassword(...args),
  },
  AuthApiError: class AuthApiError extends Error {
    constructor(public kind: string, message: string) {
      super(message)
    }
  },
}))

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    replace: mockReplace,
  }),
}))

vi.mock("@/lib/auth/use-captcha", () => ({
  useCaptcha: () => ({
    challenge: { captcha_id: "test-cid", image: "base64img", expires_in: 300 },
    answer: "ABCD",
    setAnswer: vi.fn(),
    refresh: vi.fn(),
    loading: false,
    error: null,
  }),
}))

describe("ResetPasswordPage", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockResetPassword.mockResolvedValue({ message: "Password updated successfully." })
  })

  it("renders all required input fields and submit button", () => {
    render(<ResetPasswordPage />)
    expect(screen.getByLabelText(/Username/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/Reset code/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/^New password/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/Confirm new password/i)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /Set new password/i })).toBeInTheDocument()
  })

  it("shows error when username or reset code is missing", async () => {
    render(<ResetPasswordPage />)
    fireEvent.click(screen.getByRole("button", { name: /Set new password/i }))
    await waitFor(() => {
      expect(screen.getByText(/Enter your username and reset code/i)).toBeInTheDocument()
    })
    expect(mockResetPassword).not.toHaveBeenCalled()
  })

  it("shows error when passwords do not match", async () => {
    render(<ResetPasswordPage />)
    fireEvent.change(screen.getByLabelText(/Username/i), { target: { value: "testuser" } })
    fireEvent.change(screen.getByLabelText(/Reset code/i), { target: { value: "ABC123XYZ" } })
    fireEvent.change(screen.getByLabelText(/^New password/i), { target: { value: "Password123!" } })
    fireEvent.change(screen.getByLabelText(/Confirm new password/i), { target: { value: "DifferentPass!" } })

    fireEvent.click(screen.getByRole("button", { name: /Set new password/i }))
    await waitFor(() => {
      expect(screen.getByText(/Passwords do not match/i)).toBeInTheDocument()
    })
    expect(mockResetPassword).not.toHaveBeenCalled()
  })

  it("calls authApi.resetPassword on valid submission", async () => {
    render(<ResetPasswordPage />)
    fireEvent.change(screen.getByLabelText(/Username/i), { target: { value: "testuser" } })
    fireEvent.change(screen.getByLabelText(/Reset code/i), { target: { value: "ABC123XYZ" } })
    fireEvent.change(screen.getByLabelText(/^New password/i), { target: { value: "Password123!" } })
    fireEvent.change(screen.getByLabelText(/Confirm new password/i), { target: { value: "Password123!" } })

    fireEvent.click(screen.getByRole("button", { name: /Set new password/i }))
    await waitFor(() => {
      expect(mockResetPassword).toHaveBeenCalledWith({
        username: "testuser",
        code: "ABC123XYZ",
        new_password: "Password123!",
        confirm_password: "Password123!",
        captcha_id: "test-cid",
        captcha_answer: "ABCD",
      })
    })
    expect(screen.getByText(/Password updated successfully/i)).toBeInTheDocument()
  })
})

