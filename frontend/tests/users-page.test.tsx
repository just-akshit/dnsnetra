import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"
import UsersPage from "@/app/(dashboard)/users/page"

// ---------- shared mock state (vi.hoisted so vi.mock factories can reference) --

const {
  MockAdminApiError,
  mockList,
  mockApprove,
  mockDisable,
  mockEnable,
  mockRevokeSessions,
  mockCreate,
  mockResetPassword,
  mockResetCode,
  mockUpdate,
  mockUser,
} = vi.hoisted(() => {
  const MockAdminApiError = class AdminApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  }
  return {
    MockAdminApiError,
    mockList: vi.fn(),
    mockApprove: vi.fn(),
    mockDisable: vi.fn(),
    mockEnable: vi.fn(),
    mockRevokeSessions: vi.fn(),
    mockCreate: vi.fn(),
    mockResetPassword: vi.fn(),
    mockResetCode: vi.fn(),
    mockUpdate: vi.fn(),
    mockUser: { current: { id: 1, username: "admin", role: "ADMIN" } },
  }
})

vi.mock("@/lib/admin/users-api", () => ({
  AdminApiError: MockAdminApiError,
  usersApi: {
    list: (...args: unknown[]) => mockList(...args),
    approve: (...args: unknown[]) => mockApprove(...args),
    disable: (...args: unknown[]) => mockDisable(...args),
    enable: (...args: unknown[]) => mockEnable(...args),
    revokeSessions: (...args: unknown[]) => mockRevokeSessions(...args),
    create: (...args: unknown[]) => mockCreate(...args),
    resetPassword: (...args: unknown[]) => mockResetPassword(...args),
    resetCode: (...args: unknown[]) => mockResetCode(...args),
    update: (...args: unknown[]) => mockUpdate(...args),
  },
}))

vi.mock("@/components/auth/AuthGuard", () => ({
  useAuthUser: () => mockUser.current,
}))

// ---------- helpers -----------------------------------------------------------

function pendingUser(overrides = {}) {
  return { id: 7, username: "new.analyst", role: "ANALYST", status: "PENDING", is_active: false, ...overrides }
}

function activeUser(overrides = {}) {
  return { id: 2, username: "alice", role: "ANALYST", status: "ACTIVE", is_active: true, ...overrides }
}

function listOf(...items: object[]) {
  return { total: items.length, limit: 200, offset: 0, items }
}

// ---------- tests -------------------------------------------------------------

describe("UsersPage", () => {
  beforeEach(() => {
    mockUser.current = { id: 1, username: "admin", role: "ADMIN" }
    mockList.mockResolvedValue(listOf(pendingUser()))
    mockApprove.mockResolvedValue({ message: "ok" })
    mockDisable.mockResolvedValue({ message: "disabled" })
    mockEnable.mockResolvedValue({ message: "enabled" })
    mockRevokeSessions.mockResolvedValue({ message: "revoked", revoked_count: 1 })
    mockCreate.mockResolvedValue({ message: "created" })
    mockResetPassword.mockResolvedValue({
      username: "alice",
      temporary_password: "TmpPass123!",
      must_change_password: true,
    })
    mockResetCode.mockResolvedValue({ code: "abc123", expires_at: "2026-01-01T00:00:00Z" })
    mockUpdate.mockResolvedValue({ message: "updated" })
  })

  // ── access control ───────────────────────────────────────────────────────────

  it("shows access-denied message for non-ADMIN role", () => {
    mockUser.current = { id: 4, username: "joe", role: "ANALYST" }
    render(<UsersPage />)
    expect(screen.getByText(/Administrator access required/)).toBeInTheDocument()
  })

  it("does not call the API for non-ADMIN users", () => {
    mockUser.current = { id: 4, username: "joe", role: "ANALYST" }
    render(<UsersPage />)
    expect(mockList).not.toHaveBeenCalled()
  })

  it("loads the page for SUPER_ADMIN", async () => {
    mockUser.current = { id: 1, username: "root", role: "SUPER_ADMIN" }
    render(<UsersPage />)
    await waitFor(() => expect(mockList).toHaveBeenCalled())
  })

  // ── pending section ──────────────────────────────────────────────────────────

  it("shows pending accounts in the pending section", async () => {
    render(<UsersPage />)
    await waitFor(() => expect(screen.getByText("new.analyst")).toBeInTheDocument())
  })

  it("shows the pending count in the section heading", async () => {
    render(<UsersPage />)
    await waitFor(() => expect(screen.getByText(/Pending approval \(1\)/)).toBeInTheDocument())
  })

  it("shows zero count when no pending accounts", async () => {
    mockList.mockResolvedValue(listOf(activeUser()))
    render(<UsersPage />)
    await waitFor(() => expect(screen.getByText(/Pending approval \(0\)/)).toBeInTheDocument())
  })

  // ── all accounts section ─────────────────────────────────────────────────────

  it("shows active users in the All accounts section", async () => {
    mockList.mockResolvedValue(listOf(activeUser({ username: "alice" })))
    render(<UsersPage />)
    await waitFor(() => expect(screen.getByText("alice")).toBeInTheDocument())
  })

  it("shows both sections when both types of users exist", async () => {
    mockList.mockResolvedValue(listOf(pendingUser(), activeUser({ username: "alice" })))
    render(<UsersPage />)
    await waitFor(() => {
      expect(screen.getByText("new.analyst")).toBeInTheDocument()
      expect(screen.getByText("alice")).toBeInTheDocument()
    })
  })

  // ── error state ──────────────────────────────────────────────────────────────

  it("shows error message when API call fails", async () => {
    mockList.mockRejectedValue(new MockAdminApiError(500, "Internal server error"))
    render(<UsersPage />)
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument())
    expect(screen.getByRole("alert")).toHaveTextContent("Internal server error")
  })

  it("shows generic error message for non-AdminApiError failures", async () => {
    mockList.mockRejectedValue(new Error("network down"))
    render(<UsersPage />)
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Could not load users."))
  })

  // ── Create user button ───────────────────────────────────────────────────────

  it("renders Create user button for admins", async () => {
    render(<UsersPage />)
    expect(screen.getByRole("button", { name: /Create user/i })).toBeInTheDocument()
  })

  it("offers only assignable roles in the create dialog", async () => {
    mockUser.current = { id: 1, username: "admin", role: "ADMIN" }
    render(<UsersPage />)
    fireEvent.click(screen.getByRole("button", { name: /create user/i }))
    const dialog = screen.getByRole("dialog")
    expect(within(dialog).queryByText("ADMIN")).not.toBeInTheDocument()
    expect(within(dialog).getByText("ANALYST")).toBeInTheDocument()
  })

  // ── hierarchy-aware actions ──────────────────────────────────────────────────

  it("hides reset for an ADMIN target when the actor is ADMIN", async () => {
    mockUser.current = { id: 1, username: "admin", role: "ADMIN" }
    mockList.mockResolvedValue(listOf(activeUser({ id: 3, username: "admin2", role: "ADMIN" })))
    render(<UsersPage />)
    await screen.findByText("admin2")
    expect(screen.queryByRole("button", { name: /reset password/i })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /change role/i })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /disable/i })).not.toBeInTheDocument()
  })

  it("shows the temporary password once and clears it on close", async () => {
    mockUser.current = { id: 1, username: "root", role: "SUPER_ADMIN" }
    mockList.mockResolvedValue(listOf(activeUser()))
    render(<UsersPage />)

    fireEvent.click(await screen.findByRole("button", { name: /reset password/i }))
    fireEvent.click(screen.getByRole("button", { name: /confirm/i }))

    expect(await screen.findByText("TmpPass123!")).toBeInTheDocument()

    fireEvent.click(screen.getByRole("button", { name: "Close dialog" }))
    expect(screen.queryByText("TmpPass123!")).not.toBeInTheDocument()
  })

  it("submits the create form", async () => {
    render(<UsersPage />)
    fireEvent.click(screen.getByRole("button", { name: /create user/i }))
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: "bob" } })
    fireEvent.change(screen.getByLabelText(/temporary password/i), {
      target: { value: "Pwd123!" },
    })
    fireEvent.click(screen.getByRole("button", { name: "Create" }))
    await waitFor(() => expect(mockCreate).toHaveBeenCalledWith({
      username: "bob",
      password: "Pwd123!",
      role: "ANALYST",
      status: "ACTIVE",
    }))
  })

  it("guides the user to a valid temporary password", async () => {
    render(<UsersPage />)
    fireEvent.click(screen.getByRole("button", { name: /create user/i }))

    expect(screen.getByLabelText(/temporary password/i)).toHaveAttribute("minlength", "8")
    expect(screen.getByText(/at least 8 characters/i)).toBeInTheDocument()
  })

  it("shows a one-time reset code", async () => {
    mockUser.current = { id: 1, username: "root", role: "SUPER_ADMIN" }
    mockList.mockResolvedValue(listOf(activeUser()))
    render(<UsersPage />)

    fireEvent.click(await screen.findByRole("button", { name: /issue reset code/i }))
    fireEvent.click(screen.getByRole("button", { name: /issue code/i }))

    expect(await screen.findByText("abc123")).toBeInTheDocument()
  })
})
