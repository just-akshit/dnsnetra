import { render, screen, waitFor } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"
import UsersPage from "./page"

// ---------- shared mock state (vi.hoisted so vi.mock factories can reference) --

const { MockAdminApiError, mockList, mockApprove, mockDisable, mockEnable, mockRevokeSessions, mockUser } =
  vi.hoisted(() => {
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
      mockUser: { current: { username: "admin", role: "ADMIN" } },
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
    mockUser.current = { username: "admin", role: "ADMIN" }
    mockList.mockResolvedValue(listOf(pendingUser()))
    mockApprove.mockResolvedValue({ message: "ok" })
    mockDisable.mockResolvedValue({ message: "disabled" })
    mockEnable.mockResolvedValue({ message: "enabled" })
    mockRevokeSessions.mockResolvedValue({ message: "revoked", revoked_count: 1 })
  })

  // ── access control ───────────────────────────────────────────────────────────

  it("shows access-denied message for non-ADMIN role", () => {
    mockUser.current = { username: "joe", role: "ANALYST" }
    render(<UsersPage />)
    expect(screen.getByText(/Administrator access required/)).toBeInTheDocument()
  })

  it("does not call the API for non-ADMIN users", () => {
    mockUser.current = { username: "joe", role: "ANALYST" }
    render(<UsersPage />)
    expect(mockList).not.toHaveBeenCalled()
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
    // The button is present in the DOM before data loads (it's in the header)
    expect(screen.getByRole("button", { name: /Create user/i })).toBeInTheDocument()
  })
})
